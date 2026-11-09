package com.sorrowblue.kmcifs.client

import com.sorrowblue.kmcifs.client.protocol.SmbAccessMask
import com.sorrowblue.kmcifs.client.protocol.SmbCreateDisposition
import com.sorrowblue.kmcifs.client.protocol.SmbCreateOptions
import com.sorrowblue.kmcifs.client.protocol.SmbFileAttributes
import com.sorrowblue.kmcifs.client.protocol.SmbFileMetadata
import com.sorrowblue.kmcifs.client.protocol.SmbShareAccess
import kotlinx.coroutines.runBlocking

/**
 * Open mode for [SmbRandomAccessFile].
 *
 * Corresponds to the mode strings used by `java.io.RandomAccessFile` (`"r"`, `"rw"`, `"rws"`, `"rwd"`).
 */
enum class SmbRandomAccessMode(
    val modeString: String,
    val writable: Boolean,
    val writeThrough: Boolean,
) {
    /** Opens an existing file for reading only. Fails if the file does not exist. */
    READ_ONLY(modeString = "r", writable = false, writeThrough = false),

    /** Opens a file for reading and writing, creating it if it does not already exist. */
    READ_WRITE(modeString = "rw", writable = true, writeThrough = false),

    /** Opens a file for reading and writing, writing every update to file content or metadata synchronously to server storage (`FILE_WRITE_THROUGH`). */
    READ_WRITE_SYNC(modeString = "rws", writable = true, writeThrough = true),

    /** Opens a file for reading and writing, writing every update to file content synchronously to server storage (`FILE_WRITE_THROUGH`). */
    READ_WRITE_DSYNC(modeString = "rwd", writable = true, writeThrough = true);

    companion object {
        fun fromModeString(mode: String): SmbRandomAccessMode {
            return when (mode.trim().lowercase()) {
                "r" -> READ_ONLY
                "rw" -> READ_WRITE
                "rws" -> READ_WRITE_SYNC
                "rwd" -> READ_WRITE_DSYNC
                else -> throw IllegalArgumentException(
                    "Illegal mode \"$mode\" must be one of \"r\", \"rw\", \"rws\", or \"rwd\"",
                )
            }
        }
    }
}

/**
 * Exception thrown when an attempt is made to read past the end of an SMB file (EOF).
 */
class SmbEndOfFileException(
    message: String = "End of SMB file reached",
) : Exception(message)

/**
 * Provides a `java.io.RandomAccessFile`-compatible random-access API over a remote SMB file.
 *
 * Maintains an internal file pointer ([position]) and supports seeking to arbitrary offsets ([seek]),
 * reading from the current position ([read], [readByte], [readFully]), writing at the current position ([write]),
 * and querying or changing the file length ([length] / [setLength]).
 *
 * For workloads with frequent small reads (such as [readByte] or container header parsing), pass a positive
 * [bufferSize] to enable an in-memory read-ahead buffer (defaults to `0`, disabling buffering). Any write or
 * size change immediately invalidates the read buffer to preserve read-after-write consistency.
 *
 * Like `java.io.RandomAccessFile`, a single [SmbRandomAccessFile] instance is designed for sequential use from
 * one thread at a time. To read concurrently from multiple threads, open a separate [SmbRandomAccessFile]
 * instance per thread (the underlying [SmbShare] and [SmbClient] are thread-safe and can be shared).
 */
class SmbRandomAccessFile(
    val share: SmbShare,
    val path: String,
    val mode: SmbRandomAccessMode = SmbRandomAccessMode.READ_ONLY,
    val bufferSize: Int = DEFAULT_BUFFER_SIZE,
) : AutoCloseable {

    constructor(
        share: SmbShare,
        path: String,
        mode: String,
        bufferSize: Int = DEFAULT_BUFFER_SIZE,
    ) : this(
        share = share,
        path = path,
        mode = SmbRandomAccessMode.fromModeString(mode),
        bufferSize = bufferSize,
    )

    internal constructor(
        file: SmbFile,
        path: String,
        mode: SmbRandomAccessMode,
        bufferSize: Int = DEFAULT_BUFFER_SIZE,
    ) : this(
        share = file.share,
        path = path,
        mode = mode,
        bufferSize = bufferSize,
    ) {
        this.smbFile = file
        this.closed = false
    }

    private var smbFile: SmbFile? = null

    @kotlin.concurrent.Volatile
    private var closed: Boolean = false
    private var currentPosition: Long = 0L

    private var bufferStartOffset: Long = -1L
    private var bufferData: ByteArray = ByteArray(0)
    private var bufferValidLength: Int = 0
    private val scratchBuffer: ByteArray = ByteArray(8)

    /**
     * Whether the underlying SMB file handle is currently open.
     */
    val isOpen: Boolean
        get() = smbFile != null && !closed

    /**
     * Current file pointer offset in bytes from the beginning of the file.
     */
    val position: Long
        get() = currentPosition

    /**
     * Current length of the file in bytes.
     *
     * Returns the file size retrieved from the server and updated by local writes or [setLength].
     */
    val length: Long
        get() = requireOpenFile().size

    /**
     * Metadata of the open SMB file.
     */
    val metadata: SmbFileMetadata
        get() = requireOpenFile().metadata

    /**
     * Opens the remote SMB file if it is not already open.
     */
    suspend fun open(): SmbRandomAccessFile {
        check(!closed) { "SmbRandomAccessFile is already closed" }
        if (smbFile != null) return this
        ensureOpenLocked()
        invalidateBuffer()
        return this
    }

    /**
     * Sets the file-pointer offset, measured from the beginning of this file, at which the next
     * read or write occurs.
     *
     * The offset may be set beyond the end of the file; setting the offset beyond the end of the file
     * does not change the file length until data is written at that offset.
     */
    fun seek(pos: Long) {
        require(pos >= 0L) { "Negative seek offset: $pos" }
        check(!closed) { "SmbRandomAccessFile is closed" }
        currentPosition = pos
    }

    /**
     * Attempts to skip over [n] bytes of input starting from the current position, returning the
     * actual number of bytes skipped. Never skips past the end of the file.
     */
    fun skipBytes(n: Int): Int {
        if (n <= 0) return 0
        val fileLen = length
        val pos = currentPosition
        if (pos >= fileLen) return 0
        val skipped = minOf(n.toLong(), fileLen - pos).toInt()
        currentPosition = pos + skipped
        return skipped
    }

    /**
     * Reads a single byte from the current position and returns it as an integer in the range `0..255`,
     * or `-1` if the end of the file has been reached.
     */
    fun read(): Int {
        check(!closed) { "SmbRandomAccessFile is closed" }
        val fastFile = smbFile
        val pos = currentPosition
        if (fastFile != null) {
            if (pos >= fastFile.size) return -1
            if (bufferSize > 0) {
                val bufStart = bufferStartOffset
                val bufLen = bufferValidLength
                val buf = bufferData
                val rel = pos - bufStart
                if (bufStart >= 0L && rel >= 0L && rel < bufLen && rel < buf.size) {
                    val value = buf[rel.toInt()].toInt() and 0xFF
                    currentPosition = pos + 1L
                    return value
                }
            }
        }

        return runBlocking {
            val file = ensureOpenLocked()
            val curPos = currentPosition
            if (curPos >= file.size) return@runBlocking -1

            if (bufferSize > 0) {
                if (!isOffsetInBuffer(curPos)) {
                    fillBufferLocked(file, curPos)
                }
                val bufStart = bufferStartOffset
                val bufLen = bufferValidLength
                val buf = bufferData
                val rel = curPos - bufStart
                if (bufStart >= 0L && rel >= 0L && rel < bufLen && rel < buf.size) {
                    val value = buf[rel.toInt()].toInt() and 0xFF
                    currentPosition = curPos + 1L
                    return@runBlocking value
                }
            }

            val n = file.readInto(curPos, scratchBuffer, 0, 1)
            if (n <= 0) return@runBlocking -1
            currentPosition = curPos + 1L
            scratchBuffer[0].toInt() and 0xFF
        }
    }

    /**
     * Reads a signed 8-bit value ([Byte]) from the current position and advances the file pointer by 1.
     * Throws [SmbEndOfFileException] if the end of the file has been reached.
     */
    fun readByte(): Byte {
        val b = read()
        if (b < 0) throw SmbEndOfFileException("EOF reached at offset $currentPosition while reading byte")
        return b.toByte()
    }

    /**
     * Reads an unsigned 8-bit value (`0..255`) from the current position and advances the file pointer by 1.
     * Throws [SmbEndOfFileException] if the end of the file has been reached.
     */
    fun readUnsignedByte(): Int {
        val b = read()
        if (b < 0) throw SmbEndOfFileException("EOF reached at offset $currentPosition while reading unsigned byte")
        return b
    }

    /**
     * Reads up to `b.size` bytes from the current position into [b] and returns the number of bytes read,
     * or `-1` if no bytes could be read because the end of the file has been reached.
     */
    fun read(b: ByteArray): Int = read(b, 0, b.size)

    /**
     * Reads up to [len] bytes from the current position into [b] starting at offset [off], returning the
     * number of bytes read or `-1` if the end of the file has been reached.
     */
    fun read(b: ByteArray, off: Int, len: Int): Int {
        require(off >= 0 && len >= 0 && len <= b.size - off) {
            "Invalid buffer bounds: off=$off, len=$len, size=${b.size}"
        }
        check(!closed) { "SmbRandomAccessFile is closed" }
        if (len == 0) return 0

        // Fast path: バッファ内で完結する読み取りは runBlocking を介さずオンメモリコピーで即座に返す
        val fastFile = smbFile
        val pos = currentPosition
        if (fastFile != null) {
            val fileSize = fastFile.size
            if (pos >= fileSize) return -1
            val availableInFile = (fileSize - pos).coerceAtMost(len.toLong()).toInt()
            if (availableInFile <= 0) return -1
            if (bufferSize > 0) {
                val bufStart = bufferStartOffset
                val bufLen = bufferValidLength
                val buf = bufferData
                val rel = pos - bufStart
                if (bufStart >= 0L && rel >= 0L && rel < bufLen) {
                    val bufIndex = rel.toInt()
                    val availableInBuf = bufLen - bufIndex
                    if (availableInBuf >= availableInFile && bufIndex + availableInFile <= buf.size) {
                        buf.copyInto(
                            destination = b,
                            destinationOffset = off,
                            startIndex = bufIndex,
                            endIndex = bufIndex + availableInFile,
                        )
                        currentPosition = pos + availableInFile
                        return availableInFile
                    }
                }
            }
        }

        return runBlocking {
            val file = ensureOpenLocked()
            if (currentPosition >= file.size) return@runBlocking -1

            val availableInFile = (file.size - currentPosition).coerceAtMost(len.toLong()).toInt()
            if (availableInFile <= 0) return@runBlocking -1

            var totalRead = 0
            var dstOffset = off
            var remaining = availableInFile

            // 1. まず既存の内部バッファにヒットする領域があればそこからコピーする
            if (bufferSize > 0 && isOffsetInBuffer(currentPosition)) {
                val bufIndex = (currentPosition - bufferStartOffset).toInt()
                val copyLen = minOf(remaining, bufferValidLength - bufIndex)
                bufferData.copyInto(
                    destination = b,
                    destinationOffset = dstOffset,
                    startIndex = bufIndex,
                    endIndex = bufIndex + copyLen,
                )
                currentPosition += copyLen
                dstOffset += copyLen
                totalRead += copyLen
                remaining -= copyLen
            }

            if (remaining == 0) {
                return@runBlocking totalRead
            }

            // 2. 残りの要求サイズがバッファサイズ以上なら直接 SMB READ を発行する（ゼロコピー）
            if (bufferSize <= 0 || remaining >= bufferSize) {
                val readCount = file.readInto(currentPosition, b, dstOffset, remaining)
                if (readCount > 0) {
                    currentPosition += readCount
                    totalRead += readCount
                }
                return@runBlocking if (totalRead == 0) -1 else totalRead
            }

            // 3. 小さな読み取りはバッファを補充してからコピーする
            fillBufferLocked(file, currentPosition)
            if (isOffsetInBuffer(currentPosition)) {
                val bufIndex = (currentPosition - bufferStartOffset).toInt()
                val copyLen = minOf(remaining, bufferValidLength - bufIndex)
                bufferData.copyInto(
                    destination = b,
                    destinationOffset = dstOffset,
                    startIndex = bufIndex,
                    endIndex = bufIndex + copyLen,
                )
                currentPosition += copyLen
                totalRead += copyLen
            }

            if (totalRead == 0) -1 else totalRead
        }
    }

    /**
     * Reads up to [length] bytes from the current position and returns them as a new [ByteArray].
     */
    fun readBytes(length: Int): ByteArray {
        require(length >= 0) { "length must be non-negative: $length" }
        if (length == 0) return ByteArray(0)
        val buf = ByteArray(length)
        val n = read(buf, 0, length)
        if (n <= 0) return ByteArray(0)
        return if (n == length) buf else buf.copyOf(n)
    }

    /**
     * Reads exactly [len] bytes from the current position into [b] starting at [off].
     * Throws [SmbEndOfFileException] if the end of the file is reached before [len] bytes are read.
     */
    fun readFully(b: ByteArray, off: Int = 0, len: Int = b.size - off) {
        require(off >= 0 && len >= 0 && len <= b.size - off) {
            "Invalid buffer bounds: off=$off, len=$len, size=${b.size}"
        }
        var total = 0
        while (total < len) {
            val count = read(b, off + total, len - total)
            if (count < 0) {
                throw SmbEndOfFileException("EOF reached after reading $total of $len bytes")
            }
            total += count
        }
    }

    /**
     * Reads a single byte from the current position and returns `true` if it is non-zero, or `false` if zero.
     */
    fun readBoolean(): Boolean = readByte().toInt() != 0

    /**
     * Reads a signed 16-bit big-endian integer from the current position.
     */
    fun readShort(): Short {
        readFully(scratchBuffer, 0, 2)
        return (((scratchBuffer[0].toInt() and 0xFF) shl 8) or (scratchBuffer[1].toInt() and 0xFF)).toShort()
    }

    /**
     * Reads an unsigned 16-bit big-endian integer from the current position.
     */
    fun readUnsignedShort(): Int {
        readFully(scratchBuffer, 0, 2)
        return ((scratchBuffer[0].toInt() and 0xFF) shl 8) or (scratchBuffer[1].toInt() and 0xFF)
    }

    /**
     * Reads a signed 32-bit big-endian integer from the current position.
     */
    fun readInt(): Int {
        readFully(scratchBuffer, 0, 4)
        return ((scratchBuffer[0].toInt() and 0xFF) shl 24) or
            ((scratchBuffer[1].toInt() and 0xFF) shl 16) or
            ((scratchBuffer[2].toInt() and 0xFF) shl 8) or
            (scratchBuffer[3].toInt() and 0xFF)
    }

    /**
     * Reads a signed 64-bit big-endian integer from the current position.
     */
    fun readLong(): Long {
        readFully(scratchBuffer, 0, 8)
        return ((scratchBuffer[0].toLong() and 0xFFL) shl 56) or
            ((scratchBuffer[1].toLong() and 0xFFL) shl 48) or
            ((scratchBuffer[2].toLong() and 0xFFL) shl 40) or
            ((scratchBuffer[3].toLong() and 0xFFL) shl 32) or
            ((scratchBuffer[4].toLong() and 0xFFL) shl 24) or
            ((scratchBuffer[5].toLong() and 0xFFL) shl 16) or
            ((scratchBuffer[6].toLong() and 0xFFL) shl 8) or
            (scratchBuffer[7].toLong() and 0xFFL)
    }

    /**
     * Writes the low-order 8 bits of [b] at the current position and advances the file pointer by 1.
     */
    fun write(b: Int) {
        scratchBuffer[0] = b.toByte()
        write(scratchBuffer, 0, 1)
    }

    /**
     * Writes a single byte [v] at the current position and advances the file pointer by 1.
     */
    fun writeByte(v: Int) {
        write(v)
    }

    /**
     * Writes all bytes from [b] at the current position and advances the file pointer.
     */
    fun write(b: ByteArray) {
        write(b, 0, b.size)
    }

    /**
     * Writes [len] bytes from [b] starting at offset [off] at the current position and advances
     * the file pointer by the number of bytes written.
     */
    fun write(b: ByteArray, off: Int, len: Int): Int = runBlocking {
        check(mode.writable) { "File \"$path\" is opened in read-only mode (${mode.modeString})" }
        require(off >= 0 && len >= 0 && len <= b.size - off) {
            "Invalid buffer bounds: off=$off, len=$len, size=${b.size}"
        }
        val file = ensureOpenLocked()
        if (len == 0) return@runBlocking 0

        invalidateBuffer()
        val written = file.write(
            offset = currentPosition,
            data = b,
            startIndex = off,
            length = len,
        )
        currentPosition += written
        written
    }

    /**
     * Writes a boolean value as a single byte (`1` for `true`, `0` for `false`) at the current position.
     */
    fun writeBoolean(v: Boolean) {
        write(if (v) 1 else 0)
    }

    /**
     * Writes a 16-bit big-endian integer at the current position.
     */
    fun writeShort(v: Int) {
        scratchBuffer[0] = ((v ushr 8) and 0xFF).toByte()
        scratchBuffer[1] = (v and 0xFF).toByte()
        write(scratchBuffer, 0, 2)
    }

    /**
     * Writes a 32-bit big-endian integer at the current position.
     */
    fun writeInt(v: Int) {
        scratchBuffer[0] = ((v ushr 24) and 0xFF).toByte()
        scratchBuffer[1] = ((v ushr 16) and 0xFF).toByte()
        scratchBuffer[2] = ((v ushr 8) and 0xFF).toByte()
        scratchBuffer[3] = (v and 0xFF).toByte()
        write(scratchBuffer, 0, 4)
    }

    /**
     * Writes a 64-bit big-endian integer at the current position.
     */
    fun writeLong(v: Long) {
        scratchBuffer[0] = ((v ushr 56) and 0xFFL).toByte()
        scratchBuffer[1] = ((v ushr 48) and 0xFFL).toByte()
        scratchBuffer[2] = ((v ushr 40) and 0xFFL).toByte()
        scratchBuffer[3] = ((v ushr 32) and 0xFFL).toByte()
        scratchBuffer[4] = ((v ushr 24) and 0xFFL).toByte()
        scratchBuffer[5] = ((v ushr 16) and 0xFFL).toByte()
        scratchBuffer[6] = ((v ushr 8) and 0xFFL).toByte()
        scratchBuffer[7] = (v and 0xFFL).toByte()
        write(scratchBuffer, 0, 8)
    }

    /**
     * Truncates or extends the file to [newLength] bytes.
     *
     * If the current [position] is greater than [newLength], [position] is set to [newLength]
     * (matching `java.io.RandomAccessFile.setLength`).
     */
    fun setLength(newLength: Long) = runBlocking {
        check(mode.writable) { "File \"$path\" is opened in read-only mode (${mode.modeString})" }
        val file = ensureOpenLocked()
        invalidateBuffer()
        file.setLength(newLength)
        if (currentPosition > newLength) {
            currentPosition = newLength
        }
    }

    /**
     * Flushes server-side write buffers for this file to persistent storage (`SMB2 FLUSH`).
     */
    fun flush() = runBlocking {
        val file = ensureOpenLocked()
        file.flush()
    }

    /**
     * Closes the remote SMB file handle on the server (`SMB2 CLOSE`) and releases internal buffers.
     */
    suspend fun closeSuspend() {
        if (closed) return
        closed = true
        invalidateBuffer()
        bufferData = ByteArray(0)
        val file = smbFile
        smbFile = null
        file?.closeSuspend()
    }

    override fun close() {
        if (closed) return
        runBlocking {
            closeSuspend()
        }
    }

    private fun requireOpenFile(): SmbFile {
        check(!closed) { "SmbRandomAccessFile is closed" }
        return smbFile ?: runBlocking { ensureOpenLocked() }
    }

    private suspend fun ensureOpenLocked(): SmbFile {
        check(!closed) { "SmbRandomAccessFile is closed" }
        smbFile?.let { return it }

        val desiredAccess = if (mode.writable) {
            SmbAccessMask.WRITE_DEFAULT
        } else {
            SmbAccessMask.READ_DEFAULT
        }
        val shareAccess = if (mode.writable) {
            SmbShareAccess.FILE_SHARE_READ or SmbShareAccess.FILE_SHARE_WRITE
        } else {
            SmbShareAccess.ALL
        }
        val createDisposition = if (mode.writable) {
            SmbCreateDisposition.FILE_OPEN_IF
        } else {
            SmbCreateDisposition.FILE_OPEN
        }
        var createOptions = SmbCreateOptions.FILE_NON_DIRECTORY_FILE or SmbCreateOptions.FILE_SYNCHRONOUS_IO_NONALERT
        if (mode.writeThrough) {
            createOptions = createOptions or SmbCreateOptions.FILE_WRITE_THROUGH
        }

        val opened = share.openFile(
            path = path,
            desiredAccess = desiredAccess,
            shareAccess = shareAccess,
            createDisposition = createDisposition,
            fileAttributes = SmbFileAttributes.NORMAL,
            createOptions = createOptions,
        )
        smbFile = opened
        return opened
    }

    private fun isOffsetInBuffer(offset: Long): Boolean {
        return bufferStartOffset >= 0L &&
            offset >= bufferStartOffset &&
            offset < bufferStartOffset + bufferValidLength
    }

    private suspend fun fillBufferLocked(file: SmbFile, fromOffset: Long) {
        if (bufferSize <= 0 || fromOffset >= file.size) {
            invalidateBuffer()
            return
        }
        val toRead = minOf(bufferSize.toLong(), file.size - fromOffset).toInt()
        if (toRead <= 0) {
            invalidateBuffer()
            return
        }
        if (bufferData.size < toRead) {
            bufferData = ByteArray(bufferSize)
        }
        val fetchedCount = file.readInto(fromOffset, bufferData, 0, toRead)
        if (fetchedCount <= 0) {
            invalidateBuffer()
            return
        }
        bufferStartOffset = fromOffset
        bufferValidLength = fetchedCount
    }

    private fun invalidateBuffer() {
        bufferStartOffset = -1L
        bufferValidLength = 0
    }

    companion object {
        const val DEFAULT_BUFFER_SIZE: Int = 0

        /**
         * Opens the file at [path] on [share] with the specified [mode] string (`"r"`, `"rw"`, `"rws"`, `"rwd"`)
         * and returns an open [SmbRandomAccessFile].
         */
        suspend fun open(
            share: SmbShare,
            path: String,
            mode: String = "r",
            bufferSize: Int = DEFAULT_BUFFER_SIZE,
        ): SmbRandomAccessFile {
            return SmbRandomAccessFile(
                share = share,
                path = path,
                mode = SmbRandomAccessMode.fromModeString(mode),
                bufferSize = bufferSize,
            ).open()
        }

        /**
         * Opens the file at [path] on [share] with the specified [SmbRandomAccessMode]
         * and returns an open [SmbRandomAccessFile].
         */
        suspend fun open(
            share: SmbShare,
            path: String,
            mode: SmbRandomAccessMode,
            bufferSize: Int = DEFAULT_BUFFER_SIZE,
        ): SmbRandomAccessFile {
            return SmbRandomAccessFile(
                share = share,
                path = path,
                mode = mode,
                bufferSize = bufferSize,
            ).open()
        }
    }
}
