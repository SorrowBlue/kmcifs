package com.sorrowblue.kmcifs.client

import com.sorrowblue.kmcifs.client.protocol.SmbAccessMask
import com.sorrowblue.kmcifs.client.protocol.SmbCreateDisposition
import com.sorrowblue.kmcifs.client.protocol.SmbCreateOptions
import com.sorrowblue.kmcifs.client.protocol.SmbFileAttributes
import com.sorrowblue.kmcifs.client.protocol.SmbFileMetadata
import com.sorrowblue.kmcifs.client.protocol.SmbShareAccess
import kotlinx.coroutines.runBlocking

/**
 * [SmbRandomAccessFile] のオープンモード。
 *
 * Java の `RandomAccessFile` と同じモード文字列（`"r"`, `"rw"`, `"rws"`, `"rwd"`）に対応する。
 */
enum class SmbRandomAccessMode(
    val modeString: String,
    val writable: Boolean,
    val writeThrough: Boolean,
) {
    /** 読み取り専用で既存ファイルを開く。ファイルが存在しない場合はエラーとなる。 */
    READ_ONLY(modeString = "r", writable = false, writeThrough = false),

    /** 読み書き両用で開く。ファイルが存在しない場合は新規作成する。 */
    READ_WRITE(modeString = "rw", writable = true, writeThrough = false),

    /** 読み書き両用で開き、データとメタデータの変更をサーバー側ストレージへ同期書き込みする (`FILE_WRITE_THROUGH`)。 */
    READ_WRITE_SYNC(modeString = "rws", writable = true, writeThrough = true),

    /** 読み書き両用で開き、データの変更をサーバー側ストレージへ同期書き込みする (`FILE_WRITE_THROUGH`)。 */
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
 * ファイル末尾（EOF）を超えて読み取ろうとした際に送出される例外。
 */
class SmbEndOfFileException(
    message: String = "End of SMB file reached",
) : Exception(message)

/**
 * Java の `RandomAccessFile` に相当するランダムアクセス API を提供する SMB ファイルクラス。
 *
 * ファイルポインタ（[position]）を内部で保持し、[seek] による任意位置への移動、
 * [read] / [readByte] による現在位置からの読み取り、[write] による現在位置への書き込み、
 * および [length] / [setLength] によるファイルサイズの参照・変更を行う。
 *
 * 小さな読み取り（[readByte] やヘッダ解析など）で先読みバッファリングを行いたい場合は、
 * [bufferSize] に正のバイト数を指定することでインメモリ読み取りバッファを有効化できる（既定値は `0` でバッファリングなし）。
 * 書き込みやサイズ変更が行われた際はバッファを即座に無効化し、読み書きの整合性を維持する。
 *
 * なお、Java の `RandomAccessFile` と同様に 1 つの [SmbRandomAccessFile] インスタンスは単一スレッドから順次操作する設計となっており、
 * 別スレッドで並列に読み取る場合はスレッドごとに個別の [SmbRandomAccessFile] インスタンスを開くこと（共有元の [SmbShare] / [SmbClient] はマルチスレッド安全に共有可能）。
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
     * ファイルハンドルが現在オープンされているかどうか。
     */
    val isOpen: Boolean
        get() = smbFile != null && !closed

    /**
     * 現在のファイルポインタ位置（先頭からのバイトオフセット）。
     */
    val position: Long
        get() = currentPosition

    /**
     * 現在のファイルサイズ（バイト単位）。
     *
     * オープン済みの場合はサーバーから取得・更新されたファイルサイズを返す。
     */
    val length: Long
        get() = requireOpenFile().size

    /**
     * オープン済みのファイルのメタデータ。
     */
    val metadata: SmbFileMetadata
        get() = requireOpenFile().metadata

    /**
     * リモート SMB ファイルをオープンする。既にオープン済みの場合は何もしない。
     */
    suspend fun open(): SmbRandomAccessFile {
        check(!closed) { "SmbRandomAccessFile is already closed" }
        if (smbFile != null) return this
        ensureOpenLocked()
        invalidateBuffer()
        return this
    }

    /**
     * 次回の読み書きが行われるファイルポインタ位置を先頭からのバイトオフセット [pos] に移動する。
     *
     * [pos] にはファイル末尾を超える値も指定でき、その位置へ書き込みを行った時点でファイルサイズが拡張される。
     */
    fun seek(pos: Long) {
        require(pos >= 0L) { "Negative seek offset: $pos" }
        check(!closed) { "SmbRandomAccessFile is closed" }
        currentPosition = pos
    }

    /**
     * 現在位置から最大 [n] バイトをスキップし、実際にスキップされたバイト数を返す。
     * ファイル末尾を超えてスキップすることはない。
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
     * 現在位置から 1 バイトを読み取り、`0..255` の整数として返す。
     * ファイル末尾に達している場合は `-1` を返す。
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
     * 現在位置から符号付き 1 バイト（[Byte]）を読み取り、ファイルポインタを 1 進める。
     * ファイル末尾に達している場合は [SmbEndOfFileException] を送出する。
     */
    fun readByte(): Byte {
        val b = read()
        if (b < 0) throw SmbEndOfFileException("EOF reached at offset $currentPosition while reading byte")
        return b.toByte()
    }

    /**
     * 現在位置から符号なし 1 バイト（`0..255`）を読み取り、ファイルポインタを 1 進める。
     * ファイル末尾に達している場合は [SmbEndOfFileException] を送出する。
     */
    fun readUnsignedByte(): Int {
        val b = read()
        if (b < 0) throw SmbEndOfFileException("EOF reached at offset $currentPosition while reading unsigned byte")
        return b
    }

    /**
     * 現在位置から配列 [b] に最大 `b.size` バイトを読み込み、実際に読み取ったバイト数を返す。
     * ファイル末尾に達しているため 1 バイトも読み取れなかった場合は `-1` を返す。
     */
    fun read(b: ByteArray): Int = read(b, 0, b.size)

    /**
     * 現在位置から配列 [b] の [off] 番目以降へ最大 [len] バイトを読み込み、実際に読み取ったバイト数を返す。
     * ファイル末尾に達しているため 1 バイトも読み取れなかった場合は `-1` を返す。
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
     * 現在位置から最大 [length] バイトを読み取り、新しいバイト配列として返す。
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
     * 現在位置から [len] バイトすべてを配列 [b]（開始位置 [off]）へ読み込む。
     * [len] バイト読み切る前にファイル末尾へ達した場合は [SmbEndOfFileException] を送出する。
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
     * 現在位置から 1 バイトを読み取り、`0` 以外なら `true`、`0` なら `false` を返す。
     */
    fun readBoolean(): Boolean = readByte().toInt() != 0

    /**
     * 現在位置からビッグエンディアンの符号付き 16 ビット整数を読み取る。
     */
    fun readShort(): Short {
        readFully(scratchBuffer, 0, 2)
        return (((scratchBuffer[0].toInt() and 0xFF) shl 8) or (scratchBuffer[1].toInt() and 0xFF)).toShort()
    }

    /**
     * 現在位置からビッグエンディアンの符号なし 16 ビット整数を読み取る。
     */
    fun readUnsignedShort(): Int {
        readFully(scratchBuffer, 0, 2)
        return ((scratchBuffer[0].toInt() and 0xFF) shl 8) or (scratchBuffer[1].toInt() and 0xFF)
    }

    /**
     * 現在位置からビッグエンディアンの 32 ビット整数を読み取る。
     */
    fun readInt(): Int {
        readFully(scratchBuffer, 0, 4)
        return ((scratchBuffer[0].toInt() and 0xFF) shl 24) or
            ((scratchBuffer[1].toInt() and 0xFF) shl 16) or
            ((scratchBuffer[2].toInt() and 0xFF) shl 8) or
            (scratchBuffer[3].toInt() and 0xFF)
    }

    /**
     * 現在位置からビッグエンディアンの 64 ビット整数を読み取る。
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
     * 現在位置へ下位 8 ビット（1 バイト）を書き込み、ファイルポインタを 1 進める。
     */
    fun write(b: Int) {
        scratchBuffer[0] = b.toByte()
        write(scratchBuffer, 0, 1)
    }

    /**
     * 現在位置へ 1 バイトを書き込み、ファイルポインタを 1 進める。
     */
    fun writeByte(v: Int) {
        write(v)
    }

    /**
     * 現在位置へバイト配列 [b] の全内容を書き込み、ファイルポインタを進ませる。
     */
    fun write(b: ByteArray) {
        write(b, 0, b.size)
    }

    /**
     * 現在位置へバイト配列 [b] の [off] から [len] バイトを書き込み、実際に書き込まれた分だけファイルポインタを進める。
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
     * 現在位置へ真偽値（1 バイト）を書き込む。
     */
    fun writeBoolean(v: Boolean) {
        write(if (v) 1 else 0)
    }

    /**
     * 現在位置へビッグエンディアンの 16 ビット整数を書き込む。
     */
    fun writeShort(v: Int) {
        scratchBuffer[0] = ((v ushr 8) and 0xFF).toByte()
        scratchBuffer[1] = (v and 0xFF).toByte()
        write(scratchBuffer, 0, 2)
    }

    /**
     * 現在位置へビッグエンディアンの 32 ビット整数を書き込む。
     */
    fun writeInt(v: Int) {
        scratchBuffer[0] = ((v ushr 24) and 0xFF).toByte()
        scratchBuffer[1] = ((v ushr 16) and 0xFF).toByte()
        scratchBuffer[2] = ((v ushr 8) and 0xFF).toByte()
        scratchBuffer[3] = (v and 0xFF).toByte()
        write(scratchBuffer, 0, 4)
    }

    /**
     * 現在位置へビッグエンディアンの 64 ビット整数を書き込む。
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
     * ファイルサイズを [newLength] バイトに変更（トランケートまたは拡張）する。
     *
     * 現在の [position] が [newLength] より大きい場合、`RandomAccessFile.setLength` と同様に
     * [position] は [newLength] へ移動する。
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
     * サーバー側の書き込みバッファをディスクへフラッシュする (`SMB2 FLUSH`)。
     */
    fun flush() = runBlocking {
        val file = ensureOpenLocked()
        file.flush()
    }

    /**
     * リモート SMB ファイルハンドルをサーバー上で閉じ、内部バッファを解放する (`SMB2 CLOSE`)。
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
         * 指定した共有フォルダ [share] 上の [path] を [mode]（`"r"`, `"rw"`, `"rws"`, `"rwd"`）で開き、
         * オープン済みの [SmbRandomAccessFile] を返す。
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
         * 指定した共有フォルダ [share] 上の [path] を [mode] で開き、
         * オープン済みの [SmbRandomAccessFile] を返す。
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
