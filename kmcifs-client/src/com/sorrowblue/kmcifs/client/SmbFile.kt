package com.sorrowblue.kmcifs.client

import com.sorrowblue.kmcifs.client.protocol.NtStatus
import com.sorrowblue.kmcifs.client.protocol.SmbException
import com.sorrowblue.kmcifs.client.protocol.SmbFileId
import com.sorrowblue.kmcifs.client.protocol.SmbFileMetadata
import com.sorrowblue.kmcifs.client.protocol.SmbMessages
import kotlinx.coroutines.runBlocking
import kotlinx.io.Buffer
import kotlinx.io.RawSink
import kotlinx.io.RawSource
import kotlinx.io.Sink
import kotlinx.io.Source
import kotlinx.io.buffered

/**
 * Represents an open handle to a remote SMB file.
 *
 * Provides offset-based reads ([read], [readInto]) and writes ([write]),
 * byte-range exclusive or shared locking ([lock] / [unlock]), and file truncation or extension ([setLength]).
 */
class SmbFile internal constructor(
    val share: SmbShare,
    val fileId: SmbFileId,
    initialMetadata: SmbFileMetadata,
) : AutoCloseable {

    @kotlin.concurrent.Volatile
    private var closed = false

    val isClosed: Boolean
        get() = closed

    var metadata: SmbFileMetadata = initialMetadata
        private set

    val size: Long
        get() = metadata.size

    private fun ensureOpen() {
        if (closed) {
            throw SmbException(NtStatus.STATUS_FILE_CLOSED, "SMB file handle is already closed")
        }
    }

    /**
     * Reads up to [length] bytes starting at [offset].
     * Requests exceeding the server's `MaxReadSize` are automatically split into chunks.
     */
    suspend fun read(offset: Long, length: Int): ByteArray {
        ensureOpen()
        require(offset >= 0L) { "offset must be non-negative" }
        require(length >= 0) { "length must be non-negative" }
        if (length == 0) return ByteArray(0)

        val maxChunk = share.client.maxReadSize.coerceAtMost(262144)
        if (length <= maxChunk) {
            return readSingleChunk(offset, length)
        }

        val buffer = ByteArray(length)
        val totalRead = readInto(offset, buffer, 0, length)
        return if (totalRead == length) buffer else buffer.copyOf(totalRead)
    }

    /**
     * Reads up to [length] bytes starting at [offset] directly into [destination] at [destinationOffset]
     * without allocating intermediate byte arrays.
     *
     * @return Total number of bytes read, or `0` if EOF is reached.
     */
    suspend fun readInto(
        offset: Long,
        destination: ByteArray,
        destinationOffset: Int = 0,
        length: Int = destination.size - destinationOffset,
    ): Int {
        ensureOpen()
        require(offset >= 0L) { "offset must be non-negative" }
        require(destinationOffset >= 0 && length >= 0 && length <= destination.size - destinationOffset) {
            "Invalid destination slice bounds"
        }
        if (length == 0) return 0

        val maxChunk = share.client.maxReadSize.coerceAtMost(262144)
        var totalRead = 0
        while (totalRead < length) {
            val toRead = minOf(maxChunk, length - totalRead)
            val readCount = readSingleChunkInto(
                offset = offset + totalRead,
                destination = destination,
                destinationOffset = destinationOffset + totalRead,
                length = toRead,
            )
            if (readCount <= 0) break
            totalRead += readCount
            if (readCount < toRead) break
        }
        return totalRead
    }

    private suspend fun readSingleChunk(offset: Long, length: Int): ByteArray {
        ensureOpen()
        val req = SmbMessages.buildReadRequest(
            sessionId = share.client.sessionId,
            treeId = share.treeId,
            fileId = fileId,
            offset = offset,
            length = length,
        )
        val resp = share.client.executeCommand(req, share.encryptShare)
        return SmbMessages.parseReadResponse(resp, length)
    }

    private suspend fun readSingleChunkInto(
        offset: Long,
        destination: ByteArray,
        destinationOffset: Int,
        length: Int,
    ): Int {
        ensureOpen()
        val req = SmbMessages.buildReadRequest(
            sessionId = share.client.sessionId,
            treeId = share.treeId,
            fileId = fileId,
            offset = offset,
            length = length,
        )
        val resp = share.client.executeCommand(req, share.encryptShare)
        return SmbMessages.parseReadResponseInto(resp, destination, destinationOffset, length)
    }

    /**
     * Reads all bytes from the beginning of the file to the end.
     */
    suspend fun readAll(): ByteArray {
        ensureOpen()
        if (size <= 0L) {
            return read(0L, 65536)
        }
        require(size <= Int.MAX_VALUE) { "File size ($size bytes) exceeds ByteArray capacity; use chunked read(offset, length)" }
        return read(0L, size.toInt())
    }

    /**
     * Writes a slice of [data] starting at file [offset].
     * Payloads exceeding the server's `MaxWriteSize` are automatically split into chunks.
     *
     * @return Total number of bytes written.
     */
    suspend fun write(
        offset: Long,
        data: ByteArray,
        startIndex: Int = 0,
        length: Int = data.size - startIndex,
    ): Int {
        ensureOpen()
        require(offset >= 0L) { "offset must be non-negative" }
        require(startIndex >= 0 && length >= 0 && length <= data.size - startIndex) { "Invalid data slice bounds" }
        if (length == 0) return 0

        val maxChunk = share.client.maxWriteSize.coerceAtMost(262144)
        var totalWritten = 0
        while (totalWritten < length) {
            val chunkLen = minOf(maxChunk, length - totalWritten)
            val req = SmbMessages.buildWriteRequest(
                sessionId = share.client.sessionId,
                treeId = share.treeId,
                fileId = fileId,
                offset = offset + totalWritten,
                data = data,
                startIndex = startIndex + totalWritten,
                length = chunkLen,
            )
            val resp = share.client.executeCommand(req, share.encryptShare)
            val written = SmbMessages.parseWriteResponse(resp)
            if (written <= 0) break
            val actualWritten = minOf(written, chunkLen)
            totalWritten += actualWritten
            if (actualWritten < chunkLen) break
        }

        val endPos = offset + totalWritten
        if (endPos > metadata.size) {
            metadata = metadata.copy(size = endPos)
        }
        return totalWritten
    }

    /**
     * Acquires an exclusive or shared byte-range lock on the file (`SMB2 LOCK`).
     *
     * @param offset Starting byte offset of the lock range.
     * @param length Number of bytes to lock.
     * @param exclusive `true` for an exclusive lock (`SMB2_LOCKFLAG_EXCLUSIVE_LOCK`),
     *   or `false` for a shared lock (`SMB2_LOCKFLAG_SHARED_LOCK`).
     * @param failImmediately If `true`, fails immediately (`SMB2_LOCKFLAG_FAIL_IMMEDIATELY`) when the range conflicts
     *   with an existing lock instead of waiting.
     */
    suspend fun lock(
        offset: Long = 0L,
        length: Long = Long.MAX_VALUE,
        exclusive: Boolean = true,
        failImmediately: Boolean = true,
    ) {
        ensureOpen()
        var flags = if (exclusive) {
            SmbMessages.SMB2_LOCKFLAG_EXCLUSIVE_LOCK
        } else {
            SmbMessages.SMB2_LOCKFLAG_SHARED_LOCK
        }
        if (failImmediately) {
            flags = flags or SmbMessages.SMB2_LOCKFLAG_FAIL_IMMEDIATELY
        }
        val req = SmbMessages.buildLockRequest(
            sessionId = share.client.sessionId,
            treeId = share.treeId,
            fileId = fileId,
            offset = offset,
            length = length,
            flags = flags,
        )
        val resp = share.client.executeCommand(req, share.encryptShare)
        SmbMessages.parseSimpleSuccessResponse(resp, "LOCK")
    }

    /**
     * Releases a byte-range lock previously acquired with [lock] (`SMB2 LOCK` with `SMB2_LOCKFLAG_UNLOCK`).
     */
    suspend fun unlock(offset: Long = 0L, length: Long = Long.MAX_VALUE) {
        ensureOpen()
        val req = SmbMessages.buildLockRequest(
            sessionId = share.client.sessionId,
            treeId = share.treeId,
            fileId = fileId,
            offset = offset,
            length = length,
            flags = SmbMessages.SMB2_LOCKFLAG_UNLOCK,
        )
        val resp = share.client.executeCommand(req, share.encryptShare)
        SmbMessages.parseSimpleSuccessResponse(resp, "UNLOCK")
    }

    /**
     * Truncates or extends the file to [newSize] bytes (`FileEndOfFileInformation`).
     */
    suspend fun setLength(newSize: Long) {
        ensureOpen()
        require(newSize >= 0L) { "newSize must be non-negative" }
        val req = SmbMessages.buildSetInfoRequest(
            sessionId = share.client.sessionId,
            treeId = share.treeId,
            fileId = fileId,
            fileInfoClass = 20u, // FileEndOfFileInformation
            infoBuffer = SmbMessages.buildFileEndOfFilePayload(newSize),
        )
        val resp = share.client.executeCommand(req, share.encryptShare)
        SmbMessages.parseSimpleSuccessResponse(resp, "SET_INFO (EndOfFile)")
        metadata = metadata.copy(size = newSize)
    }

    /**
     * Flushes server-side write buffers for this file to persistent storage (`SMB2 FLUSH`).
     */
    suspend fun flush() {
        ensureOpen()
        val req = SmbMessages.buildFlushRequest(
            sessionId = share.client.sessionId,
            treeId = share.treeId,
            fileId = fileId,
        )
        val resp = share.client.executeCommand(req, share.encryptShare)
        SmbMessages.parseSimpleSuccessResponse(resp, "FLUSH")
    }

    /**
     * Wraps this open file handle in an [SmbRandomAccessFile].
     */
    fun toRandomAccessFile(
        path: String = "",
        mode: SmbRandomAccessMode = SmbRandomAccessMode.READ_WRITE,
        bufferSize: Int = SmbRandomAccessFile.DEFAULT_BUFFER_SIZE,
    ): SmbRandomAccessFile {
        return SmbRandomAccessFile(
            file = this,
            path = path,
            mode = mode,
            bufferSize = bufferSize,
        )
    }

    /**
     * Returns a `kotlinx.io.RawSource` that reads from this file.
     *
     * @param startOffset Initial byte offset from which to start reading (defaults to `0L`).
     * @param closeFileOnClose Whether closing the returned source also closes this [SmbFile] handle.
     */
    fun asRawSource(
        startOffset: Long = 0L,
        closeFileOnClose: Boolean = true,
    ): RawSource {
        require(startOffset >= 0L) { "startOffset must be non-negative" }
        return object : RawSource {
            private var currentOffset = startOffset
            private var sourceClosed = false
            private val tempBuffer = ByteArray(64 * 1024)
            private var bufPos = 0
            private var bufLimit = 0

            override fun readAtMostTo(sink: Buffer, byteCount: Long): Long {
                check(!sourceClosed) { "Source is closed" }
                if (byteCount <= 0L) return 0L

                if (bufPos >= bufLimit) {
                    if (currentOffset >= size) return -1L
                    val fetchLen = minOf(size - currentOffset, tempBuffer.size.toLong()).toInt()
                    if (fetchLen <= 0) return -1L

                    val bytesRead = runBlocking {
                        readInto(currentOffset, tempBuffer, 0, fetchLen)
                    }
                    if (bytesRead <= 0) return -1L

                    currentOffset += bytesRead
                    bufPos = 0
                    bufLimit = bytesRead
                }

                val toCopy = minOf(byteCount, (bufLimit - bufPos).toLong()).toInt()
                sink.write(tempBuffer, bufPos, bufPos + toCopy)
                bufPos += toCopy
                return toCopy.toLong()
            }

            override fun close() {
                if (sourceClosed) return
                sourceClosed = true
                bufPos = 0
                bufLimit = 0
                if (closeFileOnClose) {
                    this@SmbFile.close()
                }
            }
        }
    }

    /**
     * Returns a buffered `kotlinx.io.Source` that reads from this file.
     */
    fun asSource(
        startOffset: Long = 0L,
        closeFileOnClose: Boolean = true,
    ): Source = asRawSource(startOffset, closeFileOnClose).buffered()

    /**
     * Returns a `kotlinx.io.RawSink` that writes to this file.
     *
     * @param startOffset Initial byte offset at which to start writing (defaults to `0L`).
     * @param closeFileOnClose Whether closing the returned sink also closes this [SmbFile] handle.
     */
    fun asRawSink(
        startOffset: Long = 0L,
        closeFileOnClose: Boolean = true,
    ): RawSink {
        require(startOffset >= 0L) { "startOffset must be non-negative" }
        return object : RawSink {
            private var currentOffset = startOffset
            private var sinkClosed = false
            private val tempBuffer = ByteArray(64 * 1024)
            private var bufLen = 0

            private fun flushBuffer() {
                if (bufLen <= 0) return
                var offsetInBuf = 0
                while (offsetInBuf < bufLen) {
                    val toWrite = bufLen - offsetInBuf
                    val written = runBlocking {
                        this@SmbFile.write(currentOffset, tempBuffer, offsetInBuf, toWrite)
                    }
                    check(written > 0) { "Failed to write remaining bytes to SMB file at offset $currentOffset" }
                    currentOffset += written
                    offsetInBuf += written
                }
                bufLen = 0
            }

            override fun write(source: Buffer, byteCount: Long) {
                check(!sinkClosed) { "Sink is closed" }
                var remaining = byteCount
                while (remaining > 0L) {
                    val space = tempBuffer.size - bufLen
                    val toRead = minOf(remaining, space.toLong()).toInt()
                    val readCount = source.readAtMostTo(tempBuffer, bufLen, bufLen + toRead)
                    if (readCount <= 0) break
                    bufLen += readCount
                    remaining -= readCount
                    if (bufLen == tempBuffer.size) {
                        flushBuffer()
                    }
                }
            }

            override fun flush() {
                check(!sinkClosed) { "Sink is closed" }
                flushBuffer()
                runBlocking {
                    this@SmbFile.flush()
                }
            }

            override fun close() {
                if (sinkClosed) return
                val flushError = runCatching {
                    flushBuffer()
                    runBlocking {
                        this@SmbFile.flush()
                    }
                }.exceptionOrNull()
                sinkClosed = true
                if (closeFileOnClose) {
                    runCatching { this@SmbFile.close() }
                }
                if (flushError != null) {
                    throw flushError
                }
            }
        }
    }

    /**
     * Returns a buffered `kotlinx.io.Sink` that writes to this file.
     */
    fun asSink(
        startOffset: Long = 0L,
        closeFileOnClose: Boolean = true,
    ): Sink = asRawSink(startOffset, closeFileOnClose).buffered()

    /**
     * Closes the file handle on the server (`SMB2 CLOSE`).
     */
    suspend fun closeSuspend() {
        if (closed) return
        closed = true
        runCatching {
            share.closeFileId(fileId)
        }
    }

    override fun close() {
        if (closed) return
        runBlocking {
            closeSuspend()
        }
    }
}
