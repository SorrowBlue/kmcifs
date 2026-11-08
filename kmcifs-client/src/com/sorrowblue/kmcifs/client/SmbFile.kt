package com.sorrowblue.kmcifs.client

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
 * オープン済みのリモート SMB ファイルハンドルを表すクラス。
 *
 * 任意オフセットからの読み取り ([read])、書き込み ([write])、
 * バイト範囲の排他ロック・共有ロック ([lock] / [unlock])、およびサイズ変更 ([setLength]) を提供する。
 */
class SmbFile internal constructor(
    val share: SmbShare,
    val fileId: SmbFileId,
    initialMetadata: SmbFileMetadata,
) : AutoCloseable {

    private var closed = false

    var metadata: SmbFileMetadata = initialMetadata
        private set

    val size: Long
        get() = metadata.size

    /**
     * 指定したオフセットから最大 [length] バイトを読み取る。
     * サーバーの `MaxReadSize` を超える長さも自動的にチャンク分割して読み取る。
     */
    suspend fun read(offset: Long, length: Int): ByteArray {
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
     * 指定したオフセットから最大 [length] バイトを読み取り、呼び出し元の [destination]（開始位置 [destinationOffset]）へ直接書き込む。
     * 中間配列を生成しないゼロコピー読み取りを行い、実際に読み取られたバイト数（EOF 時は `0`）を返す。
     */
    suspend fun readInto(
        offset: Long,
        destination: ByteArray,
        destinationOffset: Int = 0,
        length: Int = destination.size - destinationOffset,
    ): Int {
        require(offset >= 0L) { "offset must be non-negative" }
        require(destinationOffset >= 0 && length >= 0 && destinationOffset + length <= destination.size) {
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
        val req = SmbMessages.buildReadRequest(
            sessionId = share.client.sessionId,
            treeId = share.treeId,
            fileId = fileId,
            offset = offset,
            length = length,
        )
        val resp = share.client.executeCommand(req, share.encryptShare)
        return SmbMessages.parseReadResponse(resp)
    }

    private suspend fun readSingleChunkInto(
        offset: Long,
        destination: ByteArray,
        destinationOffset: Int,
        length: Int,
    ): Int {
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
     * ファイル先頭から末尾まで全バイトを読み取る。
     */
    suspend fun readAll(): ByteArray {
        if (size <= 0L) {
            return read(0L, 65536)
        }
        require(size <= Int.MAX_VALUE) { "File size ($size bytes) exceeds ByteArray capacity; use chunked read(offset, length)" }
        return read(0L, size.toInt())
    }

    /**
     * 指定したオフセットへバイト配列を書き込む。
     * サーバーの `MaxWriteSize` を超えるデータも自動的にチャンク分割して書き込む。
     *
     * @return 実際に書き込まれた合計バイト数
     */
    suspend fun write(
        offset: Long,
        data: ByteArray,
        startIndex: Int = 0,
        length: Int = data.size - startIndex,
    ): Int {
        require(offset >= 0L) { "offset must be non-negative" }
        require(startIndex >= 0 && length >= 0 && startIndex + length <= data.size) { "Invalid data slice bounds" }
        if (length == 0) return 0

        val maxChunk = share.client.maxWriteSize.coerceAtMost(65536)
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
            totalWritten += written
            if (written < chunkLen) break
        }

        val endPos = offset + totalWritten
        if (endPos > metadata.size) {
            metadata = metadata.copy(size = endPos)
        }
        return totalWritten
    }

    /**
     * ファイルの指定バイト範囲に対して排他ロックまたは共有ロックを取得する (`SMB2 LOCK`)。
     *
     * @param offset ロック開始オフセット
     * @param length ロックするバイト長
     * @param exclusive `true` の場合は排他ロック (`SMB2_LOCKFLAG_EXCLUSIVE_LOCK`)、`false` の場合は共有ロック (`SMB2_LOCKFLAG_SHARED_LOCK`)
     * @param failImmediately ロックが競合している場合に待機せず即座に失敗させる場合は `true`
     */
    suspend fun lock(
        offset: Long = 0L,
        length: Long = Long.MAX_VALUE,
        exclusive: Boolean = true,
        failImmediately: Boolean = true,
    ) {
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
     * [lock] で取得した指定バイト範囲のロックを解除する (`SMB2 LOCK` with `SMB2_LOCKFLAG_UNLOCK`)。
     */
    suspend fun unlock(offset: Long = 0L, length: Long = Long.MAX_VALUE) {
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
     * ファイルサイズを変更（トランケートまたは拡張）する (`FileEndOfFileInformation`)。
     */
    suspend fun setLength(newSize: Long) {
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
     * サーバー側の書き込みバッファをストレージにフラッシュする (`SMB2 FLUSH`)。
     */
    suspend fun flush() {
        val req = SmbMessages.buildFlushRequest(
            sessionId = share.client.sessionId,
            treeId = share.treeId,
            fileId = fileId,
        )
        val resp = share.client.executeCommand(req, share.encryptShare)
        SmbMessages.parseSimpleSuccessResponse(resp, "FLUSH")
    }

    /**
     * このファイルハンドルをラップした [SmbRandomAccessFile] を返す。
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
     * このファイルを読み取る `kotlinx.io.RawSource` を返す。
     *
     * @param startOffset 読み取り開始オフセット（デフォルトは `0L`）
     * @param closeFileOnClose `Source.close()` 時にこの [SmbFile] ハンドルも閉じる場合は `true`
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
     * このファイルを読み取るバッファリング済みの `kotlinx.io.Source` を返す。
     */
    fun asSource(
        startOffset: Long = 0L,
        closeFileOnClose: Boolean = true,
    ): Source = asRawSource(startOffset, closeFileOnClose).buffered()

    /**
     * このファイルへ書き込む `kotlinx.io.RawSink` を返す。
     *
     * @param startOffset 書き込み開始オフセット（デフォルトは `0L`）
     * @param closeFileOnClose `Sink.close()` 時にこの [SmbFile] ハンドルも閉じる場合は `true`
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
     * このファイルへ書き込むバッファリング済みの `kotlinx.io.Sink` を返す。
     */
    fun asSink(
        startOffset: Long = 0L,
        closeFileOnClose: Boolean = true,
    ): Sink = asRawSink(startOffset, closeFileOnClose).buffered()

    /**
     * ファイルハンドルをサーバー上で閉じる (`SMB2 CLOSE`)。
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
