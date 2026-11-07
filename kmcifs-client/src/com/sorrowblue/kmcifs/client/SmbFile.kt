package com.sorrowblue.kmcifs.client

import com.sorrowblue.kmcifs.client.protocol.SmbFileId
import com.sorrowblue.kmcifs.client.protocol.SmbFileMetadata
import com.sorrowblue.kmcifs.client.protocol.SmbMessages

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
        var totalRead = 0
        while (totalRead < length) {
            val toRead = minOf(maxChunk, length - totalRead)
            val chunk = readSingleChunk(offset + totalRead, toRead)
            if (chunk.isEmpty()) break
            chunk.copyInto(buffer, totalRead)
            totalRead += chunk.size
            if (chunk.size < toRead) break
        }
        return if (totalRead == length) buffer else buffer.copyOf(totalRead)
    }

    private suspend fun readSingleChunk(offset: Long, length: Int): ByteArray {
        val credits = maxOf(1, (length + 65535) / 65536).toUShort()
        val req = SmbMessages.buildReadRequest(
            messageId = share.client.allocateMessageId(credits),
            sessionId = share.client.sessionId,
            treeId = share.treeId,
            fileId = fileId,
            offset = offset,
            length = length,
        )
        val resp = share.client.executeCommand(req, share.encryptShare)
        return SmbMessages.parseReadResponse(resp)
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
            val credits = maxOf(1, (chunkLen + 65535) / 65536).toUShort()
            val req = SmbMessages.buildWriteRequest(
                messageId = share.client.allocateMessageId(credits),
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
            messageId = share.client.allocateMessageId(1u),
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
            messageId = share.client.allocateMessageId(1u),
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
            messageId = share.client.allocateMessageId(1u),
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
            messageId = share.client.allocateMessageId(1u),
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
     * ファイルハンドルをサーバー上で閉じる (`SMB2 CLOSE`)。
     */
    suspend fun closeSuspend() {
        if (closed) return
        closed = true
        share.closeFileId(fileId)
    }

    override fun close() {
        closed = true
    }
}
