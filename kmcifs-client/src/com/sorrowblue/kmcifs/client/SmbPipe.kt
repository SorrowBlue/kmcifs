package com.sorrowblue.kmcifs.client

import com.sorrowblue.kmcifs.client.protocol.SmbAccessMask
import com.sorrowblue.kmcifs.client.protocol.SmbCreateDisposition
import com.sorrowblue.kmcifs.client.protocol.SmbCreateOptions
import com.sorrowblue.kmcifs.client.protocol.SmbFileAttributes
import com.sorrowblue.kmcifs.client.protocol.SmbFileId
import com.sorrowblue.kmcifs.client.protocol.SmbMessages
import com.sorrowblue.kmcifs.client.protocol.SmbShareAccess

/**
 * `IPC$` 共有（名前付きパイプ用ツリー接続）を表すクラス。
 */
class SmbPipeShare internal constructor(
    val client: SmbClient,
    val treeId: UInt,
    val encryptShare: Boolean,
) : AutoCloseable {

    private var disconnected = false

    /**
     * 指定した名前のパイプ（例: `"srvsvc"`, `"wkssvc"`）を開く。
     */
    suspend fun openPipe(pipeName: String): SmbNamedPipe {
        val cleanName = pipeName.removePrefix("\\pipe\\").removePrefix("pipe\\").trimStart('/', '\\')
        val createReq = SmbMessages.buildCreateRequest(
            messageId = client.allocateMessageId(1u),
            sessionId = client.sessionId,
            treeId = treeId,
            path = cleanName,
            desiredAccess = SmbAccessMask.GENERIC_READ or SmbAccessMask.GENERIC_WRITE or SmbAccessMask.SYNCHRONIZE,
            fileAttributes = SmbFileAttributes.NORMAL,
            shareAccess = SmbShareAccess.ALL,
            createDisposition = SmbCreateDisposition.FILE_OPEN,
            createOptions = SmbCreateOptions.FILE_NON_DIRECTORY_FILE or SmbCreateOptions.FILE_SYNCHRONOUS_IO_NONALERT,
        )
        val createResp = SmbMessages.parseCreateResponse(client.executeCommand(createReq, encryptShare))
        return SmbNamedPipe(
            pipeShare = this,
            pipeName = cleanName,
            fileId = createResp.fileId,
        )
    }

    internal suspend fun closeFileId(fileId: SmbFileId) {
        val closeReq = SmbMessages.buildCloseRequest(
            messageId = client.allocateMessageId(1u),
            sessionId = client.sessionId,
            treeId = treeId,
            fileId = fileId,
        )
        val closeResp = client.executeCommand(closeReq, encryptShare)
        SmbMessages.parseSimpleSuccessResponse(closeResp, "CLOSE (Pipe)")
    }

    suspend fun closeSuspend() {
        if (disconnected) return
        disconnected = true
        runCatching {
            val req = SmbMessages.buildTreeDisconnectRequest(
                messageId = client.allocateMessageId(1u),
                sessionId = client.sessionId,
                treeId = treeId,
            )
            client.executeCommand(req, encryptShare)
        }
    }

    override fun close() {
        disconnected = true
    }
}

/**
 * オープン済みの SMB 名前付きパイプハンドルを表すクラス。
 */
class SmbNamedPipe internal constructor(
    val pipeShare: SmbPipeShare,
    val pipeName: String,
    val fileId: SmbFileId,
) : AutoCloseable {

    private var closed = false

    /**
     * `FSCTL_PIPE_TRANSCEIVE` (`SMB2 IOCTL`) を使用して、パイプへの書き込みと応答の読み取りを 1 往復で実行する。
     */
    suspend fun transceive(input: ByteArray, maxOutputLength: Int = 65536): ByteArray {
        val credits = maxOf(1, (maxOf(input.size, maxOutputLength) + 65535) / 65536).toUShort()
        val req = SmbMessages.buildIoctlRequest(
            messageId = pipeShare.client.allocateMessageId(credits),
            sessionId = pipeShare.client.sessionId,
            treeId = pipeShare.treeId,
            fileId = fileId,
            ctlCode = SmbMessages.FSCTL_PIPE_TRANSCEIVE,
            inputData = input,
            maxOutputResponse = maxOutputLength,
        )
        val resp = pipeShare.client.executeCommand(req, pipeShare.encryptShare)
        return SmbMessages.parseIoctlResponse(resp)
    }

    /**
     * パイプへデータを書き込む (`SMB2 WRITE`)。
     */
    suspend fun write(data: ByteArray): Int {
        val credits = maxOf(1, (data.size + 65535) / 65536).toUShort()
        val req = SmbMessages.buildWriteRequest(
            messageId = pipeShare.client.allocateMessageId(credits),
            sessionId = pipeShare.client.sessionId,
            treeId = pipeShare.treeId,
            fileId = fileId,
            offset = 0L,
            data = data,
        )
        val resp = pipeShare.client.executeCommand(req, pipeShare.encryptShare)
        return SmbMessages.parseWriteResponse(resp)
    }

    /**
     * パイプからデータを読み取る (`SMB2 READ`)。
     */
    suspend fun read(maxLength: Int = 4280): ByteArray {
        val credits = maxOf(1, (maxLength + 65535) / 65536).toUShort()
        val req = SmbMessages.buildReadRequest(
            messageId = pipeShare.client.allocateMessageId(credits),
            sessionId = pipeShare.client.sessionId,
            treeId = pipeShare.treeId,
            fileId = fileId,
            offset = 0L,
            length = maxLength,
        )
        val resp = pipeShare.client.executeCommand(req, pipeShare.encryptShare)
        return SmbMessages.parseReadResponse(resp)
    }

    suspend fun closeSuspend() {
        if (closed) return
        closed = true
        pipeShare.closeFileId(fileId)
    }

    override fun close() {
        closed = true
    }
}
