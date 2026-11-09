package com.sorrowblue.kmcifs.client

import com.sorrowblue.kmcifs.client.protocol.NtStatus
import com.sorrowblue.kmcifs.client.protocol.SmbAccessMask
import com.sorrowblue.kmcifs.client.protocol.SmbCreateDisposition
import com.sorrowblue.kmcifs.client.protocol.SmbCreateOptions
import com.sorrowblue.kmcifs.client.protocol.SmbException
import com.sorrowblue.kmcifs.client.protocol.SmbFileAttributes
import com.sorrowblue.kmcifs.client.protocol.SmbFileId
import com.sorrowblue.kmcifs.client.protocol.SmbMessages
import com.sorrowblue.kmcifs.client.protocol.SmbShareAccess
import kotlinx.coroutines.runBlocking

/**
 * Represents a tree connection to the `IPC$` share for named pipe operations.
 */
class SmbPipeShare internal constructor(
    val client: SmbClient,
    val treeId: UInt,
    val encryptShare: Boolean,
) : AutoCloseable {

    @kotlin.concurrent.Volatile
    private var disconnected = false

    val isClosed: Boolean
        get() = disconnected || client.isClosed

    /**
     * Opens a named pipe by name (for example, `"srvsvc"` or `"wkssvc"`).
     */
    suspend fun openPipe(pipeName: String): SmbNamedPipe {
        if (disconnected) {
            throw SmbException(NtStatus.STATUS_NETWORK_NAME_DELETED, "SMB IPC$ share is already disconnected")
        }
        val cleanName = pipeName.replace('/', '\\').trimStart('\\').let {
            if (it.startsWith("pipe\\", ignoreCase = true)) it.substring(5) else it
        }.trimStart('\\')
        require(cleanName.isNotEmpty()) { "pipeName must not be blank" }
        val createReq = SmbMessages.buildCreateRequest(
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
                sessionId = client.sessionId,
                treeId = treeId,
            )
            client.executeCommand(req, encryptShare)
        }
    }

    override fun close() {
        if (disconnected) return
        runBlocking {
            closeSuspend()
        }
    }
}

/**
 * Represents an open handle to an SMB named pipe.
 */
class SmbNamedPipe internal constructor(
    val pipeShare: SmbPipeShare,
    val pipeName: String,
    val fileId: SmbFileId,
) : AutoCloseable {

    @kotlin.concurrent.Volatile
    private var closed = false

    val isClosed: Boolean
        get() = closed

    private fun ensureOpen() {
        if (closed) {
            throw SmbException(NtStatus.STATUS_FILE_CLOSED, "SMB named pipe is already closed")
        }
    }

    /**
     * Performs a combined write and read transaction on the named pipe in a single round-trip
     * using `FSCTL_PIPE_TRANSCEIVE` (`SMB2 IOCTL`).
     */
    suspend fun transceive(input: ByteArray, maxOutputLength: Int = 65536): ByteArray {
        ensureOpen()
        require(maxOutputLength >= 0) { "maxOutputLength must be non-negative: $maxOutputLength" }
        val maxOutput = minOf(maxOutputLength, pipeShare.client.maxTransactSize)
        val req = SmbMessages.buildIoctlRequest(
            sessionId = pipeShare.client.sessionId,
            treeId = pipeShare.treeId,
            fileId = fileId,
            ctlCode = SmbMessages.FSCTL_PIPE_TRANSCEIVE,
            inputData = input,
            maxOutputResponse = maxOutput,
        )
        val resp = pipeShare.client.executeCommand(req, pipeShare.encryptShare)
        return SmbMessages.parseIoctlResponse(resp)
    }

    /**
     * Writes data to the named pipe (`SMB2 WRITE`).
     */
    suspend fun write(data: ByteArray): Int {
        ensureOpen()
        if (data.isEmpty()) return 0
        val maxChunk = pipeShare.client.maxWriteSize.coerceAtMost(262144)
        var totalWritten = 0
        while (totalWritten < data.size) {
            val chunkLen = minOf(maxChunk, data.size - totalWritten)
            val req = SmbMessages.buildWriteRequest(
                sessionId = pipeShare.client.sessionId,
                treeId = pipeShare.treeId,
                fileId = fileId,
                offset = 0L,
                data = data,
                startIndex = totalWritten,
                length = chunkLen,
            )
            val resp = pipeShare.client.executeCommand(req, pipeShare.encryptShare)
            val written = SmbMessages.parseWriteResponse(resp)
            if (written <= 0) break
            val actualWritten = minOf(written, chunkLen)
            totalWritten += actualWritten
            if (actualWritten < chunkLen) break
        }
        return totalWritten
    }

    /**
     * Reads data from the named pipe (`SMB2 READ`).
     */
    suspend fun read(maxLength: Int = 4280): ByteArray {
        ensureOpen()
        require(maxLength >= 0) { "maxLength must be non-negative: $maxLength" }
        if (maxLength == 0) return ByteArray(0)
        val readLen = minOf(maxLength, pipeShare.client.maxReadSize)
        val req = SmbMessages.buildReadRequest(
            sessionId = pipeShare.client.sessionId,
            treeId = pipeShare.treeId,
            fileId = fileId,
            offset = 0L,
            length = readLen,
        )
        val resp = pipeShare.client.executeCommand(req, pipeShare.encryptShare)
        return SmbMessages.parseReadResponse(resp, readLen)
    }

    suspend fun closeSuspend() {
        if (closed) return
        closed = true
        runCatching {
            pipeShare.closeFileId(fileId)
        }
    }

    override fun close() {
        if (closed) return
        runBlocking {
            closeSuspend()
        }
    }
}
