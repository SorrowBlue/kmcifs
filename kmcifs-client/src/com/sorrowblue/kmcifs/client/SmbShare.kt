package com.sorrowblue.kmcifs.client

import com.sorrowblue.kmcifs.client.protocol.NtStatus
import com.sorrowblue.kmcifs.client.protocol.SmbAccessMask
import com.sorrowblue.kmcifs.client.protocol.SmbCreateDisposition
import com.sorrowblue.kmcifs.client.protocol.SmbCreateOptions
import com.sorrowblue.kmcifs.client.protocol.SmbDirectoryEntry
import com.sorrowblue.kmcifs.client.protocol.SmbException
import com.sorrowblue.kmcifs.client.protocol.SmbFileAttributes
import com.sorrowblue.kmcifs.client.protocol.SmbFileId
import com.sorrowblue.kmcifs.client.protocol.SmbFileMetadata
import com.sorrowblue.kmcifs.client.protocol.SmbHeader
import com.sorrowblue.kmcifs.client.protocol.SmbMessages
import com.sorrowblue.kmcifs.client.protocol.SmbShareAccess
import kotlinx.coroutines.runBlocking
import kotlinx.io.Sink
import kotlinx.io.Source

/**
 * Provides file and directory operations on a connected SMB shared folder (`SMB2 TREE_CONNECT`).
 */
class SmbShare internal constructor(
    val client: SmbClient,
    val shareName: String,
    val treeId: UInt,
    val encryptShare: Boolean,
) : AutoCloseable {

    @kotlin.concurrent.Volatile
    private var disconnected = false

    val isClosed: Boolean
        get() = disconnected || client.isClosed

    private fun ensureConnected() {
        if (disconnected) {
            throw SmbException(NtStatus.STATUS_NETWORK_NAME_DELETED, "SMB share is already disconnected")
        }
    }

    /**
     * Lists files and subdirectories within the specified directory.
     *
     * @param path Path relative to the share root (use `""` or `"/"` for the root directory).
     * @param pattern Search wildcard pattern (defaults to `"*"`).
     * @param bufferSize Maximum output buffer size in bytes requested per `SMB2 QUERY_DIRECTORY` call.
     */
    suspend fun listDirectory(
        path: String = "",
        pattern: String = "*",
        bufferSize: Int = client.config.queryDirectoryBufferSize,
    ): List<SmbDirectoryEntry> {
        ensureConnected()
        require(bufferSize > 0) { "bufferSize must be positive: $bufferSize" }
        val queryBufLen = minOf(client.maxTransactSize, bufferSize)

        val createReq = SmbMessages.buildCreateRequest(
            sessionId = client.sessionId,
            treeId = treeId,
            path = path,
            desiredAccess = SmbAccessMask.FILE_LIST_DIRECTORY or SmbAccessMask.FILE_READ_ATTRIBUTES or SmbAccessMask.SYNCHRONIZE,
            fileAttributes = SmbFileAttributes.DIRECTORY,
            shareAccess = SmbShareAccess.ALL,
            createDisposition = SmbCreateDisposition.FILE_OPEN,
            createOptions = SmbCreateOptions.FILE_DIRECTORY_FILE or SmbCreateOptions.FILE_SYNCHRONOUS_IO_NONALERT,
        )
        val firstQueryReq = SmbMessages.buildQueryDirectoryRequest(
            sessionId = client.sessionId,
            treeId = treeId,
            fileId = SmbFileId.COMPOUND_RELATED,
            searchPattern = pattern,
            flags = 0x01u, // SMB2_RESTART_SCANS
            outputBufferLength = queryBufLen,
        )

        val compoundResps = client.executeCompoundCommands(listOf(createReq, firstQueryReq), encryptShare)
        val createResp = SmbMessages.parseCreateResponse(compoundResps[0])
        val dirFileId = createResp.fileId

        val entries = mutableListOf<SmbDirectoryEntry>()
        try {
            val firstBatch = SmbMessages.parseQueryDirectoryResponse(compoundResps[1])
            if (firstBatch != null) {
                entries.addAll(firstBatch)
                while (true) {
                    val queryReq = SmbMessages.buildQueryDirectoryRequest(
                        sessionId = client.sessionId,
                        treeId = treeId,
                        fileId = dirFileId,
                        searchPattern = pattern,
                        flags = 0x00u,
                        outputBufferLength = queryBufLen,
                    )
                    val queryRespRaw = client.executeCommand(queryReq, encryptShare)
                    val batch = SmbMessages.parseQueryDirectoryResponse(queryRespRaw) ?: break
                    entries.addAll(batch)
                }
            }
        } finally {
            closeFileId(dirFileId)
        }
        return entries
    }

    /**
     * Retrieves metadata for the file or directory at the specified [path].
     */
    suspend fun stat(path: String): SmbFileMetadata {
        ensureConnected()
        val createReq = SmbMessages.buildCreateRequest(
            sessionId = client.sessionId,
            treeId = treeId,
            path = path,
            desiredAccess = SmbAccessMask.FILE_READ_ATTRIBUTES or SmbAccessMask.SYNCHRONIZE,
            fileAttributes = SmbFileAttributes.NORMAL,
            shareAccess = SmbShareAccess.ALL,
            createDisposition = SmbCreateDisposition.FILE_OPEN,
            createOptions = SmbCreateOptions.FILE_SYNCHRONOUS_IO_NONALERT,
        )
        val closeReq = SmbMessages.buildCloseRequest(
            sessionId = client.sessionId,
            treeId = treeId,
            fileId = SmbFileId.COMPOUND_RELATED,
        )
        val responses = client.executeCompoundCommands(listOf(createReq, closeReq), encryptShare)
        val createResp = SmbMessages.parseCreateResponse(responses[0])
        SmbMessages.parseSimpleSuccessResponse(responses[1], "CLOSE")
        return createResp.metadata
    }

    /**
     * Returns whether a file or directory exists at the specified [path].
     */
    suspend fun exists(path: String): Boolean {
        return try {
            stat(path)
            true
        } catch (e: SmbException) {
            if (e.ntStatus == NtStatus.STATUS_OBJECT_NAME_NOT_FOUND ||
                e.ntStatus == NtStatus.STATUS_OBJECT_PATH_NOT_FOUND ||
                e.ntStatus == NtStatus.STATUS_NO_SUCH_FILE
            ) {
                false
            } else {
                throw e
            }
        }
    }

    /**
     * Opens a file with the specified access mask and sharing mode, returning an [SmbFile] handle.
     *
     * Pass `shareAccess = SmbShareAccess.EXCLUSIVE` to open the file with an exclusive share lock
     * that denies concurrent opens from other processes.
     */
    suspend fun openFile(
        path: String,
        desiredAccess: UInt = SmbAccessMask.READ_DEFAULT,
        shareAccess: UInt = SmbShareAccess.ALL,
        createDisposition: SmbCreateDisposition = SmbCreateDisposition.FILE_OPEN,
        fileAttributes: UInt = SmbFileAttributes.NORMAL,
        createOptions: UInt = SmbCreateOptions.FILE_NON_DIRECTORY_FILE or SmbCreateOptions.FILE_SYNCHRONOUS_IO_NONALERT,
    ): SmbFile {
        ensureConnected()
        val createReq = SmbMessages.buildCreateRequest(
            sessionId = client.sessionId,
            treeId = treeId,
            path = path,
            desiredAccess = desiredAccess,
            fileAttributes = fileAttributes,
            shareAccess = shareAccess,
            createDisposition = createDisposition,
            createOptions = createOptions,
        )
        val createResp = SmbMessages.parseCreateResponse(client.executeCommand(createReq, encryptShare))
        return SmbFile(
            share = this,
            fileId = createResp.fileId,
            initialMetadata = createResp.metadata,
        )
    }

    /**
     * Opens and returns an [SmbRandomAccessFile] modeled after `java.io.RandomAccessFile`.
     *
     * [mode] accepts `"r"` (read-only), `"rw"` (read/write), or `"rws"` / `"rwd"` (synchronous read/write).
     */
    suspend fun openRandomAccessFile(
        path: String,
        mode: String = "r",
        bufferSize: Int = client.config.randomAccessBufferSize,
    ): SmbRandomAccessFile {
        return SmbRandomAccessFile.open(
            share = this,
            path = path,
            mode = mode,
            bufferSize = bufferSize,
        )
    }

    /**
     * Opens and returns an [SmbRandomAccessFile] with the specified [SmbRandomAccessMode].
     */
    suspend fun openRandomAccessFile(
        path: String,
        mode: SmbRandomAccessMode,
        bufferSize: Int = client.config.randomAccessBufferSize,
    ): SmbRandomAccessFile {
        return SmbRandomAccessFile.open(
            share = this,
            path = path,
            mode = mode,
            bufferSize = bufferSize,
        )
    }

    /**
     * Opens and returns a buffered `kotlinx.io.Source` for reading the file at [path].
     * Closing the returned [Source] also closes the underlying [SmbFile] handle.
     */
    suspend fun openSource(path: String): Source {
        val file = openFile(
            path = path,
            desiredAccess = SmbAccessMask.READ_DEFAULT,
            shareAccess = SmbShareAccess.ALL,
            createDisposition = SmbCreateDisposition.FILE_OPEN,
        )
        return file.asSource(startOffset = 0L, closeFileOnClose = true)
    }

    /**
     * Opens and returns a buffered `kotlinx.io.Sink` for writing to the file at [path].
     * Closing the returned [Sink] flushes pending data and closes the underlying [SmbFile] handle.
     *
     * @param append If `true`, appends to the end of an existing file (or creates it if absent).
     * @param overwrite When [append] is `false`, `true` overwrites an existing file (`FILE_OVERWRITE_IF`)
     *   whereas `false` requires creating a new file (`FILE_CREATE`).
     */
    suspend fun openSink(
        path: String,
        append: Boolean = false,
        overwrite: Boolean = true,
    ): Sink {
        val disposition = when {
            append -> SmbCreateDisposition.FILE_OPEN_IF
            overwrite -> SmbCreateDisposition.FILE_OVERWRITE_IF
            else -> SmbCreateDisposition.FILE_CREATE
        }
        val file = openFile(
            path = path,
            desiredAccess = SmbAccessMask.WRITE_DEFAULT,
            shareAccess = SmbShareAccess.FILE_SHARE_READ,
            createDisposition = disposition,
        )
        val startOffset = if (append) file.size else 0L
        return file.asSink(startOffset = startOffset, closeFileOnClose = true)
    }

    /**
     * Reads the entire contents of a file into a [ByteArray].
     */
    suspend fun readBytes(path: String): ByteArray {
        val file = openFile(
            path = path,
            desiredAccess = SmbAccessMask.READ_DEFAULT,
            shareAccess = SmbShareAccess.FILE_SHARE_READ,
            createDisposition = SmbCreateDisposition.FILE_OPEN,
        )
        return try {
            file.readAll()
        } finally {
            file.closeSuspend()
        }
    }

    /**
     * Reads the entire contents of a file decoded as a UTF-8 [String].
     */
    suspend fun readText(path: String): String = readBytes(path).decodeToString()

    /**
     * Writes a [ByteArray] to a file.
     *
     * @param overwrite If `true`, overwrites an existing file (`FILE_OVERWRITE_IF`);
     *   if `false`, fails if the file already exists (`FILE_CREATE`).
     */
    suspend fun writeBytes(path: String, data: ByteArray, overwrite: Boolean = true) {
        val disposition = if (overwrite) SmbCreateDisposition.FILE_OVERWRITE_IF else SmbCreateDisposition.FILE_CREATE
        val file = openFile(
            path = path,
            desiredAccess = SmbAccessMask.WRITE_DEFAULT,
            shareAccess = SmbShareAccess.EXCLUSIVE,
            createDisposition = disposition,
        )
        try {
            file.write(0L, data)
            file.flush()
        } finally {
            file.closeSuspend()
        }
    }

    /**
     * Encodes [text] as UTF-8 and writes it to a file.
     */
    suspend fun writeText(path: String, text: String, overwrite: Boolean = true) {
        writeBytes(path, text.encodeToByteArray(), overwrite)
    }

    /**
     * Appends a [ByteArray] to the end of a file, creating the file if it does not exist.
     */
    suspend fun appendBytes(path: String, data: ByteArray) {
        val file = openFile(
            path = path,
            desiredAccess = SmbAccessMask.WRITE_DEFAULT,
            shareAccess = SmbShareAccess.FILE_SHARE_READ,
            createDisposition = SmbCreateDisposition.FILE_OPEN_IF,
        )
        try {
            file.write(file.size, data)
            file.flush()
        } finally {
            file.closeSuspend()
        }
    }

    /**
     * Creates a new directory at [path].
     */
    suspend fun createDirectory(path: String) {
        ensureConnected()
        val createReq = SmbMessages.buildCreateRequest(
            sessionId = client.sessionId,
            treeId = treeId,
            path = path,
            desiredAccess = SmbAccessMask.GENERIC_READ or SmbAccessMask.GENERIC_WRITE or SmbAccessMask.SYNCHRONIZE,
            fileAttributes = SmbFileAttributes.DIRECTORY,
            shareAccess = SmbShareAccess.ALL,
            createDisposition = SmbCreateDisposition.FILE_CREATE,
            createOptions = SmbCreateOptions.FILE_DIRECTORY_FILE or SmbCreateOptions.FILE_SYNCHRONOUS_IO_NONALERT,
        )
        val closeReq = SmbMessages.buildCloseRequest(
            sessionId = client.sessionId,
            treeId = treeId,
            fileId = SmbFileId.COMPOUND_RELATED,
        )
        val responses = client.executeCompoundCommands(listOf(createReq, closeReq), encryptShare)
        SmbMessages.parseCreateResponse(responses[0])
        SmbMessages.parseSimpleSuccessResponse(responses[1], "CLOSE")
    }

    /**
     * Deletes the file at [path].
     */
    suspend fun deleteFile(path: String) {
        deleteEntry(path, isDirectory = false)
    }

    /**
     * Deletes the empty directory at [path].
     */
    suspend fun deleteDirectory(path: String) {
        deleteEntry(path, isDirectory = true)
    }

    /**
     * Deletes the file or directory at [path], recursively removing all descendants if it is a directory.
     */
    suspend fun deleteRecursively(path: String) {
        val meta = try {
            stat(path)
        } catch (e: SmbException) {
            if (e.ntStatus == NtStatus.STATUS_OBJECT_NAME_NOT_FOUND ||
                e.ntStatus == NtStatus.STATUS_OBJECT_PATH_NOT_FOUND ||
                e.ntStatus == NtStatus.STATUS_NO_SUCH_FILE
            ) {
                return
            }
            throw e
        }
        if (!meta.isDirectory) {
            deleteFile(path)
            return
        }
        deleteDirectoryTree(path.trim('/', '\\'))
    }

    private suspend fun deleteDirectoryTree(normalizedBase: String) {
        val children = listDirectory(normalizedBase)
        for (child in children) {
            val childPath = if (normalizedBase.isEmpty()) child.name else "$normalizedBase/${child.name}"
            if (child.isDirectory) {
                deleteDirectoryTree(childPath)
            } else {
                deleteFile(childPath)
            }
        }
        deleteDirectory(normalizedBase)
    }

    private suspend fun deleteEntry(path: String, isDirectory: Boolean) {
        ensureConnected()
        val dirFlag = if (isDirectory) SmbCreateOptions.FILE_DIRECTORY_FILE else SmbCreateOptions.FILE_NON_DIRECTORY_FILE
        val createReq = SmbMessages.buildCreateRequest(
            sessionId = client.sessionId,
            treeId = treeId,
            path = path,
            desiredAccess = SmbAccessMask.DELETE_DEFAULT,
            fileAttributes = if (isDirectory) SmbFileAttributes.DIRECTORY else SmbFileAttributes.NORMAL,
            shareAccess = SmbShareAccess.ALL,
            createDisposition = SmbCreateDisposition.FILE_OPEN,
            createOptions = dirFlag or SmbCreateOptions.FILE_SYNCHRONOUS_IO_NONALERT,
        )
        val setInfoReq = SmbMessages.buildSetInfoRequest(
            sessionId = client.sessionId,
            treeId = treeId,
            fileId = SmbFileId.COMPOUND_RELATED,
            fileInfoClass = 13u, // FileDispositionInformation
            infoBuffer = SmbMessages.buildFileDispositionPayload(deletePending = true),
        )
        val closeReq = SmbMessages.buildCloseRequest(
            sessionId = client.sessionId,
            treeId = treeId,
            fileId = SmbFileId.COMPOUND_RELATED,
        )
        val responses = client.executeCompoundCommands(listOf(createReq, setInfoReq, closeReq), encryptShare)
        val createResp = SmbMessages.parseCreateResponse(responses[0])
        try {
            SmbMessages.parseSimpleSuccessResponse(responses[1], "SET_INFO (Delete)")
        } catch (e: Throwable) {
            if (SmbHeader.decode(responses[2]).status != NtStatus.STATUS_SUCCESS) {
                runCatching { closeFileId(createResp.fileId) }
            }
            throw e
        }
        SmbMessages.parseSimpleSuccessResponse(responses[2], "CLOSE")
    }

    /**
     * Renames or moves a file or directory from [fromPath] to [toPath] (`FileRenameInformation`).
     */
    suspend fun rename(fromPath: String, toPath: String, replaceIfExists: Boolean = true) {
        ensureConnected()
        val createReq = SmbMessages.buildCreateRequest(
            sessionId = client.sessionId,
            treeId = treeId,
            path = fromPath,
            desiredAccess = SmbAccessMask.DELETE_DEFAULT,
            fileAttributes = SmbFileAttributes.NORMAL,
            shareAccess = SmbShareAccess.ALL,
            createDisposition = SmbCreateDisposition.FILE_OPEN,
            createOptions = SmbCreateOptions.FILE_SYNCHRONOUS_IO_NONALERT,
        )
        val setInfoReq = SmbMessages.buildSetInfoRequest(
            sessionId = client.sessionId,
            treeId = treeId,
            fileId = SmbFileId.COMPOUND_RELATED,
            fileInfoClass = 10u, // FileRenameInformation
            infoBuffer = SmbMessages.buildFileRenamePayload(toPath, replaceIfExists),
        )
        val closeReq = SmbMessages.buildCloseRequest(
            sessionId = client.sessionId,
            treeId = treeId,
            fileId = SmbFileId.COMPOUND_RELATED,
        )
        val responses = client.executeCompoundCommands(listOf(createReq, setInfoReq, closeReq), encryptShare)
        val createResp = SmbMessages.parseCreateResponse(responses[0])
        try {
            SmbMessages.parseSimpleSuccessResponse(responses[1], "SET_INFO (Rename)")
        } catch (e: Throwable) {
            if (SmbHeader.decode(responses[2]).status != NtStatus.STATUS_SUCCESS) {
                runCatching { closeFileId(createResp.fileId) }
            }
            throw e
        }
        SmbMessages.parseSimpleSuccessResponse(responses[2], "CLOSE")
    }

    internal suspend fun closeFileId(fileId: SmbFileId) {
        val closeReq = SmbMessages.buildCloseRequest(
            sessionId = client.sessionId,
            treeId = treeId,
            fileId = fileId,
        )
        val closeResp = client.executeCommand(closeReq, encryptShare, cancellable = false)
        SmbMessages.parseSimpleSuccessResponse(closeResp, "CLOSE")
    }

    /**
     * Sends an `SMB2 TREE_DISCONNECT` request to disconnect from this shared folder.
     */
    suspend fun closeSuspend() {
        if (disconnected) return
        disconnected = true
        runCatching {
            val req = SmbMessages.buildTreeDisconnectRequest(
                sessionId = client.sessionId,
                treeId = treeId,
            )
            client.executeCommand(req, encryptShare, cancellable = false)
        }
    }

    override fun close() {
        if (disconnected) return
        runBlocking {
            closeSuspend()
        }
    }
}
