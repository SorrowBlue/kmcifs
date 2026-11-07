package com.sorrowblue.kmcifs.client

import com.sorrowblue.kmcifs.client.protocol.NtStatus
import com.sorrowblue.kmcifs.client.protocol.SmbAccessMask
import com.sorrowblue.kmcifs.client.protocol.SmbCreateDisposition
import com.sorrowblue.kmcifs.client.protocol.SmbCreateOptions
import com.sorrowblue.kmcifs.client.protocol.SmbDirectoryEntry
import com.sorrowblue.kmcifs.client.protocol.SmbException
import com.sorrowblue.kmcifs.client.protocol.SmbFileAttributes
import com.sorrowblue.kmcifs.client.protocol.SmbFileMetadata
import com.sorrowblue.kmcifs.client.protocol.SmbMessages
import com.sorrowblue.kmcifs.client.protocol.SmbShareAccess

/**
 * 接続済みの SMB 共有フォルダ（Tree Connect）に対するファイル・ディレクトリ操作を提供するクラス。
 */
class SmbShare internal constructor(
    val client: SmbClient,
    val shareName: String,
    val treeId: UInt,
    val encryptShare: Boolean,
) : AutoCloseable {

    private var disconnected = false

    /**
     * 指定したディレクトリ内のファイル・サブディレクトリ一覧を取得する。
     *
     * @param path 共有ルートからの相対パス（ルートの場合は `""` または `"/"`）
     * @param pattern 検索ワイルドカード（デフォルトは `"*"`）
     */
    suspend fun listDirectory(path: String = "", pattern: String = "*"): List<SmbDirectoryEntry> {
        val createReq = SmbMessages.buildCreateRequest(
            messageId = client.allocateMessageId(1u),
            sessionId = client.sessionId,
            treeId = treeId,
            path = path,
            desiredAccess = SmbAccessMask.FILE_LIST_DIRECTORY or SmbAccessMask.FILE_READ_ATTRIBUTES or SmbAccessMask.SYNCHRONIZE,
            fileAttributes = SmbFileAttributes.DIRECTORY,
            shareAccess = SmbShareAccess.ALL,
            createDisposition = SmbCreateDisposition.FILE_OPEN,
            createOptions = SmbCreateOptions.FILE_DIRECTORY_FILE or SmbCreateOptions.FILE_SYNCHRONOUS_IO_NONALERT,
        )
        val createResp = SmbMessages.parseCreateResponse(client.executeCommand(createReq, encryptShare))
        val dirFileId = createResp.fileId

        val entries = mutableListOf<SmbDirectoryEntry>()
        try {
            var isFirstQuery = true
            val queryBufLen = minOf(client.maxTransactSize, 65536)
            val credits = maxOf(1, (queryBufLen + 65535) / 65536).toUShort()

            while (true) {
                val flags: UByte = if (isFirstQuery) 0x01u else 0x00u // SMB2_RESTART_SCANS on first query
                isFirstQuery = false
                val queryReq = SmbMessages.buildQueryDirectoryRequest(
                    messageId = client.allocateMessageId(credits),
                    sessionId = client.sessionId,
                    treeId = treeId,
                    fileId = dirFileId,
                    searchPattern = pattern,
                    flags = flags,
                    outputBufferLength = queryBufLen,
                )
                val queryRespRaw = client.executeCommand(queryReq, encryptShare)
                val batch = SmbMessages.parseQueryDirectoryResponse(queryRespRaw) ?: break
                entries.addAll(batch)
            }
        } finally {
            closeFileId(dirFileId)
        }
        return entries
    }

    /**
     * 指定したパスのファイルまたはディレクトリのメタデータ情報を取得する。
     */
    suspend fun stat(path: String): SmbFileMetadata {
        val createReq = SmbMessages.buildCreateRequest(
            messageId = client.allocateMessageId(1u),
            sessionId = client.sessionId,
            treeId = treeId,
            path = path,
            desiredAccess = SmbAccessMask.FILE_READ_ATTRIBUTES or SmbAccessMask.SYNCHRONIZE,
            fileAttributes = SmbFileAttributes.NORMAL,
            shareAccess = SmbShareAccess.ALL,
            createDisposition = SmbCreateDisposition.FILE_OPEN,
            createOptions = SmbCreateOptions.FILE_SYNCHRONOUS_IO_NONALERT,
        )
        val createResp = SmbMessages.parseCreateResponse(client.executeCommand(createReq, encryptShare))
        closeFileId(createResp.fileId)
        return createResp.metadata
    }

    /**
     * 指定したパスにファイルまたはディレクトリが存在するかどうかを判定する。
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
     * ファイルを指定したアクセス権・共有排他モードで開き、[SmbFile] ハンドルを返す。
     *
     * 他プロセスからのアクセスを完全に拒否する排他ロックで開く場合は、`shareAccess = SmbShareAccess.EXCLUSIVE` を指定する。
     */
    suspend fun openFile(
        path: String,
        desiredAccess: UInt = SmbAccessMask.READ_DEFAULT,
        shareAccess: UInt = SmbShareAccess.ALL,
        createDisposition: SmbCreateDisposition = SmbCreateDisposition.FILE_OPEN,
        fileAttributes: UInt = SmbFileAttributes.NORMAL,
        createOptions: UInt = SmbCreateOptions.FILE_NON_DIRECTORY_FILE or SmbCreateOptions.FILE_SYNCHRONOUS_IO_NONALERT,
    ): SmbFile {
        val createReq = SmbMessages.buildCreateRequest(
            messageId = client.allocateMessageId(1u),
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
     * Java の `RandomAccessFile` に相当する [SmbRandomAccessFile] をオープンして返す。
     *
     * [mode] には `"r"`（読み取り専用）、`"rw"`（読み書き）、`"rws"` / `"rwd"`（同期書き込み付き読み書き）を指定できる。
     */
    suspend fun openRandomAccessFile(
        path: String,
        mode: String = "r",
        bufferSize: Int = SmbRandomAccessFile.DEFAULT_BUFFER_SIZE,
    ): SmbRandomAccessFile {
        return SmbRandomAccessFile.open(
            share = this,
            path = path,
            mode = mode,
            bufferSize = bufferSize,
        )
    }

    /**
     * 指定した [SmbRandomAccessMode] で [SmbRandomAccessFile] をオープンして返す。
     */
    suspend fun openRandomAccessFile(
        path: String,
        mode: SmbRandomAccessMode,
        bufferSize: Int = SmbRandomAccessFile.DEFAULT_BUFFER_SIZE,
    ): SmbRandomAccessFile {
        return SmbRandomAccessFile.open(
            share = this,
            path = path,
            mode = mode,
            bufferSize = bufferSize,
        )
    }

    /**
     * ファイル全体を読み取ってバイト配列として返す。
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
     * ファイル全体を UTF-8 文字列として読み取る。
     */
    suspend fun readText(path: String): String = readBytes(path).decodeToString()

    /**
     * ファイルにバイト配列を書き込む。
     *
     * @param overwrite `true` の場合は既存ファイルを上書き作成（`FILE_OVERWRITE_IF`）、`false` の場合は新規作成のみ（`FILE_CREATE`）
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
     * ファイルに UTF-8 文字列を書き込む。
     */
    suspend fun writeText(path: String, text: String, overwrite: Boolean = true) {
        writeBytes(path, text.encodeToByteArray(), overwrite)
    }

    /**
     * ファイル末尾にバイト配列を追記する（ファイルが存在しない場合は新規作成）。
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
     * 新しいディレクトリを作成する。
     */
    suspend fun createDirectory(path: String) {
        val createReq = SmbMessages.buildCreateRequest(
            messageId = client.allocateMessageId(1u),
            sessionId = client.sessionId,
            treeId = treeId,
            path = path,
            desiredAccess = SmbAccessMask.GENERIC_READ or SmbAccessMask.GENERIC_WRITE or SmbAccessMask.SYNCHRONIZE,
            fileAttributes = SmbFileAttributes.DIRECTORY,
            shareAccess = SmbShareAccess.ALL,
            createDisposition = SmbCreateDisposition.FILE_CREATE,
            createOptions = SmbCreateOptions.FILE_DIRECTORY_FILE or SmbCreateOptions.FILE_SYNCHRONOUS_IO_NONALERT,
        )
        val createResp = SmbMessages.parseCreateResponse(client.executeCommand(createReq, encryptShare))
        closeFileId(createResp.fileId)
    }

    /**
     * ファイルを削除する。
     */
    suspend fun deleteFile(path: String) {
        deleteEntry(path, isDirectory = false)
    }

    /**
     * 空のディレクトリを削除する。
     */
    suspend fun deleteDirectory(path: String) {
        deleteEntry(path, isDirectory = true)
    }

    private suspend fun deleteEntry(path: String, isDirectory: Boolean) {
        val dirFlag = if (isDirectory) SmbCreateOptions.FILE_DIRECTORY_FILE else SmbCreateOptions.FILE_NON_DIRECTORY_FILE
        val createReq = SmbMessages.buildCreateRequest(
            messageId = client.allocateMessageId(1u),
            sessionId = client.sessionId,
            treeId = treeId,
            path = path,
            desiredAccess = SmbAccessMask.DELETE_DEFAULT,
            fileAttributes = if (isDirectory) SmbFileAttributes.DIRECTORY else SmbFileAttributes.NORMAL,
            shareAccess = SmbShareAccess.ALL,
            createDisposition = SmbCreateDisposition.FILE_OPEN,
            createOptions = dirFlag or SmbCreateOptions.FILE_SYNCHRONOUS_IO_NONALERT,
        )
        val createResp = SmbMessages.parseCreateResponse(client.executeCommand(createReq, encryptShare))
        try {
            val setInfoReq = SmbMessages.buildSetInfoRequest(
                messageId = client.allocateMessageId(1u),
                sessionId = client.sessionId,
                treeId = treeId,
                fileId = createResp.fileId,
                fileInfoClass = 13u, // FileDispositionInformation
                infoBuffer = SmbMessages.buildFileDispositionPayload(deletePending = true),
            )
            val setInfoResp = client.executeCommand(setInfoReq, encryptShare)
            SmbMessages.parseSimpleSuccessResponse(setInfoResp, "SET_INFO (Delete)")
        } finally {
            closeFileId(createResp.fileId)
        }
    }

    /**
     * ファイルまたはディレクトリの名前変更・移動を行う。
     */
    suspend fun rename(fromPath: String, toPath: String, replaceIfExists: Boolean = true) {
        val createReq = SmbMessages.buildCreateRequest(
            messageId = client.allocateMessageId(1u),
            sessionId = client.sessionId,
            treeId = treeId,
            path = fromPath,
            desiredAccess = SmbAccessMask.DELETE_DEFAULT,
            fileAttributes = SmbFileAttributes.NORMAL,
            shareAccess = SmbShareAccess.ALL,
            createDisposition = SmbCreateDisposition.FILE_OPEN,
            createOptions = SmbCreateOptions.FILE_SYNCHRONOUS_IO_NONALERT,
        )
        val createResp = SmbMessages.parseCreateResponse(client.executeCommand(createReq, encryptShare))
        try {
            val setInfoReq = SmbMessages.buildSetInfoRequest(
                messageId = client.allocateMessageId(1u),
                sessionId = client.sessionId,
                treeId = treeId,
                fileId = createResp.fileId,
                fileInfoClass = 10u, // FileRenameInformation
                infoBuffer = SmbMessages.buildFileRenamePayload(toPath, replaceIfExists),
            )
            val setInfoResp = client.executeCommand(setInfoReq, encryptShare)
            SmbMessages.parseSimpleSuccessResponse(setInfoResp, "SET_INFO (Rename)")
        } finally {
            closeFileId(createResp.fileId)
        }
    }

    internal suspend fun closeFileId(fileId: com.sorrowblue.kmcifs.client.protocol.SmbFileId) {
        val closeReq = SmbMessages.buildCloseRequest(
            messageId = client.allocateMessageId(1u),
            sessionId = client.sessionId,
            treeId = treeId,
            fileId = fileId,
        )
        val closeResp = client.executeCommand(closeReq, encryptShare)
        SmbMessages.parseSimpleSuccessResponse(closeResp, "CLOSE")
    }

    /**
     * `TREE_DISCONNECT` を送信して共有フォルダ接続を解除する。
     */
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
