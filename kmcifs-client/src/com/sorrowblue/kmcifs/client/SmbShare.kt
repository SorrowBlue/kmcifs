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
 * 接続済みの SMB 共有フォルダ（Tree Connect）に対するファイル・ディレクトリ操作を提供するクラス。
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
     * 指定したディレクトリ内のファイル・サブディレクトリ一覧を取得する。
     *
     * @param path 共有ルートからの相対パス（ルートの場合は `""` または `"/"`）
     * @param pattern 検索ワイルドカード（デフォルトは `"*"`）
     * @param bufferSize 1回の `QUERY_DIRECTORY` リクエストで要求する最大バッファサイズ（バイト）
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
     * 指定したパスのファイルまたはディレクトリのメタデータ情報を取得する。
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
     * Java の `RandomAccessFile` に相当する [SmbRandomAccessFile] をオープンして返す。
     *
     * [mode] には `"r"`（読み取り専用）、`"rw"`（読み書き）、`"rws"` / `"rwd"`（同期書き込み付き読み書き）を指定できる。
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
     * 指定した [SmbRandomAccessMode] で [SmbRandomAccessFile] をオープンして返す。
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
     * 指定したパスのファイルを読み取る `kotlinx.io.Source` をオープンして返す。
     * 返された `Source.close()` を呼ぶと背後の [SmbFile] ハンドルも閉じられる。
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
     * 指定したパスのファイルへ書き込む `kotlinx.io.Sink` をオープンして返す。
     * 返された `Sink.close()` を呼ぶとフラッシュのうえ背後の [SmbFile] ハンドルも閉じられる。
     *
     * @param append `true` の場合は既存ファイルの末尾から追記する
     * @param overwrite [append] が `false` のとき、`true` なら上書き作成（`FILE_OVERWRITE_IF`）、`false` なら新規作成のみ（`FILE_CREATE`）
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

    /**
     * 指定したパスのファイル、またはディレクトリとその配下の全エントリを再帰的に削除する。
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
     * ファイルまたはディレクトリの名前変更・移動を行う。
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

    internal suspend fun closeFileId(fileId: com.sorrowblue.kmcifs.client.protocol.SmbFileId) {
        val closeReq = SmbMessages.buildCloseRequest(
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
