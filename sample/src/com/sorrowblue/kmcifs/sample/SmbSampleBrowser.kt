package com.sorrowblue.kmcifs.sample

import com.sorrowblue.kmcifs.client.SmbClient
import com.sorrowblue.kmcifs.client.SmbConfig
import com.sorrowblue.kmcifs.client.SmbEncryptionPolicy
import com.sorrowblue.kmcifs.client.SmbFile
import com.sorrowblue.kmcifs.client.SmbShare
import com.sorrowblue.kmcifs.client.auth.SmbCredentials
import com.sorrowblue.kmcifs.client.protocol.SmbAccessMask
import com.sorrowblue.kmcifs.client.protocol.SmbCipherId
import com.sorrowblue.kmcifs.client.protocol.SmbCreateDisposition
import com.sorrowblue.kmcifs.client.protocol.SmbDialect
import com.sorrowblue.kmcifs.client.protocol.SmbDirectoryEntry
import com.sorrowblue.kmcifs.client.protocol.SmbShareAccess
import com.sorrowblue.kmcifs.client.protocol.SmbShareInfo
import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.network.sockets.ServerSocket
import io.ktor.network.sockets.Socket
import io.ktor.network.sockets.aSocket
import io.ktor.network.sockets.openReadChannel
import io.ktor.network.sockets.openWriteChannel
import io.ktor.utils.io.readUTF8Line
import io.ktor.utils.io.writeFully
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

/**
 * サンプルアプリのファイルビューアで扱うプレビュー種別。
 */
enum class SmbPreviewType(val label: String) {
    TEXT("TEXT"),
    IMAGE("IMAGE"),
    VIDEO("VIDEO"),
    OTHER("FILE");

    companion object {
        private val TEXT_EXTENSIONS = setOf(
            "txt", "md", "markdown", "json", "xml", "yaml", "yml", "toml",
            "ini", "conf", "cfg", "properties", "csv", "tsv", "log",
            "html", "htm", "css", "js", "mjs", "ts", "tsx", "jsx",
            "kt", "kts", "java", "py", "rb", "go", "rs", "c", "cpp", "h", "hpp",
            "cs", "swift", "sh", "bash", "zsh", "bat", "cmd", "ps1", "sql",
            "gradle", "gitignore", "gitattributes", "env", " srt", "vtt",
        )

        private val TEXT_FILENAMES = setOf(
            "readme", "license", "notice", "authors", "changelog", "makefile", "dockerfile",
        )

        private val IMAGE_EXTENSIONS = setOf(
            "jpg", "jpeg", "png", "webp", "gif", "bmp", "ico", "heic", "heif",
        )

        private val VIDEO_EXTENSIONS = setOf(
            "mp4", "m4v", "mkv", "webm", "mov", "3gp", "avi", "ts",
        )

        fun fromFileName(fileName: String): SmbPreviewType {
            val clean = fileName.trim()
            val dotIndex = clean.lastIndexOf('.')
            if (dotIndex <= 0 || dotIndex == clean.length - 1) {
                if (clean.lowercase() in TEXT_FILENAMES) return TEXT
                if (clean.startsWith('.') && clean.drop(1).lowercase() in TEXT_EXTENSIONS) return TEXT
                return OTHER
            }
            val ext = clean.substring(dotIndex + 1).lowercase()
            return when (ext) {
                in TEXT_EXTENSIONS -> TEXT
                in IMAGE_EXTENSIONS -> IMAGE
                in VIDEO_EXTENSIONS -> VIDEO
                else -> OTHER
            }
        }
    }
}

/**
 * 確立された SMB セッションの概要情報。
 */
data class SmbConnectionSummary(
    val host: String,
    val port: Int,
    val negotiatedDialect: SmbDialect,
    val negotiatedCipher: SmbCipherId?,
    val isEncrypted: Boolean,
)

/**
 * 指定ディレクトリ内のフォルダ一覧とファイル一覧。
 */
data class SmbDirectoryListing(
    val connection: SmbConnectionSummary,
    val shareName: String,
    val directoryPath: String,
    val folders: List<SmbDirectoryEntry>,
    val files: List<SmbDirectoryEntry>,
)

/**
 * テキストファイルのプレビュー結果。
 */
data class SmbTextFileContent(
    val fileName: String,
    val filePath: String,
    val text: String,
    val totalSize: Long,
    val loadedBytes: Int,
    val isTruncated: Boolean,
)

/**
 * パス操作やサイズ・日時の表示文字列変換を行うユーティリティ。
 */
object SmbFormatUtils {

    fun normalizePath(path: String): String {
        return path.trim().replace('\\', '/').trim('/')
    }

    fun joinPath(parent: String, child: String): String {
        val cleanParent = normalizePath(parent)
        val cleanChild = normalizePath(child)
        return when {
            cleanParent.isEmpty() -> cleanChild
            cleanChild.isEmpty() -> cleanParent
            else -> "$cleanParent/$cleanChild"
        }
    }

    fun parentPath(path: String): String? {
        val clean = normalizePath(path)
        if (clean.isEmpty()) return null
        val lastSlash = clean.lastIndexOf('/')
        return if (lastSlash < 0) "" else clean.substring(0, lastSlash)
    }

    fun formatBytes(bytes: Long): String {
        if (bytes < 1024L) return "$bytes B"
        val kb = bytes / 1024.0
        if (kb < 1024.0) return "${formatDecimal1(kb)} KB"
        val mb = kb / 1024.0
        if (mb < 1024.0) return "${formatDecimal1(mb)} MB"
        val gb = mb / 1024.0
        return "${formatDecimal1(gb)} GB"
    }

    fun formatDurationMillis(millis: Long): String {
        val totalSeconds = (millis / 1000L).coerceAtLeast(0L)
        val hours = totalSeconds / 3600L
        val minutes = (totalSeconds % 3600L) / 60L
        val seconds = totalSeconds % 60L
        val mm = minutes.toString().padStart(2, '0')
        val ss = seconds.toString().padStart(2, '0')
        return if (hours > 0L) "$hours:$mm:$ss" else "$mm:$ss"
    }

    fun formatEpochMillisUtc(epochMillis: Long): String {
        if (epochMillis <= 0L) return "-"
        val totalSeconds = epochMillis / 1000L
        val days = totalSeconds / 86400L
        val remSecs = ((totalSeconds % 86400L) + 86400L) % 86400L
        val hour = (remSecs / 3600L).toInt()
        val minute = ((remSecs % 3600L) / 60L).toInt()

        // Howard Hinnant's civil_from_days algorithm
        val z = days + 719468L
        val era = (if (z >= 0) z else z - 146096L) / 146097L
        val doe = z - era * 146097L
        val yoe = (doe - doe / 1460L + doe / 36524L - doe / 146096L) / 365L
        var y = yoe + era * 400L
        val doy = doe - (365L * yoe + yoe / 4L - yoe / 100L)
        val mp = (5L * doy + 2L) / 153L
        val d = (doy - (153L * mp + 2L) / 5L + 1L).toInt()
        val m = (mp + (if (mp < 10L) 3L else -9L)).toInt()
        if (m <= 2) y += 1L

        val yyyy = y.toString().padStart(4, '0')
        val mo = m.toString().padStart(2, '0')
        val dd = d.toString().padStart(2, '0')
        val hh = hour.toString().padStart(2, '0')
        val mi = minute.toString().padStart(2, '0')
        return "$yyyy-$mo-$dd $hh:$mi"
    }

    private fun formatDecimal1(value: Double): String {
        val tenths = ((value * 10.0) + 0.5).toLong()
        val whole = tenths / 10L
        val frac = tenths % 10L
        return "$whole.$frac"
    }
}

/**
 * サンプルアプリ向けに SMB セッションを保持し、共有フォルダ一覧取得・ディレクトリ探索・ファイル内容取得を行うクラス。
 */
class SmbBrowserSession {

    private val mutex = Mutex()
    private var activeConfig: SmbSavedConnection? = null
    private var activeClient: SmbClient? = null
    private var activeShareName: String? = null
    private var activeShare: SmbShare? = null

    /**
     * 指定した接続設定で SMB サーバーへ接続し、セッション情報を返す。
     */
    suspend fun connect(config: SmbSavedConnection): SmbConnectionSummary = mutex.withLock {
        closeInternal()
        val client = openClient(config)
        activeConfig = config
        activeClient = client
        return client.toSummary()
    }

    /**
     * 接続中のサーバーから共有フォルダ一覧を取得する。
     */
    suspend fun listShares(includeHidden: Boolean = false): List<SmbShareInfo> = mutex.withLock {
        val client = ensureClientLocked()
        return try {
            client.listShares(includeHidden = includeHidden)
        } catch (e: Throwable) {
            val reconnected = reconnectLocked()
            reconnected.listShares(includeHidden = includeHidden)
        }
    }

    /**
     * 指定した共有フォルダおよび相対パスのディレクトリ一覧（フォルダ一覧・ファイル一覧）を取得する。
     */
    suspend fun listDirectory(shareName: String, directoryPath: String): SmbDirectoryListing = mutex.withLock {
        val cleanShare = shareName.trim('/', '\\', ' ')
        require(cleanShare.isNotEmpty()) { "Share name must not be empty" }
        val normalizedPath = SmbFormatUtils.normalizePath(directoryPath)

        val entries = try {
            val share = ensureShareLocked(cleanShare)
            share.listDirectory(normalizedPath)
        } catch (e: Throwable) {
            reconnectLocked()
            val share = ensureShareLocked(cleanShare)
            share.listDirectory(normalizedPath)
        }

        val sortedFolders = entries
            .filter { it.isDirectory }
            .sortedWith(compareBy(String.CASE_INSENSITIVE_ORDER) { it.name })

        val sortedFiles = entries
            .filterNot { it.isDirectory }
            .sortedWith(compareBy(String.CASE_INSENSITIVE_ORDER) { it.name })

        val client = activeClient ?: error("SMB client is not connected")
        return SmbDirectoryListing(
            connection = client.toSummary(),
            shareName = cleanShare,
            directoryPath = normalizedPath,
            folders = sortedFolders,
            files = sortedFiles,
        )
    }

    /**
     * テキストファイルの内容を読み取る。
     */
    suspend fun readTextFile(
        shareName: String,
        filePath: String,
        maxBytes: Int = 512 * 1024,
    ): SmbTextFileContent = mutex.withLock {
        val cleanShare = shareName.trim('/', '\\', ' ')
        val normalizedPath = SmbFormatUtils.normalizePath(filePath)
        val fileName = normalizedPath.substringAfterLast('/', normalizedPath)

        val file = openFileWithRetryLocked(cleanShare, normalizedPath)
        try {
            val totalSize = file.size
            val toRead = if (totalSize <= 0L) {
                maxBytes
            } else {
                minOf(totalSize, maxBytes.toLong()).toInt()
            }
            val bytes = file.read(offset = 0L, length = toRead)
            return SmbTextFileContent(
                fileName = fileName,
                filePath = normalizedPath,
                text = bytes.decodeToString(),
                totalSize = maxOf(totalSize, bytes.size.toLong()),
                loadedBytes = bytes.size,
                isTruncated = totalSize > bytes.size,
            )
        } finally {
            runCatching { file.closeSuspend() }
        }
    }

    /**
     * 画像などのファイル全体をバイト配列として読み取る。
     */
    suspend fun readFileBytes(
        shareName: String,
        filePath: String,
        maxBytes: Int = 50 * 1024 * 1024,
        onProgress: ((loadedBytes: Long, totalBytes: Long) -> Unit)? = null,
    ): ByteArray = mutex.withLock {
        val cleanShare = shareName.trim('/', '\\', ' ')
        val normalizedPath = SmbFormatUtils.normalizePath(filePath)

        val file = openFileWithRetryLocked(cleanShare, normalizedPath)
        try {
            val fileSize = file.size
            require(fileSize <= maxBytes.toLong()) {
                "File size (${SmbFormatUtils.formatBytes(fileSize)}) exceeds maximum preview limit (${SmbFormatUtils.formatBytes(maxBytes.toLong())})"
            }
            if (fileSize <= 0L) {
                val chunk = file.read(0L, 65536)
                onProgress?.invoke(chunk.size.toLong(), chunk.size.toLong())
                return chunk
            }

            val total = fileSize.toInt()
            val buffer = ByteArray(total)
            val chunkSize = 65536
            var offset = 0
            onProgress?.invoke(0L, fileSize)
            while (offset < total) {
                val readLen = minOf(chunkSize, total - offset)
                val chunk = file.read(offset.toLong(), readLen)
                if (chunk.isEmpty()) break
                chunk.copyInto(buffer, offset)
                offset += chunk.size
                onProgress?.invoke(offset.toLong(), fileSize)
                if (chunk.size < readLen) break
            }
            return if (offset == total) buffer else buffer.copyOf(offset)
        } finally {
            runCatching { file.closeSuspend() }
        }
    }

    /**
     * 動画などの大きなファイルをチャンク単位で順次読み取り、[onChunk] コールバックへ渡す。
     *
     * @return 読み取った合計バイト数
     */
    suspend fun streamFile(
        shareName: String,
        filePath: String,
        onProgress: ((loadedBytes: Long, totalBytes: Long) -> Unit)? = null,
        onChunk: suspend (chunk: ByteArray) -> Unit,
    ): Long = mutex.withLock {
        val cleanShare = shareName.trim('/', '\\', ' ')
        val normalizedPath = SmbFormatUtils.normalizePath(filePath)

        val file = openFileWithRetryLocked(cleanShare, normalizedPath)
        try {
            val totalSize = file.size
            val chunkSize = 65536
            var offset = 0L
            onProgress?.invoke(0L, totalSize)

            while (totalSize <= 0L || offset < totalSize) {
                val readLen = if (totalSize > 0L) {
                    minOf(chunkSize.toLong(), totalSize - offset).toInt()
                } else {
                    chunkSize
                }
                val chunk = file.read(offset, readLen)
                if (chunk.isEmpty()) break
                onChunk(chunk)
                offset += chunk.size
                onProgress?.invoke(offset, maxOf(totalSize, offset))
                if (chunk.size < readLen) break
            }
            return offset
        } finally {
            runCatching { file.closeSuspend() }
        }
    }

    /**
     * 動画ストリーミング再生向けに、リモートファイルを開いたまま任意オフセットからオンデマンド読み取りを行う
     * [SmbRandomAccessStream] を返す。
     */
    suspend fun openRandomAccessStream(
        shareName: String,
        filePath: String,
        cacheWindowBytes: Int = 256 * 1024,
        onBytesFetched: ((totalFetchedBytes: Long, lastPosition: Long) -> Unit)? = null,
    ): SmbRandomAccessStream = mutex.withLock {
        val cleanShare = shareName.trim('/', '\\', ' ')
        val normalizedPath = SmbFormatUtils.normalizePath(filePath)

        val smbFile = openFileWithRetryLocked(cleanShare, normalizedPath)
        return SmbRandomAccessStream(
            sessionMutex = mutex,
            initialFile = smbFile,
            reopenFileLocked = {
                reconnectLocked()
                val share = ensureShareLocked(cleanShare)
                share.openFile(
                    path = normalizedPath,
                    desiredAccess = SmbAccessMask.READ_DEFAULT,
                    shareAccess = SmbShareAccess.ALL,
                    createDisposition = SmbCreateDisposition.FILE_OPEN,
                )
            },
            cacheWindowBytes = cacheWindowBytes,
            onBytesFetched = onBytesFetched,
        )
    }

    private suspend fun openFileWithRetryLocked(shareName: String, normalizedPath: String): SmbFile {
        return try {
            val share = ensureShareLocked(shareName)
            share.openFile(
                path = normalizedPath,
                desiredAccess = SmbAccessMask.READ_DEFAULT,
                shareAccess = SmbShareAccess.ALL,
                createDisposition = SmbCreateDisposition.FILE_OPEN,
            )
        } catch (e: Throwable) {
            reconnectLocked()
            val share = ensureShareLocked(shareName)
            share.openFile(
                path = normalizedPath,
                desiredAccess = SmbAccessMask.READ_DEFAULT,
                shareAccess = SmbShareAccess.ALL,
                createDisposition = SmbCreateDisposition.FILE_OPEN,
            )
        }
    }

    /**
     * 現在開いている共有およびクライアント接続を閉じる。
     */
    suspend fun closeSuspend() = mutex.withLock {
        closeInternal()
    }

    private suspend fun ensureClientLocked(): SmbClient {
        val current = activeClient
        if (current != null && !current.isClosed) return current
        val cfg = activeConfig ?: error("SMB session is not configured")
        activeShare = null
        activeShareName = null
        val client = openClient(cfg)
        activeClient = client
        return client
    }

    private suspend fun reconnectLocked(): SmbClient {
        val cfg = activeConfig ?: error("SMB session is not configured")
        runCatching { activeShare?.closeSuspend() }
        runCatching { activeClient?.closeSuspend() }
        activeShare = null
        activeShareName = null
        val client = openClient(cfg)
        activeClient = client
        return client
    }

    private suspend fun ensureShareLocked(shareName: String): SmbShare {
        val client = ensureClientLocked()
        val existing = activeShare
        if (existing != null && activeShareName.equals(shareName, ignoreCase = true)) {
            return existing
        }
        if (existing != null) {
            runCatching { existing.closeSuspend() }
            activeShare = null
            activeShareName = null
        }
        val opened = client.connectShare(shareName)
        activeShare = opened
        activeShareName = shareName
        return opened
    }

    private suspend fun closeInternal() {
        runCatching { activeShare?.closeSuspend() }
        runCatching { activeClient?.closeSuspend() }
        activeShare = null
        activeShareName = null
        activeClient = null
    }

    private suspend fun openClient(config: SmbSavedConnection): SmbClient {
        val credentials = SmbCredentials(
            username = config.username,
            password = config.password,
            domain = config.domain,
        )
        val smbConfig = SmbConfig(
            encryptionPolicy = config.encryptionPolicy,
            preferEncryption = config.encryptionPolicy == SmbEncryptionPolicy.REQUIRED,
            alwaysSign = true,
            verifyServerSignatures = false,
        )
        return SmbClient.connect(
            host = config.host.trim(),
            port = config.port,
            credentials = credentials,
            config = smbConfig,
        )
    }

    private fun SmbClient.toSummary(): SmbConnectionSummary {
        return SmbConnectionSummary(
            host = host,
            port = port,
            negotiatedDialect = negotiatedDialect,
            negotiatedCipher = negotiatedCipher,
            isEncrypted = isSessionEncrypted,
        )
    }
}

/**
 * オープン済みの [SmbFile] に対して、マルチブロック LRU キャッシュと非同期プリフェッチ（先読み）を伴う
 * ランダムアクセス読み取りを提供するストリーム。
 *
 * 映像トラックと音声トラックが異なるファイルオフセットを交互に読み取る際のキャッシュスラッシングを防ぎ、
 * 連続ブロックをバックグラウンドで先読みすることで再生途切れを防止する。
 */
class SmbRandomAccessStream internal constructor(
    private val sessionMutex: Mutex,
    initialFile: SmbFile,
    private val reopenFileLocked: (suspend () -> SmbFile)? = null,
    private val cacheWindowBytes: Int = 256 * 1024,
    private val maxCachedBlocks: Int = 64,
    private val onBytesFetched: ((totalFetchedBytes: Long, lastPosition: Long) -> Unit)? = null,
) {
    private var smbFile: SmbFile = initialFile
    val size: Long = initialFile.size
    private val blockSize: Int = cacheWindowBytes.coerceAtLeast(65536)

    @kotlin.concurrent.Volatile
    private var closed: Boolean = false

    val isClosed: Boolean
        get() = closed

    @kotlin.concurrent.Volatile
    var totalFetchedBytes: Long = 0L
        private set

    @kotlin.concurrent.Volatile
    var lastReadPosition: Long = 0L
        private set

    private val cacheMutex = Mutex()
    private val blockCache = LinkedHashMap<Long, ByteArray>()
    private val prefetchScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var prefetchJob: Job? = null

    @kotlin.concurrent.Volatile
    private var lastAccessedBlockIndex: Long = -1L

    @kotlin.concurrent.Volatile
    private var prefetchFromBlock: Long = -1L

    @kotlin.concurrent.Volatile
    private var prefetchToBlock: Long = -1L

    /**
     * ファイル内の [position] から最大 [length] バイトを読み取り、[buffer] の [offset] 位置へ格納する。
     *
     * メモリキャッシュ ([blockCache]) へのアクセスは [cacheMutex] で保護し、ネットワーク通信を行う [sessionMutex] と分離することで、
     * バックグラウンド先読み通信中でもキャッシュ済みブロックを待機なしで即座に返却する。
     * また、コンテナのヘッダ・インデックス解析時（ファイル末尾や各チャンクへのランダムシーク時）には不要な先読みを抑制し、
     * 連続読み取り（シーケンシャル再生）に入った時点でプリフェッチを開始する。
     *
     * @return 実際に読み取ったバイト数。ファイル終端に達している場合は `-1`。
     */
    suspend fun readAt(position: Long, buffer: ByteArray, offset: Int, length: Int): Int {
        if (closed) return -1
        if (size > 0L && position >= size) return -1
        if (length <= 0) return 0

        var totalCopied = 0
        var currentPos = position
        var currentOutOffset = offset
        var remainingToRead = if (size > 0L) {
            minOf(length.toLong(), size - position).toInt()
        } else {
            length
        }
        val firstBlockIndex = position / blockSize
        val prevBlock = lastAccessedBlockIndex
        val isSequential = prevBlock >= 0L && (firstBlockIndex == prevBlock || firstBlockIndex == prevBlock + 1L)
        if (!isSequential && prevBlock >= 0L && kotlin.math.abs(firstBlockIndex - prevBlock) > 2L) {
            // ランダムシーク発生時は古い位置の先読みジョブを停止して帯域を空ける
            prefetchToBlock = -1L
            prefetchJob?.cancel()
        }
        var lastBlockIndex = -1L

        while (remainingToRead > 0 && !closed) {
            val blockIndex = currentPos / blockSize
            lastBlockIndex = blockIndex
            val offsetInBlock = (currentPos % blockSize).toInt()

            // 1. まずメモリキャッシュを短時間ロックで確認（プリフェッチ通信に阻害されない）
            var block = cacheMutex.withLock {
                val hit = blockCache.remove(blockIndex)
                if (hit != null) {
                    blockCache[blockIndex] = hit
                }
                hit
            }

            // 2. キャッシュミス時のみ SMB セッションロックを取得してネットワークから取得
            if (block == null) {
                block = withContext(NonCancellable) {
                    sessionMutex.withLock {
                        if (closed) ByteArray(0) else fetchAndCacheBlockLocked(blockIndex)
                    }
                }
            }

            if (block.isEmpty() || offsetInBlock >= block.size) break

            val available = block.size - offsetInBlock
            val toCopy = minOf(remainingToRead, available)
            block.copyInto(
                destination = buffer,
                destinationOffset = currentOutOffset,
                startIndex = offsetInBlock,
                endIndex = offsetInBlock + toCopy,
            )
            totalCopied += toCopy
            currentPos += toCopy
            currentOutOffset += toCopy
            remainingToRead -= toCopy

            if (block.size < blockSize) break
        }

        if (lastBlockIndex >= 0L) {
            lastAccessedBlockIndex = lastBlockIndex
        }

        // シーケンシャル読み取り中（または複数ブロックに跨る連続読み取り時）のみ後続ブロックをプリフェッチする
        if (totalCopied > 0 && lastBlockIndex >= 0L && !closed && (isSequential || lastBlockIndex > firstBlockIndex)) {
            schedulePrefetch(startBlock = lastBlockIndex + 1L, count = 4)
        }

        return if (totalCopied == 0) -1 else totalCopied
    }

    private suspend fun fetchAndCacheBlockLocked(blockIndex: Long): ByteArray {
        cacheMutex.withLock {
            val existing = blockCache.remove(blockIndex)
            if (existing != null) {
                blockCache[blockIndex] = existing
                return existing
            }
        }

        val blockStartOffset = blockIndex * blockSize.toLong()
        if (size > 0L && blockStartOffset >= size) return ByteArray(0)

        val fetchLen = if (size > 0L) {
            minOf(blockSize.toLong(), size - blockStartOffset).toInt()
        } else {
            blockSize
        }
        if (fetchLen <= 0) return ByteArray(0)

        val fetched = try {
            smbFile.read(offset = blockStartOffset, length = fetchLen)
        } catch (e: Throwable) {
            val reopen = reopenFileLocked ?: throw e
            if (closed) throw e
            smbFile = reopen()
            smbFile.read(offset = blockStartOffset, length = fetchLen)
        }
        if (fetched.isNotEmpty()) {
            cacheMutex.withLock {
                putBlockInCacheLocked(blockIndex, fetched)
            }
            totalFetchedBytes += fetched.size
            lastReadPosition = blockStartOffset
            onBytesFetched?.invoke(totalFetchedBytes, blockStartOffset)
        }
        return fetched
    }

    private fun putBlockInCacheLocked(blockIndex: Long, data: ByteArray) {
        blockCache.remove(blockIndex)
        while (blockCache.size >= maxCachedBlocks) {
            val eldestKey = blockCache.keys.firstOrNull() ?: break
            blockCache.remove(eldestKey)
        }
        blockCache[blockIndex] = data
    }

    private fun schedulePrefetch(startBlock: Long, count: Int) {
        if (closed) return
        prefetchFromBlock = startBlock
        prefetchToBlock = startBlock + count - 1L
        if (prefetchJob?.isActive == true) return
        prefetchJob = prefetchScope.launch {
            var idx = prefetchFromBlock
            while (!closed && idx <= prefetchToBlock) {
                val startOffset = idx * blockSize.toLong()
                if (size > 0L && startOffset >= size) break
                val alreadyCached = cacheMutex.withLock { blockCache.containsKey(idx) }
                if (!alreadyCached && !closed) {
                    withContext(NonCancellable) {
                        sessionMutex.withLock {
                            if (!closed) {
                                runCatching { fetchAndCacheBlockLocked(idx) }
                            }
                        }
                    }
                }
                val latestFrom = prefetchFromBlock
                idx = if (latestFrom > idx + 1L) latestFrom else idx + 1L
            }
        }
    }

    fun markClosed() {
        closed = true
        prefetchScope.cancel()
    }

    suspend fun closeSuspend() {
        closed = true
        val job = prefetchJob
        prefetchJob = null
        prefetchScope.cancel()
        runCatching { job?.join() }
        withContext(NonCancellable) {
            sessionMutex.withLock {
                cacheMutex.withLock {
                    blockCache.clear()
                }
                runCatching { smbFile.closeSuspend() }
            }
        }
    }
}

/**
 * マルチプラットフォームで動作するローカルループバック (`127.0.0.1`) HTTP 1.1 Range ストリーミングサーバー。
 *
 * [SmbRandomAccessStream] をバックエンドとして `206 Partial Content` / `Accept-Ranges: bytes` を提供し、
 * 各 OS の外部メディアプレイヤーや内蔵プレイヤーから全量ダウンロードなしでオンデマンド再生できるようにする。
 */
class SmbHttpRangeServer private constructor(
    private val selectorManager: SelectorManager,
    private val serverSocket: ServerSocket,
    val stream: SmbRandomAccessStream,
    fileName: String,
    val port: Int,
) {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val mimeType = guessMimeType(fileName)
    val streamUrl: String = "http://127.0.0.1:$port/${encodeUrlPathSegment(fileName.ifEmpty { "stream.bin" })}"

    @kotlin.concurrent.Volatile
    private var closed = false

    private fun startAcceptLoop() {
        scope.launch {
            while (!closed) {
                val client = try {
                    serverSocket.accept()
                } catch (e: Throwable) {
                    break
                }
                launch {
                    handleClient(client)
                }
            }
        }
    }

    private suspend fun handleClient(socket: Socket) {
        try {
            val readChannel = socket.openReadChannel()
            val writeChannel = socket.openWriteChannel(autoFlush = false)

            val requestLine = readChannel.readUTF8Line() ?: return
            val isHead = requestLine.startsWith("HEAD ", ignoreCase = true)

            var rangeHeader: String? = null
            while (true) {
                val line = readChannel.readUTF8Line() ?: break
                if (line.isEmpty()) break
                if (line.startsWith("Range:", ignoreCase = true)) {
                    rangeHeader = line.substringAfter(':').trim()
                }
            }

            val totalSize = stream.size
            var startOffset = 0L
            var endOffset = if (totalSize > 0L) totalSize - 1L else Long.MAX_VALUE
            var isPartial = false

            if (rangeHeader != null && rangeHeader.startsWith("bytes=", ignoreCase = true)) {
                val spec = rangeHeader.substringAfter('=').substringBefore(',').trim()
                val dashIdx = spec.indexOf('-')
                if (dashIdx >= 0) {
                    val startPart = spec.substring(0, dashIdx).trim()
                    val endPart = spec.substring(dashIdx + 1).trim()
                    if (startPart.isNotEmpty()) {
                        startOffset = startPart.toLongOrNull() ?: 0L
                        if (endPart.isNotEmpty()) {
                            endOffset = endPart.toLongOrNull() ?: endOffset
                        }
                        isPartial = true
                    } else if (endPart.isNotEmpty() && totalSize > 0L) {
                        val suffixLen = endPart.toLongOrNull() ?: 0L
                        startOffset = (totalSize - suffixLen).coerceAtLeast(0L)
                        endOffset = totalSize - 1L
                        isPartial = true
                    }
                }
            }

            if (totalSize > 0L) {
                if (startOffset >= totalSize) {
                    val err = "HTTP/1.1 416 Range Not Satisfiable\r\nContent-Range: bytes */$totalSize\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    val errBytes = err.encodeToByteArray()
                    writeChannel.writeFully(errBytes, 0, errBytes.size)
                    writeChannel.flush()
                    return
                }
                endOffset = endOffset.coerceAtMost(totalSize - 1L)
            }

            val contentLength = if (totalSize > 0L) (endOffset - startOffset + 1L) else -1L
            val statusLine = if (isPartial) "HTTP/1.1 206 Partial Content" else "HTTP/1.1 200 OK"
            val headers = buildString {
                append(statusLine).append("\r\n")
                append("Content-Type: ").append(mimeType).append("\r\n")
                append("Accept-Ranges: bytes\r\n")
                if (isPartial && totalSize > 0L) {
                    append("Content-Range: bytes ").append(startOffset).append('-').append(endOffset).append('/').append(totalSize).append("\r\n")
                }
                if (contentLength >= 0L) {
                    append("Content-Length: ").append(contentLength).append("\r\n")
                }
                append("Connection: close\r\n\r\n")
            }

            val headerBytes = headers.encodeToByteArray()
            writeChannel.writeFully(headerBytes, 0, headerBytes.size)
            writeChannel.flush()

            if (isHead) return

            val buffer = ByteArray(65536)
            var currentPos = startOffset
            while (!closed && !stream.isClosed && (totalSize <= 0L || currentPos <= endOffset)) {
                val toRead = if (totalSize > 0L) {
                    minOf(buffer.size.toLong(), endOffset - currentPos + 1L).toInt()
                } else {
                    buffer.size
                }
                if (toRead <= 0) break

                val readBytes = stream.readAt(currentPos, buffer, 0, toRead)
                if (readBytes <= 0) break

                writeChannel.writeFully(buffer, 0, readBytes)
                writeChannel.flush()
                currentPos += readBytes
            }
        } catch (_: Throwable) {
            // プレイヤー側がシーク等でコネクションを閉じた場合は正常終了
        } finally {
            runCatching { socket.close() }
        }
    }

    suspend fun closeSuspend() {
        if (closed) return
        closed = true
        scope.cancel()
        runCatching { serverSocket.close() }
        runCatching { selectorManager.close() }
        stream.closeSuspend()
    }

    companion object {
        suspend fun start(stream: SmbRandomAccessStream, fileName: String): SmbHttpRangeServer {
            val selectorManager = SelectorManager(Dispatchers.IO)
            val serverSocket = aSocket(selectorManager).tcp().bind("127.0.0.1", 0)
            val boundPort = (serverSocket.localAddress as? InetSocketAddress)?.port ?: 0
            return SmbHttpRangeServer(
                selectorManager = selectorManager,
                serverSocket = serverSocket,
                stream = stream,
                fileName = fileName,
                port = boundPort,
            ).also { it.startAcceptLoop() }
        }

        private fun encodeUrlPathSegment(name: String): String {
            val bytes = name.encodeToByteArray()
            return buildString(bytes.size * 2) {
                for (b in bytes) {
                    val c = b.toInt() and 0xFF
                    val isUnreserved = (c in 'a'.code..'z'.code) ||
                        (c in 'A'.code..'Z'.code) ||
                        (c in '0'.code..'9'.code) ||
                        c == '-'.code || c == '_'.code || c == '.'.code || c == '~'.code
                    if (isUnreserved) {
                        append(c.toChar())
                    } else {
                        append('%')
                        append(c.toString(16).uppercase().padStart(2, '0'))
                    }
                }
            }
        }

        private fun guessMimeType(fileName: String): String {
            val ext = fileName.substringAfterLast('.', "").lowercase()
            return when (ext) {
                "avi" -> "video/x-msvideo"
                "mp4", "m4v" -> "video/mp4"
                "mkv" -> "video/x-matroska"
                "webm" -> "video/webm"
                "mov" -> "video/quicktime"
                "ts" -> "video/mp2t"
                "jpg", "jpeg" -> "image/jpeg"
                "png" -> "image/png"
                "webp" -> "image/webp"
                "gif" -> "image/gif"
                "bmp" -> "image/bmp"
                "txt", "md", "log", "json", "xml", "csv" -> "text/plain; charset=utf-8"
                else -> "application/octet-stream"
            }
        }
    }
}

