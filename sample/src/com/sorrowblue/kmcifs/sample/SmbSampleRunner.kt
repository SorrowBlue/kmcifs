package com.sorrowblue.kmcifs.sample

import com.sorrowblue.kmcifs.client.SmbClient
import com.sorrowblue.kmcifs.client.SmbConfig
import com.sorrowblue.kmcifs.client.SmbEncryptionPolicy
import com.sorrowblue.kmcifs.client.auth.SmbCredentials
import com.sorrowblue.kmcifs.client.protocol.SmbCipherId
import com.sorrowblue.kmcifs.client.protocol.SmbDialect
import com.sorrowblue.kmcifs.client.protocol.SmbDirectoryEntry
import com.sorrowblue.kmcifs.client.protocol.SmbShareInfo

/**
 * Connection parameters shared across the sample applications.
 */
data class SmbSampleRequest(
    val host: String,
    val port: Int = 445,
    val username: String = "",
    val password: String = "",
    val domain: String = "",
    val shareName: String = "",
    val directoryPath: String = "",
    val readFilePath: String = "",
    val encryptionPolicy: SmbEncryptionPolicy = SmbEncryptionPolicy.NEGOTIATE,
)

/**
 * Execution report produced by [SmbSampleRunner].
 */
data class SmbSampleReport(
    val platformName: String,
    val host: String,
    val port: Int,
    val negotiatedDialect: SmbDialect,
    val negotiatedCipher: SmbCipherId?,
    val isEncrypted: Boolean,
    val shares: List<SmbShareInfo>,
    val targetShare: String?,
    val directoryPath: String,
    val directoryEntries: List<SmbDirectoryEntry>,
    val readFilePath: String?,
    val fileContentPreview: String?,
) {
    fun formatSummary(): String = buildString {
        appendLine("=== kmcifs Sample Report ($platformName) ===")
        appendLine("Server            : $host:$port")
        appendLine("Negotiated Dialect: $negotiatedDialect")
        appendLine("Negotiated Cipher : ${negotiatedCipher ?: "None"}")
        appendLine("Session Encrypted : $isEncrypted")
        appendLine()
        appendLine("--- Shares (${shares.size}) ---")
        if (shares.isEmpty()) {
            appendLine("  (No shares returned or IPC$ enumeration skipped)")
        } else {
            for (share in shares) {
                appendLine("  - ${share.name} [${share.type}] ${share.comment}")
            }
        }

        if (targetShare != null) {
            appendLine()
            appendLine("--- Directory Listing: //$host/$targetShare/${directoryPath.trimStart('/', '\\')} (${directoryEntries.size} entries) ---")
            for (entry in directoryEntries) {
                val kind = if (entry.isDirectory) "DIR " else "FILE"
                appendLine("  [$kind] ${entry.name} (${entry.size} bytes)")
            }
        }

        if (readFilePath != null && fileContentPreview != null) {
            appendLine()
            appendLine("--- File Content Preview ($readFilePath) ---")
            appendLine(fileContentPreview)
        }
    }
}

/**
 * Shared SMB operation runner invoked across all platform sample applications.
 */
object SmbSampleRunner {

    /**
     * Connects to the specified SMB server and performs share enumeration, directory listing, and file preview reading.
     */
    suspend fun execute(platformName: String, request: SmbSampleRequest): SmbSampleReport {
        val credentials = SmbCredentials(
            username = request.username,
            password = request.password,
            domain = request.domain,
        )
        val config = SmbConfig(
            encryptionPolicy = request.encryptionPolicy,
            preferEncryption = true,
        )

        val client = SmbClient.connect(
            host = request.host,
            port = request.port,
            credentials = credentials,
            config = config,
        )

        try {
            val shares = runCatching { client.listShares(includeHidden = false) }
                .getOrElse { emptyList() }

            var selectedShareName: String? = null
            var entries: List<SmbDirectoryEntry> = emptyList()
            var filePreview: String? = null
            var previewedFilePath: String? = null

            val candidateShares = if (request.shareName.isNotBlank()) {
                listOf(request.shareName)
            } else {
                shares.map { it.name }
            }

            for (candidate in candidateShares) {
                val share = if (request.shareName.isNotBlank()) {
                    client.connectShare(candidate)
                } else {
                    runCatching { client.connectShare(candidate) }.getOrNull() ?: continue
                }
                try {
                    val dirEntries = if (request.shareName.isNotBlank()) {
                        share.listDirectory(request.directoryPath)
                    } else {
                        runCatching { share.listDirectory(request.directoryPath) }.getOrNull() ?: continue
                    }
                    selectedShareName = candidate
                    entries = dirEntries
                    if (request.readFilePath.isNotBlank()) {
                        val file = share.openFile(request.readFilePath)
                        try {
                            val bytes = file.read(offset = 0L, length = 4096)
                            filePreview = bytes.decodeToString()
                            previewedFilePath = request.readFilePath
                        } finally {
                            file.closeSuspend()
                        }
                    } else {
                        val firstSmallFile = entries.firstOrNull {
                            !it.isDirectory && it.size in 1..4096 && it.name.endsWith(".txt", ignoreCase = true)
                        }
                        if (firstSmallFile != null) {
                            val subPath = if (request.directoryPath.isBlank()) {
                                firstSmallFile.name
                            } else {
                                "${request.directoryPath.trimEnd('/', '\\')}/${firstSmallFile.name}"
                            }
                            runCatching {
                                filePreview = share.readText(subPath)
                                previewedFilePath = subPath
                            }
                        }
                    }
                    break
                } finally {
                    share.closeSuspend()
                }
            }

            return SmbSampleReport(
                platformName = platformName,
                host = request.host,
                port = request.port,
                negotiatedDialect = client.negotiatedDialect,
                negotiatedCipher = client.negotiatedCipher,
                isEncrypted = client.isSessionEncrypted,
                shares = shares,
                targetShare = selectedShareName,
                directoryPath = request.directoryPath,
                directoryEntries = entries,
                readFilePath = previewedFilePath,
                fileContentPreview = filePreview,
            )
        } finally {
            client.closeSuspend()
        }
    }

    /**
     * Common CLI entry-point helper for JVM, Windows, Linux, and macOS sample executables.
     */
    suspend fun runCli(platformName: String, args: Array<String>) {
        val parsed = parseCliArgs(args)
        if (parsed == null) {
            printUsage(platformName)
            return
        }
        println("Connecting to SMB server ${parsed.host}:${parsed.port} from $platformName...")
        val report = execute(platformName, parsed)
        println(report.formatSummary())
    }

    fun parseCliArgs(args: Array<String>): SmbSampleRequest? {
        if (args.isEmpty() || args.contains("--help") || args.contains("-h")) {
            return null
        }
        var host = ""
        var port = 445
        var user = ""
        var pass = ""
        var domain = ""
        var share = ""
        var dir = ""
        var file = ""

        var i = 0
        while (i < args.size) {
            when (args[i]) {
                "--host", "-H" -> host = args.getOrNull(++i).orEmpty()
                "--port", "-P" -> port = args.getOrNull(++i)?.toIntOrNull() ?: 445
                "--user", "-u" -> user = args.getOrNull(++i).orEmpty()
                "--pass", "-p" -> pass = args.getOrNull(++i).orEmpty()
                "--domain", "-d" -> domain = args.getOrNull(++i).orEmpty()
                "--share", "-s" -> share = args.getOrNull(++i).orEmpty()
                "--dir" -> dir = args.getOrNull(++i).orEmpty()
                "--file", "-f" -> file = args.getOrNull(++i).orEmpty()
            }
            i++
        }
        if (host.isBlank()) return null
        return SmbSampleRequest(
            host = host,
            port = port,
            username = user,
            password = pass,
            domain = domain,
            shareName = share,
            directoryPath = dir,
            readFilePath = file,
        )
    }

    fun printUsage(platformName: String) {
        println("kmcifs Sample Application ($platformName)")
        println("Usage: --host <server-ip> [--port 445] [--user <username>] [--pass <password>] [--domain <domain>] [--share <shareName>] [--dir <path>] [--file <filePath>]")
    }
}
