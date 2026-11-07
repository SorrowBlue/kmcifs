package com.sorrowblue.kmcifs.client

import com.sorrowblue.kmcifs.client.auth.NtlmAuthenticator
import com.sorrowblue.kmcifs.client.auth.SmbCredentials
import com.sorrowblue.kmcifs.client.crypto.Sha512
import com.sorrowblue.kmcifs.client.crypto.Smb3Kdf
import com.sorrowblue.kmcifs.client.protocol.ByteUtils.readULongLE
import com.sorrowblue.kmcifs.client.protocol.ByteUtils.readUShortLE
import com.sorrowblue.kmcifs.client.protocol.DceRpcSrvSvc
import com.sorrowblue.kmcifs.client.protocol.KtorTcpSmbTransport
import com.sorrowblue.kmcifs.client.protocol.NtStatus
import com.sorrowblue.kmcifs.client.protocol.SmbCipherId
import com.sorrowblue.kmcifs.client.protocol.SmbCommand
import com.sorrowblue.kmcifs.client.protocol.SmbDialect
import com.sorrowblue.kmcifs.client.protocol.SmbException
import com.sorrowblue.kmcifs.client.protocol.SmbHeader
import com.sorrowblue.kmcifs.client.protocol.SmbMessages
import com.sorrowblue.kmcifs.client.protocol.SmbPacketTransport
import com.sorrowblue.kmcifs.client.protocol.SmbShareInfo
import com.sorrowblue.kmcifs.client.protocol.SmbTransformHeader
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout

/**
 * SMB2 / SMB3 クライアント接続セッションを管理するクラス。
 *
 * [SmbClient.connect] でサーバーに接続し、共有フォルダ一覧の取得 ([listShares])、
 * 共有フォルダへの接続 ([connectShare])、または `IPC$` 名前付きパイプへの接続 ([connectIpcShare]) を行う。
 */
class SmbClient internal constructor(
    val host: String,
    val port: Int,
    val config: SmbConfig,
    private val transport: SmbPacketTransport,
) : AutoCloseable {

    private val mutex = Mutex()
    private var nextMessageId: ULong = 0uL

    @kotlin.concurrent.Volatile
    private var closed = false

    val isClosed: Boolean
        get() = closed

    lateinit var negotiatedDialect: SmbDialect
        private set

    var negotiatedCipher: SmbCipherId? = null
        private set

    var sessionId: ULong = 0uL
        private set

    var maxReadSize: Int = 65536
        private set

    var maxWriteSize: Int = 65536
        private set

    var maxTransactSize: Int = 65536
        private set

    var isSessionEncrypted: Boolean = false
        private set

    private var serverSigningRequired: Boolean = false
    private var isGuestOrAnonymousSession: Boolean = false

    private var signingKey: ByteArray? = null
    private var encryptionKey: ByteArray? = null
    private var decryptionKey: ByteArray? = null

    internal suspend fun initializeSession(credentials: SmbCredentials) {
        // 1. NEGOTIATE
        var preauthHash = ByteArray(64)

        val negReq = SmbMessages.buildNegotiateRequest(
            messageId = allocateMessageId(1u),
            dialects = config.dialects,
            ciphers = config.ciphers,
        )
        if (config.dialects.contains(SmbDialect.SMB_3_1_1)) {
            preauthHash = updatePreauthHash(preauthHash, negReq)
        }

        val negRespRaw = sendAndReceiveRaw(negReq)
        val negResp = SmbMessages.parseNegotiateResponse(negRespRaw)

        negotiatedDialect = negResp.dialect
        negotiatedCipher = negResp.negotiatedCipher
        serverSigningRequired = negResp.signingRequired
        maxReadSize = negResp.maxReadSize.toInt().coerceIn(4096, 8 * 1024 * 1024)
        maxWriteSize = negResp.maxWriteSize.toInt().coerceIn(4096, 8 * 1024 * 1024)
        maxTransactSize = negResp.maxTransactSize.toInt().coerceIn(4096, 8 * 1024 * 1024)

        if (negotiatedDialect == SmbDialect.SMB_3_1_1) {
            preauthHash = updatePreauthHash(preauthHash, negRespRaw)
        }

        // 2. SESSION_SETUP Round 1 (NTLMSSP Type 1)
        val type1 = NtlmAuthenticator.createType1Message()
        val spnegoInit = NtlmAuthenticator.wrapType1InSpnego(type1)
        val secMode = if (serverSigningRequired || config.alwaysSign) {
            (SmbMessages.SMB2_NEGOTIATE_SIGNING_ENABLED.toInt() or SmbMessages.SMB2_NEGOTIATE_SIGNING_REQUIRED.toInt()).toUShort()
        } else {
            SmbMessages.SMB2_NEGOTIATE_SIGNING_ENABLED
        }

        val setupReq1 = SmbMessages.buildSessionSetupRequest(
            messageId = allocateMessageId(1u),
            sessionId = 0uL,
            securityBuffer = spnegoInit,
            securityMode = secMode,
        )
        if (negotiatedDialect == SmbDialect.SMB_3_1_1) {
            preauthHash = updatePreauthHash(preauthHash, setupReq1)
        }

        val setupResp1Raw = sendAndReceiveRaw(setupReq1)
        val setupResp1 = SmbMessages.parseSessionSetupResponse(setupResp1Raw)
        sessionId = setupResp1.sessionId

        if (setupResp1.status == NtStatus.STATUS_SUCCESS) {
            // Anonymous / immediate login succeeded in 1 step
            isGuestOrAnonymousSession = true
            return
        }

        if (negotiatedDialect == SmbDialect.SMB_3_1_1) {
            preauthHash = updatePreauthHash(preauthHash, setupResp1Raw)
        }

        // 3. SESSION_SETUP Round 2 (NTLMSSP Type 2 -> Type 3)
        val challengeInfo = NtlmAuthenticator.parseType2Challenge(setupResp1.securityBuffer)
        val authResult = NtlmAuthenticator.createType3Authenticate(
            credentials = credentials,
            type1Message = type1,
            challenge = challengeInfo,
        )

        val setupReq2 = SmbMessages.buildSessionSetupRequest(
            messageId = allocateMessageId(1u),
            sessionId = sessionId,
            securityBuffer = authResult.spnegoTokenResp,
            securityMode = secMode,
        )
        if (negotiatedDialect == SmbDialect.SMB_3_1_1) {
            preauthHash = updatePreauthHash(preauthHash, setupReq2)
        }

        // Derive SMB2 / SMB3 keys before receiving Round 2 response (so response signature/encryption can be verified)
        if (!credentials.isAnonymous) {
            if (negotiatedDialect.isSmb3) {
                val derived = Smb3Kdf.deriveKeys(
                    dialect = negotiatedDialect,
                    sessionKey = authResult.exportedSessionKey,
                    preauthIntegrityHash = if (negotiatedDialect == SmbDialect.SMB_3_1_1) preauthHash else null,
                )
                signingKey = derived.signingKey
                encryptionKey = derived.encryptionKey
                decryptionKey = derived.decryptionKey
            } else {
                signingKey = authResult.exportedSessionKey.copyOf(16)
            }
        }

        val setupResp2Raw = sendAndReceiveRaw(setupReq2)
        val setupResp2 = SmbMessages.parseSessionSetupResponse(setupResp2Raw)
        if (setupResp2.status != NtStatus.STATUS_SUCCESS) {
            throw SmbException(
                setupResp2.status,
                "Authentication did not complete with STATUS_SUCCESS (${NtStatus.nameOf(setupResp2.status)})"
            )
        }

        isGuestOrAnonymousSession = credentials.isAnonymous || setupResp2.isGuestOrNull
        if (isGuestOrAnonymousSession) {
            signingKey = null
            encryptionKey = null
            decryptionKey = null
        }

        // Determine session-level encryption state
        val cipherAvailable = negotiatedDialect.isSmb3 &&
            negotiatedCipher != null &&
            encryptionKey != null &&
            decryptionKey != null

        when (config.encryptionPolicy) {
            SmbEncryptionPolicy.REQUIRED -> {
                if (!cipherAvailable) {
                    throw SmbException(
                        NtStatus.STATUS_NOT_SUPPORTED,
                        "SMB3 encryption is required by SmbConfig, but server ($negotiatedDialect) or credentials do not support encryption"
                    )
                }
                isSessionEncrypted = true
            }
            SmbEncryptionPolicy.NEGOTIATE -> {
                isSessionEncrypted = cipherAvailable && (setupResp2.encryptData || config.preferEncryption)
            }
            SmbEncryptionPolicy.DISABLED -> {
                isSessionEncrypted = false
            }
        }
    }

    /**
     * `IPC$` 共有の `srvsvc` 名前付きパイプ経由で、サーバー上の共有フォルダ一覧 (`NetrShareEnum`) を取得する。
     *
     * @param includeHidden `IPC$` や `ADMIN$`、`C$` などの管理・隠し共有も含める場合は `true`
     */
    suspend fun listShares(includeHidden: Boolean = false): List<SmbShareInfo> {
        val ipc = connectIpcShare()
        try {
            val pipe = ipc.openPipe("srvsvc")
            try {
                val bindPdu = DceRpcSrvSvc.buildBindPdu(callId = 1u)
                val bindAck = pipe.transceive(bindPdu)
                DceRpcSrvSvc.verifyBindAck(bindAck)

                val enumReq = DceRpcSrvSvc.buildNetrShareEnumRequest(host, callId = 2u)
                val firstResp = pipe.transceive(enumReq)
                val fullStub = collectRpcResponseStub(pipe, firstResp)
                val allShares = DceRpcSrvSvc.parseNetrShareEnumResponse(fullStub)
                return if (includeHidden) {
                    allShares
                } else {
                    allShares.filterNot { it.isSpecialOrHidden }
                }
            } finally {
                pipe.closeSuspend()
            }
        } finally {
            ipc.closeSuspend()
        }
    }

    private suspend fun collectRpcResponseStub(pipe: SmbNamedPipe, firstPdu: ByteArray): ByteArray {
        val chunks = mutableListOf<ByteArray>()
        var currentPdu = firstPdu
        while (true) {
            require(currentPdu.size >= 24 && currentPdu[0].toInt() == 5 && currentPdu[2].toInt() == 2) {
                "Unexpected DCE/RPC response PDU header"
            }
            val pfcFlags = currentPdu[3].toInt() and 0xFF
            val fragLen = currentPdu.readUShortLE(8).toInt().coerceAtMost(currentPdu.size)
            val authLen = currentPdu.readUShortLE(10).toInt()
            val stubEnd = (fragLen - authLen).coerceAtLeast(24)
            chunks.add(currentPdu.copyOfRange(24, stubEnd))

            // PFC_LAST_FRAG = 0x02
            if ((pfcFlags and 0x02) != 0) break
            currentPdu = pipe.read(65536)
            if (currentPdu.isEmpty()) break
        }
        val totalSize = chunks.sumOf { it.size }
        val combined = ByteArray(totalSize)
        var pos = 0
        for (chunk in chunks) {
            chunk.copyInto(combined, pos)
            pos += chunk.size
        }
        return combined
    }

    /**
     * 指定した名前の共有フォルダに接続する。
     */
    suspend fun connectShare(shareName: String): SmbShare {
        val cleanName = shareName.trim('/', '\\')
        val uncPath = "\\\\$host\\$cleanName"
        val req = SmbMessages.buildTreeConnectRequest(
            messageId = allocateMessageId(1u),
            sessionId = sessionId,
            uncPath = uncPath,
        )
        val respRaw = executeCommand(req, forceEncrypt = false)
        val treeResp = SmbMessages.parseTreeConnectResponse(respRaw)

        val encryptShare = isSessionEncrypted ||
            (config.encryptionPolicy != SmbEncryptionPolicy.DISABLED &&
                treeResp.encryptData &&
                negotiatedDialect.isSmb3 &&
                negotiatedCipher != null &&
                encryptionKey != null)

        return SmbShare(
            client = this,
            shareName = cleanName,
            treeId = treeResp.treeId,
            encryptShare = encryptShare,
        )
    }

    /**
     * `IPC$` 共有に接続し、名前付きパイプ操作用の [SmbPipeShare] を返す。
     */
    suspend fun connectIpcShare(): SmbPipeShare {
        val uncPath = "\\\\$host\\IPC$"
        val req = SmbMessages.buildTreeConnectRequest(
            messageId = allocateMessageId(1u),
            sessionId = sessionId,
            uncPath = uncPath,
        )
        val respRaw = executeCommand(req, forceEncrypt = false)
        val treeResp = SmbMessages.parseTreeConnectResponse(respRaw)

        val encryptShare = isSessionEncrypted ||
            (config.encryptionPolicy != SmbEncryptionPolicy.DISABLED &&
                treeResp.encryptData &&
                negotiatedDialect.isSmb3 &&
                negotiatedCipher != null &&
                encryptionKey != null)

        return SmbPipeShare(
            client = this,
            treeId = treeResp.treeId,
            encryptShare = encryptShare,
        )
    }

    internal fun allocateMessageId(credits: UShort = 1u): ULong {
        val id = nextMessageId
        nextMessageId += maxOf(1u, credits.toUInt()).toULong()
        return id
    }

    /**
     * セッション確立後の SMB コマンドパケットを送受信する（署名または SMB3 暗号化を自動適用し、STATUS_PENDING の非同期中間応答も処理する）。
     *
     * ソケット上のパケット送受信中に呼び出し元コルーチンがキャンセル（ExoPlayer のシークや画面終了時の割り込み等）されても、
     * 未読レスポンスが TCP バッファに残留して後続リクエストと混線しないよう [NonCancellable] でトランザクションを完結させる。
     */
    internal suspend fun executeCommand(plainRequest: ByteArray, forceEncrypt: Boolean = false): ByteArray {
        val expectedMessageId = plainRequest.readULongLE(24)
        return mutex.withLock {
            withContext(NonCancellable) {
                if (closed) {
                    throw SmbException(NtStatus.STATUS_USER_SESSION_DELETED, "SMB client is already closed")
                }
                try {
                    withTimeout(config.requestTimeoutMillis) {
                        val shouldEncrypt = (isSessionEncrypted || forceEncrypt) &&
                            negotiatedDialect.isSmb3 &&
                            negotiatedCipher != null &&
                            encryptionKey != null

                        val wirePacket = if (shouldEncrypt) {
                            SmbTransformHeader.encryptPacket(
                                plainSmbPacket = plainRequest,
                                sessionId = sessionId,
                                cipherId = negotiatedCipher!!,
                                encryptionKey = encryptionKey!!,
                            )
                        } else {
                            val key = signingKey
                            if (key != null && !isGuestOrAnonymousSession && (serverSigningRequired || config.alwaysSign || negotiatedDialect.isSmb3)) {
                                SmbHeader.signPacket(plainRequest, negotiatedDialect, key)
                            }
                            plainRequest
                        }

                        transport.sendPacket(wirePacket)
                        receiveAndUnwrapResponse(expectedMessageId)
                    }
                } catch (e: SmbException) {
                    throw e
                } catch (e: Throwable) {
                    closed = true
                    runCatching { transport.close() }
                    throw e
                }
            }
        }
    }

    private suspend fun sendAndReceiveRaw(rawRequest: ByteArray): ByteArray {
        val expectedMessageId = rawRequest.readULongLE(24)
        return mutex.withLock {
            withContext(NonCancellable) {
                if (closed) {
                    throw SmbException(NtStatus.STATUS_USER_SESSION_DELETED, "SMB client is already closed")
                }
                try {
                    withTimeout(config.requestTimeoutMillis) {
                        transport.sendPacket(rawRequest)
                        receiveAndUnwrapResponse(expectedMessageId)
                    }
                } catch (e: SmbException) {
                    throw e
                } catch (e: Throwable) {
                    closed = true
                    runCatching { transport.close() }
                    throw e
                }
            }
        }
    }

    private suspend fun receiveAndUnwrapResponse(expectedMessageId: ULong): ByteArray {
        while (true) {
            val rawIncoming = transport.receivePacket()
            val wasEncrypted = SmbTransformHeader.isTransformPacket(rawIncoming)
            val plainResponse = if (wasEncrypted) {
                val cipher = negotiatedCipher
                    ?: throw IllegalStateException("Received encrypted SMB3 Transform packet before cipher was negotiated")
                val decKey = decryptionKey
                    ?: throw IllegalStateException("Received encrypted SMB3 Transform packet without decryption key")
                SmbTransformHeader.decryptPacket(rawIncoming, cipher, decKey)
            } else {
                rawIncoming
            }

            val header = SmbHeader.decode(plainResponse)
            // Skip interim STATUS_PENDING async responses and wait for the final response
            if (header.status == NtStatus.STATUS_PENDING && header.isAsync) {
                continue
            }
            // Skip any stale response packet with an older MessageId
            if (header.messageId < expectedMessageId) {
                continue
            }

            if (!wasEncrypted && config.verifyServerSignatures && header.isSigned && !isGuestOrAnonymousSession) {
                val key = signingKey
                if (key != null && header.command != SmbCommand.SESSION_SETUP) {
                    val valid = SmbHeader.verifyPacketSignature(plainResponse, negotiatedDialect, key)
                    if (!valid) {
                        throw SmbException(
                            NtStatus.STATUS_ACCESS_DENIED,
                            "Server SMB packet signature verification failed for ${header.command}"
                        )
                    }
                }
            }

            return plainResponse
        }
    }

    private fun updatePreauthHash(currentHash: ByteArray, packet: ByteArray): ByteArray {
        val combined = ByteArray(currentHash.size + packet.size)
        currentHash.copyInto(combined, 0)
        packet.copyInto(combined, currentHash.size)
        return Sha512.digest(combined)
    }

    /**
     * `LOGOFF` リクエストを送信してセッションとソケットを正常終了する。
     */
    suspend fun closeSuspend() {
        if (closed) return
        try {
            if (sessionId != 0uL) {
                runCatching {
                    val req = SmbMessages.buildLogoffRequest(
                        messageId = allocateMessageId(1u),
                        sessionId = sessionId,
                    )
                    executeCommand(req)
                }
            }
        } finally {
            closed = true
            transport.close()
        }
    }

    override fun close() {
        closed = true
        transport.close()
    }

    companion object {
        /**
         * 指定された SMB サーバーへ TCP 接続し、ネゴシエーションと NTLMv2 認証を完了した [SmbClient] を返す。
         */
        suspend fun connect(
            host: String,
            port: Int = 445,
            credentials: SmbCredentials = SmbCredentials.Anonymous,
            config: SmbConfig = SmbConfig(),
        ): SmbClient {
            val transport = KtorTcpSmbTransport.connect(host, port, config.connectTimeoutMillis)
            val client = SmbClient(host, port, config, transport)
            try {
                client.initializeSession(credentials)
                return client
            } catch (e: Throwable) {
                client.close()
                throw e
            }
        }
    }
}
