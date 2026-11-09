package com.sorrowblue.kmcifs.client

import com.sorrowblue.kmcifs.client.auth.NtlmAuthenticator
import com.sorrowblue.kmcifs.client.auth.SmbCredentials
import com.sorrowblue.kmcifs.client.crypto.Sha512
import com.sorrowblue.kmcifs.client.crypto.Smb3Kdf
import com.sorrowblue.kmcifs.client.protocol.ByteUtils.readULongLE
import com.sorrowblue.kmcifs.client.protocol.ByteUtils.readUShortLE
import com.sorrowblue.kmcifs.client.protocol.ByteUtils.writeULongLE
import com.sorrowblue.kmcifs.client.protocol.ByteUtils.writeUShortLE
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
 * Manages an SMB2/SMB3 client session over a single TCP connection.
 *
 * Connect to a server via [SmbClient.connect], enumerate shares with [listShares],
 * connect to a file share with [connectShare], or open the `IPC$` share for named pipe
 * communication with [connectIpcShare].
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
        if (negResp.dialect !in config.dialects) {
            throw SmbException(
                NtStatus.STATUS_INVALID_NETWORK_RESPONSE,
                "Server selected dialect ${negResp.dialect} which was not offered by client (${config.dialects})"
            )
        }
        if (negResp.dialect == SmbDialect.SMB_3_1_1 &&
            negResp.negotiatedCipher != null &&
            negResp.negotiatedCipher !in config.ciphers
        ) {
            throw SmbException(
                NtStatus.STATUS_INVALID_NETWORK_RESPONSE,
                "Server selected cipher ${negResp.negotiatedCipher} which was not offered by client (${config.ciphers})"
            )
        }

        negotiatedDialect = negResp.dialect
        negotiatedCipher = negResp.negotiatedCipher
        serverSigningRequired = negResp.signingRequired
        val maxAllowedMtu = if (negotiatedDialect == SmbDialect.SMB_2_0_2 ||
            (negResp.capabilities and SmbMessages.SMB2_GLOBAL_CAP_LARGE_MTU) == 0u
        ) {
            65536
        } else {
            8 * 1024 * 1024
        }
        maxReadSize = negResp.maxReadSize.coerceIn(4096u, maxAllowedMtu.toUInt()).toInt()
        maxWriteSize = negResp.maxWriteSize.coerceIn(4096u, maxAllowedMtu.toUInt()).toInt()
        maxTransactSize = negResp.maxTransactSize.coerceIn(4096u, maxAllowedMtu.toUInt()).toInt()

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
        if (negotiatedDialect == SmbDialect.SMB_2_0_2) {
            setupReq1.writeUShortLE(6, 0u)
        }
        if (negotiatedDialect == SmbDialect.SMB_3_1_1) {
            preauthHash = updatePreauthHash(preauthHash, setupReq1)
        }

        val setupResp1Raw = sendAndReceiveRaw(setupReq1)
        val setupResp1 = SmbMessages.parseSessionSetupResponse(setupResp1Raw)
        sessionId = setupResp1.sessionId

        if (setupResp1.status == NtStatus.STATUS_SUCCESS) {
            // Anonymous / immediate login succeeded in 1 step
            isGuestOrAnonymousSession = true
            if (config.encryptionPolicy == SmbEncryptionPolicy.REQUIRED) {
                throw SmbException(
                    NtStatus.STATUS_NOT_SUPPORTED,
                    "SMB3 encryption is required by SmbConfig, but anonymous/guest session does not support encryption"
                )
            }
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
        if (negotiatedDialect == SmbDialect.SMB_2_0_2) {
            setupReq2.writeUShortLE(6, 0u)
        }
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
        } else if (config.verifyServerSignatures) {
            // MS-SMB2 3.2.5.3.1: Final SESSION_SETUP response on a non-guest/non-anonymous session MUST be signed
            val setupResp2Header = SmbHeader.decode(setupResp2Raw)
            val key = signingKey
            if (key != null) {
                if (!setupResp2Header.isSigned || !SmbHeader.verifyPacketSignature(setupResp2Raw, negotiatedDialect, key)) {
                    throw SmbException(
                        NtStatus.STATUS_ACCESS_DENIED,
                        "Server SMB packet signature missing or verification failed for SESSION_SETUP"
                    )
                }
            }
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
     * Enumerates shared folders on the server via DCE/RPC `NetrShareEnum` over the `srvsvc` named pipe on `IPC$`.
     *
     * @param includeHidden Whether to include administrative and hidden shares such as `IPC$`, `ADMIN$`, and `C$`.
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
            while (currentPdu.size < 24) {
                val more = pipe.read(65536)
                if (more.isEmpty()) break
                currentPdu += more
            }
            require(currentPdu.size >= 24 && currentPdu[0].toInt() == 5 && currentPdu[2].toInt() == 2) {
                "Unexpected DCE/RPC response PDU header"
            }
            val declaredFragLen = currentPdu.readUShortLE(8).toInt()
            require(declaredFragLen >= 24) { "Invalid DCE/RPC fragment length: $declaredFragLen" }

            while (currentPdu.size < declaredFragLen) {
                val more = pipe.read(declaredFragLen - currentPdu.size)
                if (more.isEmpty()) break
                currentPdu += more
            }

            val pfcFlags = currentPdu[3].toInt() and 0xFF
            val actualFragLen = minOf(declaredFragLen, currentPdu.size)
            val authLen = currentPdu.readUShortLE(10).toInt()
            val stubEnd = (actualFragLen - authLen).coerceAtLeast(24)
            chunks.add(currentPdu.copyOfRange(24, stubEnd))

            // PFC_LAST_FRAG = 0x02
            if ((pfcFlags and 0x02) != 0) break
            currentPdu = if (currentPdu.size > actualFragLen) {
                currentPdu.copyOfRange(actualFragLen, currentPdu.size)
            } else {
                pipe.read(65536)
            }
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
     * Connects to the specified shared folder (`SMB2 TREE_CONNECT`) and returns an [SmbShare] handle.
     */
    suspend fun connectShare(shareName: String): SmbShare {
        val cleanName = shareName.trim('/', '\\')
        require(cleanName.isNotEmpty()) { "shareName must not be blank" }
        val uncPath = "\\\\$host\\$cleanName"
        val req = SmbMessages.buildTreeConnectRequest(
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
     * Connects to the `IPC$` share (`SMB2 TREE_CONNECT`) and returns an [SmbPipeShare] for named pipe operations.
     */
    suspend fun connectIpcShare(): SmbPipeShare {
        val uncPath = "\\\\$host\\IPC$"
        val req = SmbMessages.buildTreeConnectRequest(
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

    private fun allocateMessageId(credits: UShort = 1u): ULong {
        val id = nextMessageId
        nextMessageId += maxOf(1u, credits.toUInt()).toULong()
        return id
    }

    /**
     * Sends an SMB command packet after session establishment and receives its response,
     * automatically applying packet signing or SMB3 encryption and handling interim `STATUS_PENDING` responses.
     *
     * The send/receive transaction runs inside [NonCancellable] so that if the caller coroutine is cancelled
     * mid-flight (e.g., during a media player seek or screen dismissal), no unread response remains in the
     * TCP socket buffer to corrupt subsequent requests.
     */
    internal suspend fun executeCommand(plainRequest: ByteArray, forceEncrypt: Boolean = false): ByteArray {
        return mutex.withLock {
            withContext(NonCancellable) {
                if (closed) {
                    throw SmbException(NtStatus.STATUS_USER_SESSION_DELETED, "SMB client is already closed")
                }
                try {
                    withTimeout(config.requestTimeoutMillis) {
                        val credits = if (negotiatedDialect == SmbDialect.SMB_2_0_2) {
                            plainRequest.writeUShortLE(6, 0u) // MS-SMB2 2.2.1.2: CreditCharge MUST be 0 in SMB 2.0.2
                            1u
                        } else {
                            plainRequest.readUShortLE(6)
                        }
                        val expectedMessageId = allocateMessageId(credits)
                        plainRequest.writeULongLE(24, expectedMessageId)

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
                            val commandCode = plainRequest.readUShortLE(12)
                            val mustSign = serverSigningRequired ||
                                config.alwaysSign ||
                                (negotiatedDialect.isSmb3 && commandCode == SmbCommand.TREE_CONNECT.code)
                            if (key != null && !isGuestOrAnonymousSession && mustSign) {
                                SmbHeader.signPacket(plainRequest, negotiatedDialect, key)
                            }
                            plainRequest
                        }

                        transport.sendPacket(wirePacket)
                        receiveAndUnwrapResponse(expectedMessageId, requireEncrypted = shouldEncrypt)
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

    /**
     * Sends multiple related SMB2 requests (such as `[CREATE, CLOSE]`) in a single Compounded Related packet
     * and returns the corresponding response byte arrays in request order.
     */
    internal suspend fun executeCompoundCommands(
        plainRequests: List<ByteArray>,
        forceEncrypt: Boolean = false,
    ): List<ByteArray> {
        require(plainRequests.isNotEmpty()) { "plainRequests must not be empty" }
        if (plainRequests.size == 1) {
            return listOf(executeCommand(plainRequests[0], forceEncrypt))
        }
        return mutex.withLock {
            withContext(NonCancellable) {
                if (closed) {
                    throw SmbException(NtStatus.STATUS_USER_SESSION_DELETED, "SMB client is already closed")
                }
                try {
                    withTimeout(config.requestTimeoutMillis) {
                        val expectedMessageIds = plainRequests.map { req ->
                            val credits = if (negotiatedDialect == SmbDialect.SMB_2_0_2) {
                                req.writeUShortLE(6, 0u)
                                1u
                            } else {
                                req.readUShortLE(6)
                            }
                            val msgId = allocateMessageId(credits)
                            req.writeULongLE(24, msgId)
                            msgId
                        }

                        val shouldEncrypt = (isSessionEncrypted || forceEncrypt) &&
                            negotiatedDialect.isSmb3 &&
                            negotiatedCipher != null &&
                            encryptionKey != null

                        val key = signingKey
                        val signEach: ((ByteArray) -> Unit)? = if (!shouldEncrypt && key != null && !isGuestOrAnonymousSession) {
                            { slice ->
                                val commandCode = slice.readUShortLE(12)
                                val mustSign = serverSigningRequired ||
                                    config.alwaysSign ||
                                    (negotiatedDialect.isSmb3 && commandCode == SmbCommand.TREE_CONNECT.code)
                                if (mustSign) {
                                    SmbHeader.signPacket(slice, negotiatedDialect, key)
                                }
                            }
                        } else {
                            null
                        }

                        val compoundPlain = SmbMessages.buildCompoundRelatedPacket(plainRequests, signEach)
                        val wirePacket = if (shouldEncrypt) {
                            SmbTransformHeader.encryptPacket(
                                plainSmbPacket = compoundPlain,
                                sessionId = sessionId,
                                cipherId = negotiatedCipher!!,
                                encryptionKey = encryptionKey!!,
                            )
                        } else {
                            compoundPlain
                        }

                        transport.sendPacket(wirePacket)
                        receiveAndUnwrapCompoundResponses(expectedMessageIds, requireEncrypted = shouldEncrypt)
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

    private suspend fun receiveAndUnwrapResponse(
        expectedMessageId: ULong,
        requireEncrypted: Boolean = false,
    ): ByteArray {
        while (true) {
            val rawIncoming = transport.receivePacket()
            val wasEncrypted = SmbTransformHeader.isTransformPacket(rawIncoming)
            if (requireEncrypted && !wasEncrypted) {
                throw SmbException(
                    NtStatus.STATUS_ACCESS_DENIED,
                    "Expected encrypted SMB3 Transform response, but received unencrypted packet"
                )
            }
            val plainResponse = if (wasEncrypted) {
                val cipher = negotiatedCipher
                    ?: throw IllegalStateException("Received encrypted SMB3 Transform packet before cipher was negotiated")
                val decKey = decryptionKey
                    ?: throw IllegalStateException("Received encrypted SMB3 Transform packet without decryption key")
                SmbTransformHeader.decryptPacket(rawIncoming, cipher, decKey, sessionId)
            } else {
                rawIncoming
            }

            val header = SmbHeader.decode(plainResponse)
            // Skip unsolicited server notifications (e.g., OPLOCK_BREAK with MessageId == 0xFFFFFFFFFFFFFFFF)
            if (!header.isResponse || header.messageId == ULong.MAX_VALUE) {
                continue
            }
            // Skip interim STATUS_PENDING async responses and wait for the final response
            if (header.status == NtStatus.STATUS_PENDING && header.isAsync) {
                continue
            }
            // Skip any stale response packet with an older MessageId
            if (header.messageId < expectedMessageId) {
                continue
            }
            if (header.messageId != expectedMessageId) {
                throw SmbException(
                    NtStatus.STATUS_INVALID_NETWORK_RESPONSE,
                    "Unexpected SMB2 response MessageId: expected $expectedMessageId, got ${header.messageId}"
                )
            }

            verifyIncomingPacketSignatureIfRequired(plainResponse, header, wasEncrypted)

            return plainResponse
        }
    }

    private suspend fun receiveAndUnwrapCompoundResponses(
        expectedMessageIds: List<ULong>,
        requireEncrypted: Boolean = false,
    ): List<ByteArray> {
        val expectedSet = expectedMessageIds.toHashSet()
        val collected = HashMap<ULong, ByteArray>(expectedMessageIds.size)
        val minExpectedId = expectedMessageIds.min()

        while (collected.size < expectedSet.size) {
            val rawIncoming = transport.receivePacket()
            val wasEncrypted = SmbTransformHeader.isTransformPacket(rawIncoming)
            if (requireEncrypted && !wasEncrypted) {
                throw SmbException(
                    NtStatus.STATUS_ACCESS_DENIED,
                    "Expected encrypted SMB3 Transform response, but received unencrypted packet"
                )
            }
            val plainResponse = if (wasEncrypted) {
                val cipher = negotiatedCipher
                    ?: throw IllegalStateException("Received encrypted SMB3 Transform packet before cipher was negotiated")
                val decKey = decryptionKey
                    ?: throw IllegalStateException("Received encrypted SMB3 Transform packet without decryption key")
                SmbTransformHeader.decryptPacket(rawIncoming, cipher, decKey, sessionId)
            } else {
                rawIncoming
            }

            val parts = SmbMessages.splitCompoundPacket(plainResponse)
            for (part in parts) {
                val header = SmbHeader.decode(part)
                if (!header.isResponse || header.messageId == ULong.MAX_VALUE) {
                    continue
                }
                if (header.status == NtStatus.STATUS_PENDING && header.isAsync) {
                    continue
                }
                if (header.messageId < minExpectedId) {
                    continue
                }
                if (header.messageId !in expectedSet) {
                    throw SmbException(
                        NtStatus.STATUS_INVALID_NETWORK_RESPONSE,
                        "Unexpected SMB2 response MessageId in compound response: ${header.messageId}"
                    )
                }
                verifyIncomingPacketSignatureIfRequired(part, header, wasEncrypted)
                collected[header.messageId] = part

                // いずれかのコマンドがエラー終了し、サーバーが後続の関連レスポンスを省略した場合は残りを埋めて即座に終了する
                if (part === parts.last() &&
                    header.status != NtStatus.STATUS_SUCCESS &&
                    collected.size < expectedSet.size
                ) {
                    for (id in expectedMessageIds) {
                        if (id !in collected) {
                            collected[id] = part
                        }
                    }
                    break
                }
            }
        }

        return expectedMessageIds.map { collected.getValue(it) }
    }

    /**
     * Verifies signatures and detects signature stripping on unencrypted responses per `[MS-SMB2] 3.2.5.1.3`.
     */
    private fun verifyIncomingPacketSignatureIfRequired(packet: ByteArray, header: SmbHeader, wasEncrypted: Boolean) {
        if (wasEncrypted || !config.verifyServerSignatures || isGuestOrAnonymousSession) return
        if (header.command == SmbCommand.NEGOTIATE || header.command == SmbCommand.SESSION_SETUP) return
        val key = signingKey ?: return

        val mustBeSigned = serverSigningRequired ||
            config.alwaysSign ||
            (negotiatedDialect.isSmb3 && header.command == SmbCommand.TREE_CONNECT)

        if (!header.isSigned) {
            if (mustBeSigned) {
                throw SmbException(
                    NtStatus.STATUS_ACCESS_DENIED,
                    "Server SMB packet signature missing for ${header.command}"
                )
            }
            return
        }

        if (!SmbHeader.verifyPacketSignature(packet, negotiatedDialect, key)) {
            throw SmbException(
                NtStatus.STATUS_ACCESS_DENIED,
                "Server SMB packet signature verification failed for ${header.command}"
            )
        }
    }

    private fun updatePreauthHash(currentHash: ByteArray, packet: ByteArray): ByteArray {
        val combined = ByteArray(currentHash.size + packet.size)
        currentHash.copyInto(combined, 0)
        packet.copyInto(combined, currentHash.size)
        return Sha512.digest(combined)
    }

    /**
     * Sends an `SMB2 LOGOFF` request and closes the underlying TCP transport.
     */
    suspend fun closeSuspend() {
        if (closed) return
        try {
            if (sessionId != 0uL) {
                runCatching {
                    val req = SmbMessages.buildLogoffRequest(
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
         * Connects to the specified SMB server over TCP and completes dialect negotiation and NTLMv2 authentication.
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
