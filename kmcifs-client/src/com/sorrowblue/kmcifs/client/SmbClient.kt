package com.sorrowblue.kmcifs.client

import com.sorrowblue.kmcifs.client.auth.NtlmAuthenticator
import com.sorrowblue.kmcifs.client.auth.SmbCredentials
import com.sorrowblue.kmcifs.client.crypto.Sha512
import com.sorrowblue.kmcifs.client.crypto.Smb3Kdf
import com.sorrowblue.kmcifs.client.protocol.ByteUtils.readUIntLE
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
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout

/**
 * Manages an SMB2/SMB3 client session over a single TCP connection with asynchronous
 * request pipelining and `MessageId`-based response demultiplexing.
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
    private val readerDispatcher: CoroutineDispatcher = Dispatchers.Unconfined,
) : AutoCloseable {

    private class CreditWaiter(
        val needed: Int,
        var granted: Boolean = false,
        val deferred: CompletableDeferred<Unit> = CompletableDeferred(),
    )

    private sealed class PendingExchange(
        val requireEncrypted: Boolean,
        val requestTreeId: UInt,
    ) {
        var cancelled: Boolean = false
        var deliveredEncrypted: Boolean = false
        abstract val messageIds: List<ULong>
        abstract fun fail(cause: Throwable)

        class Single(
            val messageId: ULong,
            requireEncrypted: Boolean,
            requestTreeId: UInt = 0u,
        ) : PendingExchange(requireEncrypted, requestTreeId) {
            val deferred = CompletableDeferred<ByteArray>()
            var deliveredResponse: ByteArray? = null
            override val messageIds: List<ULong> = listOf(messageId)
            override fun fail(cause: Throwable) {
                deferred.completeExceptionally(cause)
            }
        }

        class Compound(
            val expectedMessageIds: List<ULong>,
            requireEncrypted: Boolean,
            requestTreeId: UInt,
            val closesHandleInCompound: Boolean,
        ) : PendingExchange(requireEncrypted, requestTreeId) {
            val deferred = CompletableDeferred<List<ByteArray>>()
            val collected = HashMap<ULong, ByteArray>(expectedMessageIds.size)
            var deliveredResponses: List<ByteArray>? = null
            override val messageIds: List<ULong> = expectedMessageIds
            override fun fail(cause: Throwable) {
                deferred.completeExceptionally(cause)
            }
        }
    }

    private val sendMutex = Mutex()
    private val stateMutex = Mutex()
    private val clientJob = SupervisorJob()

    private var nextMessageId: ULong = 0uL
    private var availableCredits: Int = 1
    private var supportsMultiCredit: Boolean = false
    private var inFlightSenders: Int = 0
    private val creditWaiters = ArrayDeque<CreditWaiter>()
    private val pendingExchanges = HashMap<ULong, PendingExchange>()
    private var readerRunning: Boolean = false
    private var echoProbeRunning: Boolean = false
    private var connectionError: Throwable? = null

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
            messageId = stateMutex.withLock { allocateMessageId(1u) },
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
        supportsMultiCredit = negotiatedDialect != SmbDialect.SMB_2_0_2 &&
            (negResp.capabilities and SmbMessages.SMB2_GLOBAL_CAP_LARGE_MTU) != 0u
        val maxAllowedMtu = if (!supportsMultiCredit) {
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
            messageId = stateMutex.withLock { allocateMessageId(1u) },
            sessionId = 0uL,
            securityBuffer = spnegoInit,
            securityMode = secMode,
        )
        if (!supportsMultiCredit) {
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
            messageId = stateMutex.withLock { allocateMessageId(1u) },
            sessionId = sessionId,
            securityBuffer = authResult.spnegoTokenResp,
            securityMode = secMode,
        )
        if (!supportsMultiCredit) {
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

    private fun prepareCreditCharge(packet: ByteArray): UShort {
        return if (!supportsMultiCredit) {
            // MS-SMB2 3.2.4.1.5: CreditCharge MUST be 0 when SupportsMultiCredit is FALSE
            packet.writeUShortLE(6, 0u)
            1u
        } else {
            val charge = packet.readUShortLE(6)
            if (charge == 0u.toUShort()) 1u else charge
        }
    }

    private fun computeCreditRequestLocked(consumedCredits: Int): UShort {
        var queuedDemand = 0
        for (waiter in creditWaiters) {
            queuedDemand = (queuedDemand + waiter.needed).coerceAtMost(65535)
        }
        val deficit = (TARGET_CREDITS + queuedDemand - availableCredits).coerceAtLeast(consumedCredits)
        return deficit.coerceIn(1, 65535).toUShort()
    }

    private fun grantCreditsLocked(granted: Int) {
        if (granted > 0) {
            availableCredits = (availableCredits + granted).coerceAtMost(65535)
        }
        if (availableCredits <= 0 && pendingExchanges.isEmpty() && inFlightSenders == 0) {
            availableCredits = 1
        }
        while (creditWaiters.isNotEmpty() && availableCredits >= creditWaiters.first().needed) {
            val waiter = creditWaiters.removeFirst()
            availableCredits -= waiter.needed
            waiter.granted = true
            inFlightSenders++
            waiter.deferred.complete(Unit)
        }
        ensureEchoCreditProbeLocked()
    }

    private fun ensureEchoCreditProbeLocked() {
        if (closed || echoProbeRunning || pendingExchanges.isNotEmpty() || inFlightSenders > 0 || creditWaiters.isEmpty()) {
            return
        }
        val headNeeded = creditWaiters.first().needed
        if (availableCredits in 1 until headNeeded) {
            echoProbeRunning = true
            CoroutineScope(clientJob + readerDispatcher).launch {
                runEchoCreditProbeLoop()
            }
        }
    }

    private suspend fun runEchoCreditProbeLoop() {
        try {
            while (true) {
                val echoResp = withTimeout(config.requestTimeout) {
                    val echoExchange = sendMutex.withLock {
                        val shouldEncrypt = shouldEncryptPacket(forceEncrypt = false)
                        val echoReq = SmbMessages.buildEchoRequest(sessionId = sessionId)
                        val charge = prepareCreditCharge(echoReq)

                        val created = stateMutex.withLock {
                            if (closed || pendingExchanges.isNotEmpty() || inFlightSenders > 0 || creditWaiters.isEmpty()) {
                                echoProbeRunning = false
                                return@withLock null
                            }
                            val headNeeded = creditWaiters.first().needed
                            if (availableCredits !in 1..<headNeeded) {
                                echoProbeRunning = false
                                return@withLock null
                            }
                            availableCredits -= 1
                            val msgId = allocateMessageId(charge)
                            val creditReq = computeCreditRequestLocked(1)
                            echoReq.writeUShortLE(14, creditReq)
                            echoReq.writeULongLE(24, msgId)
                            PendingExchange.Single(msgId, shouldEncrypt).also {
                                pendingExchanges[msgId] = it
                            }
                        } ?: return@withLock null

                        val wirePacket = wrapOutgoingSinglePacket(echoReq, shouldEncrypt)
                        transport.sendPacket(wirePacket)
                        ensureReaderRunning()
                        created
                    } ?: return@withTimeout null

                    echoExchange.deferred.await()
                } ?: return

                val echoHeader = SmbHeader.decode(echoResp)
                if (echoHeader.status != NtStatus.STATUS_SUCCESS) {
                    throw SmbException(
                        echoHeader.status,
                        "SMB2 ECHO failed with ${NtStatus.nameOf(echoHeader.status)}",
                    )
                }
                val echoGranted = echoHeader.creditRequestResponse.toInt()

                val toFail = ArrayList<CreditWaiter>()
                val capExceededCredits: Int
                val keepProbing = stateMutex.withLock {
                    if (closed || creditWaiters.isEmpty()) {
                        echoProbeRunning = false
                        capExceededCredits = 0
                        false
                    } else if (pendingExchanges.isNotEmpty() || inFlightSenders > 0) {
                        echoProbeRunning = false
                        capExceededCredits = 0
                        false
                    } else if (echoGranted <= 1 && availableCredits < creditWaiters.first().needed) {
                        // Server refused to increase our credit balance; fail unachievable multi-credit waiters immediately
                        capExceededCredits = availableCredits
                        val iter = creditWaiters.iterator()
                        while (iter.hasNext()) {
                            val w = iter.next()
                            if (w.needed > availableCredits) {
                                iter.remove()
                                toFail.add(w)
                            }
                        }
                        while (creditWaiters.isNotEmpty() && availableCredits >= creditWaiters.first().needed) {
                            val w = creditWaiters.removeFirst()
                            availableCredits -= w.needed
                            w.granted = true
                            inFlightSenders++
                            w.deferred.complete(Unit)
                        }
                        val moreNeeded = inFlightSenders == 0 &&
                            creditWaiters.isNotEmpty() &&
                            availableCredits in 1 until creditWaiters.first().needed
                        if (!moreNeeded) echoProbeRunning = false
                        moreNeeded
                    } else {
                        capExceededCredits = 0
                        val moreNeeded = creditWaiters.isNotEmpty() && availableCredits in 1 until creditWaiters.first().needed
                        if (!moreNeeded) echoProbeRunning = false
                        moreNeeded
                    }
                }
                if (toFail.isNotEmpty()) {
                    val capEx = SmbException(
                        NtStatus.STATUS_INSUFFICIENT_RESOURCES,
                        "Server refused to grant required SMB2 credits (available: $capExceededCredits)",
                    )
                    for (w in toFail) {
                        w.deferred.completeExceptionally(capEx)
                    }
                }
                if (!keepProbing) return
            }
        } catch (e: TimeoutCancellationException) {
            val timeoutEx = SmbException(
                NtStatus.STATUS_IO_TIMEOUT,
                "SMB2 ECHO credit probe timed out after ${config.requestTimeout}",
                e,
            )
            failConnection(timeoutEx)
        } catch (e: Throwable) {
            failConnection(e)
        }
    }

    private suspend fun acquireCredits(needed: Int) {
        val waiter: CreditWaiter? = stateMutex.withLock {
            if (closed) {
                throw connectionError ?: SmbException(
                    NtStatus.STATUS_USER_SESSION_DELETED,
                    "SMB client is already closed",
                )
            }
            if (creditWaiters.isEmpty() && availableCredits >= needed) {
                availableCredits -= needed
                inFlightSenders++
                null
            } else {
                CreditWaiter(needed).also {
                    creditWaiters.addLast(it)
                    ensureEchoCreditProbeLocked()
                }
            }
        }
        if (waiter != null) {
            try {
                waiter.deferred.await()
            } catch (e: Throwable) {
                withContext(NonCancellable) {
                    stateMutex.withLock {
                        val removed = creditWaiters.remove(waiter)
                        if (waiter.granted) {
                            waiter.granted = false
                            inFlightSenders = (inFlightSenders - 1).coerceAtLeast(0)
                            grantCreditsLocked(needed)
                        } else if (removed) {
                            grantCreditsLocked(0)
                        }
                    }
                }
                throw e
            }
        }
    }

    private suspend fun releaseCredits(amount: Int) {
        stateMutex.withLock {
            inFlightSenders = (inFlightSenders - 1).coerceAtLeast(0)
            grantCreditsLocked(amount)
        }
    }

    private fun shouldEncryptPacket(forceEncrypt: Boolean): Boolean {
        return (isSessionEncrypted || forceEncrypt) &&
            negotiatedDialect.isSmb3 &&
            negotiatedCipher != null &&
            encryptionKey != null
    }

    private fun wrapOutgoingSinglePacket(plainRequest: ByteArray, shouldEncrypt: Boolean): ByteArray {
        return if (shouldEncrypt) {
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
    }

    /**
     * Sends an SMB command packet asynchronously onto the pipelined TCP connection and awaits its
     * demultiplexed response matched by `MessageId`, automatically applying SMB2 credit flow control,
     * packet signing or SMB3 encryption, and interim `STATUS_PENDING` handling.
     */
    internal suspend fun executeCommand(
        plainRequest: ByteArray,
        forceEncrypt: Boolean = false,
        cancellable: Boolean = true,
    ): ByteArray {
        if (!cancellable) {
            return withContext(NonCancellable) {
                executeCommandInternal(plainRequest, forceEncrypt, cancellable = false)
            }
        }
        return executeCommandInternal(plainRequest, forceEncrypt, cancellable = true)
    }

    private suspend fun executeCommandInternal(
        plainRequest: ByteArray,
        forceEncrypt: Boolean,
        cancellable: Boolean,
    ): ByteArray {
        if (cancellable) {
            currentCoroutineContext().ensureActive()
        }
        if (closed) {
            throw SmbException(NtStatus.STATUS_USER_SESSION_DELETED, "SMB client is already closed")
        }
        val callerContext = currentCoroutineContext()
        return try {
            withTimeout(config.requestTimeout) {
                val credits = prepareCreditCharge(plainRequest)
                acquireCredits(credits.toInt())

                var registered = false
                val exchange = try {
                    withContext(NonCancellable) {
                        sendMutex.withLock {
                            val shouldEncrypt = shouldEncryptPacket(forceEncrypt)
                            val reqTreeId = plainRequest.readUIntLE(36)
                            val single = stateMutex.withLock {
                                if (cancellable && !callerContext.isActive) {
                                    throw CancellationException("SMB request cancelled before send")
                                }
                                if (closed) {
                                    throw connectionError ?: SmbException(
                                        NtStatus.STATUS_USER_SESSION_DELETED,
                                        "SMB client is already closed",
                                    )
                                }
                                val expectedMessageId = allocateMessageId(credits)
                                val creditReq = computeCreditRequestLocked(credits.toInt())
                                plainRequest.writeUShortLE(14, creditReq)
                                plainRequest.writeULongLE(24, expectedMessageId)
                                PendingExchange.Single(expectedMessageId, shouldEncrypt, reqTreeId).also {
                                    pendingExchanges[expectedMessageId] = it
                                    inFlightSenders = (inFlightSenders - 1).coerceAtLeast(0)
                                    registered = true
                                }
                            }

                            val wirePacket = wrapOutgoingSinglePacket(plainRequest, shouldEncrypt)
                            transport.sendPacket(wirePacket)
                            ensureReaderRunning()
                            single
                        }
                    }
                } catch (e: Throwable) {
                    if (!registered) {
                        withContext(NonCancellable) {
                            releaseCredits(credits.toInt())
                        }
                    }
                    throw e
                }

                try {
                    exchange.deferred.await()
                } catch (cancelEx: CancellationException) {
                    var lateDelivered: ByteArray? = null
                    var lateEncrypted = false
                    withContext(NonCancellable) {
                        stateMutex.withLock {
                            exchange.cancelled = true
                            lateDelivered = exchange.deliveredResponse
                            lateEncrypted = exchange.deliveredEncrypted
                            exchange.deliveredResponse = null
                        }
                    }
                    val orphanResp = lateDelivered
                    if (orphanResp != null) {
                        val hdr = runCatching { SmbHeader.decode(orphanResp) }.getOrNull()
                        if (hdr != null) {
                            cleanupOrphanedSingleResponse(orphanResp, hdr, exchange.requestTreeId, lateEncrypted)
                        }
                    }
                    throw cancelEx
                }
            }
        } catch (e: SmbException) {
            throw e
        } catch (e: TimeoutCancellationException) {
            if (cancellable && !callerContext.isActive) {
                throw e
            }
            val timeoutEx = SmbException(
                NtStatus.STATUS_IO_TIMEOUT,
                "SMB request timed out after ${config.requestTimeout}",
                e,
            )
            failConnection(timeoutEx)
            throw timeoutEx
        } catch (e: CancellationException) {
            throw e
        } catch (e: Throwable) {
            failConnection(e)
            throw e
        }
    }

    /**
     * Sends multiple related SMB2 requests (such as `[CREATE, CLOSE]`) in a single Compounded Related packet
     * onto the pipelined TCP connection and returns the corresponding response byte arrays in request order.
     */
    internal suspend fun executeCompoundCommands(
        plainRequests: List<ByteArray>,
        forceEncrypt: Boolean = false,
        cancellable: Boolean = true,
    ): List<ByteArray> {
        require(plainRequests.isNotEmpty()) { "plainRequests must not be empty" }
        if (plainRequests.size == 1) {
            return listOf(executeCommand(plainRequests[0], forceEncrypt, cancellable))
        }
        if (!cancellable) {
            return withContext(NonCancellable) {
                executeCompoundCommandsInternal(plainRequests, forceEncrypt, cancellable = false)
            }
        }
        return executeCompoundCommandsInternal(plainRequests, forceEncrypt, cancellable = true)
    }

    private suspend fun executeCompoundCommandsInternal(
        plainRequests: List<ByteArray>,
        forceEncrypt: Boolean,
        cancellable: Boolean,
    ): List<ByteArray> {
        if (cancellable) {
            currentCoroutineContext().ensureActive()
        }
        if (closed) {
            throw SmbException(NtStatus.STATUS_USER_SESSION_DELETED, "SMB client is already closed")
        }
        val callerContext = currentCoroutineContext()
        return try {
            withTimeout(config.requestTimeout) {
                val partCredits = IntArray(plainRequests.size)
                var totalCredits = 0
                for (i in plainRequests.indices) {
                    val c = prepareCreditCharge(plainRequests[i]).toInt()
                    partCredits[i] = c
                    totalCredits += c
                }
                acquireCredits(totalCredits)

                var registered = false
                val exchange = try {
                    withContext(NonCancellable) {
                        sendMutex.withLock {
                            val shouldEncrypt = shouldEncryptPacket(forceEncrypt)
                            val reqTreeId = plainRequests[0].readUIntLE(36)
                            val closesHandle = plainRequests.last().readUShortLE(12) == SmbCommand.CLOSE.code
                            val compound = stateMutex.withLock {
                                if (cancellable && !callerContext.isActive) {
                                    throw CancellationException("SMB compound request cancelled before send")
                                }
                                if (closed) {
                                    throw connectionError ?: SmbException(
                                        NtStatus.STATUS_USER_SESSION_DELETED,
                                        "SMB client is already closed",
                                    )
                                }
                                val expectedMessageIds = ArrayList<ULong>(plainRequests.size)
                                for (i in plainRequests.indices) {
                                    val req = plainRequests[i]
                                    val c = partCredits[i]
                                    val msgId = allocateMessageId(c.toUShort())
                                    val creditReq = if (i == plainRequests.lastIndex) {
                                        computeCreditRequestLocked(totalCredits)
                                    } else {
                                        c.coerceIn(1, 65535).toUShort()
                                    }
                                    req.writeUShortLE(14, creditReq)
                                    req.writeULongLE(24, msgId)
                                    expectedMessageIds.add(msgId)
                                }
                                PendingExchange.Compound(
                                    expectedMessageIds = expectedMessageIds,
                                    requireEncrypted = shouldEncrypt,
                                    requestTreeId = reqTreeId,
                                    closesHandleInCompound = closesHandle,
                                ).also { ex ->
                                    for (id in expectedMessageIds) {
                                        pendingExchanges[id] = ex
                                    }
                                    inFlightSenders = (inFlightSenders - 1).coerceAtLeast(0)
                                    registered = true
                                }
                            }

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
                            ensureReaderRunning()
                            compound
                        }
                    }
                } catch (e: Throwable) {
                    if (!registered) {
                        withContext(NonCancellable) {
                            releaseCredits(totalCredits)
                        }
                    }
                    throw e
                }

                try {
                    exchange.deferred.await()
                } catch (cancelEx: CancellationException) {
                    var lateDelivered: List<ByteArray>? = null
                    var lateEncrypted = false
                    withContext(NonCancellable) {
                        stateMutex.withLock {
                            exchange.cancelled = true
                            lateDelivered = exchange.deliveredResponses
                            lateEncrypted = exchange.deliveredEncrypted
                            exchange.deliveredResponses = null
                        }
                    }
                    val orphanResps = lateDelivered
                    if (orphanResps != null) {
                        cleanupOrphanedCompoundResponses(
                            responses = orphanResps,
                            closesHandleInCompound = exchange.closesHandleInCompound,
                            requestTreeId = exchange.requestTreeId,
                            wasEncrypted = lateEncrypted,
                        )
                    }
                    throw cancelEx
                }
            }
        } catch (e: SmbException) {
            throw e
        } catch (e: TimeoutCancellationException) {
            if (cancellable && !callerContext.isActive) {
                throw e
            }
            val timeoutEx = SmbException(
                NtStatus.STATUS_IO_TIMEOUT,
                "SMB compound request timed out after ${config.requestTimeout}",
                e,
            )
            failConnection(timeoutEx)
            throw timeoutEx
        } catch (e: CancellationException) {
            throw e
        } catch (e: Throwable) {
            failConnection(e)
            throw e
        }
    }

    private suspend fun sendAndReceiveRaw(rawRequest: ByteArray): ByteArray {
        currentCoroutineContext().ensureActive()
        val callerContext = currentCoroutineContext()
        val expectedMessageId = rawRequest.readULongLE(24)
        return sendMutex.withLock {
            if (closed) {
                throw SmbException(NtStatus.STATUS_USER_SESSION_DELETED, "SMB client is already closed")
            }
            try {
                withTimeout(config.requestTimeout) {
                    withContext(NonCancellable) {
                        stateMutex.withLock {
                            availableCredits = (availableCredits - 1).coerceAtLeast(0)
                        }
                        transport.sendPacket(rawRequest)
                    }
                    val resp = receiveHandshakeResponse(expectedMessageId)
                    val respHeader = SmbHeader.decode(resp)
                    stateMutex.withLock {
                        availableCredits = maxOf(
                            1,
                            (availableCredits + respHeader.creditRequestResponse.toInt()).coerceAtMost(65535),
                        )
                    }
                    resp
                }
            } catch (e: SmbException) {
                throw e
            } catch (e: TimeoutCancellationException) {
                if (!callerContext.isActive) {
                    failConnection(e)
                    throw e
                }
                val timeoutEx = SmbException(
                    NtStatus.STATUS_IO_TIMEOUT,
                    "SMB session handshake timed out after ${config.requestTimeout}",
                    e,
                )
                failConnection(timeoutEx)
                throw timeoutEx
            } catch (e: CancellationException) {
                failConnection(e)
                throw e
            } catch (e: Throwable) {
                failConnection(e)
                throw e
            }
        }
    }

    private suspend fun receiveHandshakeResponse(expectedMessageId: ULong): ByteArray {
        while (true) {
            val rawIncoming = transport.receivePacket()
            val wasEncrypted = SmbTransformHeader.isTransformPacket(rawIncoming)
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
            if (!header.isResponse || header.messageId == ULong.MAX_VALUE) {
                continue
            }
            if (header.status == NtStatus.STATUS_PENDING && header.isAsync) {
                stateMutex.withLock {
                    availableCredits = (availableCredits + header.creditRequestResponse.toInt()).coerceAtMost(65535)
                }
                continue
            }
            if (header.messageId < expectedMessageId) {
                continue
            }
            if (header.messageId != expectedMessageId) {
                throw SmbException(
                    NtStatus.STATUS_INVALID_NETWORK_RESPONSE,
                    "Unexpected SMB2 response MessageId: expected $expectedMessageId, got ${header.messageId}"
                )
            }
            return plainResponse
        }
    }

    private suspend fun ensureReaderRunning() {
        stateMutex.withLock {
            if (closed || pendingExchanges.isEmpty() || readerRunning) return
            readerRunning = true
            CoroutineScope(clientJob + readerDispatcher).launch {
                runReaderLoop()
            }
        }
    }

    private suspend fun runReaderLoop() {
        try {
            while (true) {
                val keepReading = stateMutex.withLock {
                    if (closed || pendingExchanges.isEmpty()) {
                        readerRunning = false
                        false
                    } else {
                        true
                    }
                }
                if (!keepReading) return

                val rawIncoming = transport.receivePacket()
                dispatchIncomingPacket(rawIncoming)
            }
        } catch (e: Throwable) {
            failConnection(e)
        }
    }

    private suspend fun dispatchIncomingPacket(rawIncoming: ByteArray) {
        val wasEncrypted = SmbTransformHeader.isTransformPacket(rawIncoming)
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
        for ((partIndex, part) in parts.withIndex()) {
            val header = SmbHeader.decode(part)
            // Skip unsolicited server notifications (e.g., OPLOCK_BREAK with MessageId == 0xFFFFFFFFFFFFFFFF)
            if (!header.isResponse || header.messageId == ULong.MAX_VALUE) {
                if (header.creditRequestResponse > 0u) {
                    stateMutex.withLock {
                        grantCreditsLocked(header.creditRequestResponse.toInt())
                    }
                }
                continue
            }

            // Interim STATUS_PENDING async responses grant credits while keeping the exchange pending
            if (header.status == NtStatus.STATUS_PENDING && header.isAsync) {
                stateMutex.withLock {
                    grantCreditsLocked(header.creditRequestResponse.toInt())
                }
                continue
            }

            val exchange = stateMutex.withLock {
                val found = pendingExchanges[header.messageId]
                if (found == null && header.messageId >= nextMessageId) {
                    grantCreditsLocked(header.creditRequestResponse.toInt())
                    throw SmbException(
                        NtStatus.STATUS_INVALID_NETWORK_RESPONSE,
                        "Unexpected SMB2 response MessageId: ${header.messageId}",
                    )
                }
                if (found == null) {
                    grantCreditsLocked(header.creditRequestResponse.toInt())
                }
                found
            } ?: continue

            if (exchange.requireEncrypted && !wasEncrypted) {
                val encEx = SmbException(
                    NtStatus.STATUS_ACCESS_DENIED,
                    "Expected encrypted SMB3 Transform response, but received unencrypted packet",
                )
                stateMutex.withLock {
                    for (id in exchange.messageIds) {
                        pendingExchanges.remove(id)
                    }
                    grantCreditsLocked(header.creditRequestResponse.toInt())
                }
                exchange.fail(encEx)
                continue
            }

            try {
                verifyIncomingPacketSignatureIfRequired(part, header, wasEncrypted)
            } catch (sigEx: SmbException) {
                stateMutex.withLock {
                    for (id in exchange.messageIds) {
                        pendingExchanges.remove(id)
                    }
                    grantCreditsLocked(header.creditRequestResponse.toInt())
                }
                exchange.fail(sigEx)
                continue
            }

            when (exchange) {
                is PendingExchange.Single -> {
                    val isCancelled = stateMutex.withLock {
                        pendingExchanges.remove(exchange.messageId)
                        grantCreditsLocked(header.creditRequestResponse.toInt())
                        if (!exchange.cancelled) {
                            exchange.deliveredResponse = part
                            exchange.deliveredEncrypted = wasEncrypted
                        }
                        exchange.cancelled
                    }
                    if (isCancelled) {
                        cleanupOrphanedSingleResponse(part, header, exchange.requestTreeId, wasEncrypted)
                    } else {
                        exchange.deferred.complete(part)
                    }
                }

                is PendingExchange.Compound -> {
                    var completedList: List<ByteArray>? = null
                    var isCancelled = false
                    stateMutex.withLock {
                        exchange.collected[header.messageId] = part
                        val isNtError = (header.status and 0xC0000000u) == 0xC0000000u
                        // 先頭コマンド（CREATE）がエラー終了し、サーバーが後続の関連レスポンスを省略した場合のみ未受信分を補完する
                        if (partIndex == parts.lastIndex &&
                            isNtError &&
                            header.messageId == exchange.expectedMessageIds.first() &&
                            exchange.collected.size < exchange.expectedMessageIds.size
                        ) {
                            for (id in exchange.expectedMessageIds) {
                                if (id !in exchange.collected) {
                                    exchange.collected[id] = part
                                }
                            }
                        }
                        if (exchange.collected.size >= exchange.expectedMessageIds.size) {
                            for (id in exchange.expectedMessageIds) {
                                pendingExchanges.remove(id)
                            }
                            val list = exchange.expectedMessageIds.map { exchange.collected.getValue(it) }
                            completedList = list
                            isCancelled = exchange.cancelled
                            if (!isCancelled) {
                                exchange.deliveredResponses = list
                                exchange.deliveredEncrypted = wasEncrypted
                            }
                        }
                        grantCreditsLocked(header.creditRequestResponse.toInt())
                    }
                    val done = completedList
                    if (done != null) {
                        if (isCancelled) {
                            cleanupOrphanedCompoundResponses(
                                responses = done,
                                closesHandleInCompound = exchange.closesHandleInCompound,
                                requestTreeId = exchange.requestTreeId,
                                wasEncrypted = wasEncrypted,
                            )
                        } else {
                            exchange.deferred.complete(done)
                        }
                    }
                }
            }
        }
    }

    private fun cleanupOrphanedSingleResponse(
        respPacket: ByteArray,
        header: SmbHeader,
        requestTreeId: UInt,
        wasEncrypted: Boolean,
    ) {
        if (header.status != NtStatus.STATUS_SUCCESS) return
        when (header.command) {
            SmbCommand.CREATE -> {
                closeOrphanedCreateHandleAsync(respPacket, requestTreeId, wasEncrypted)
            }
            SmbCommand.TREE_CONNECT -> {
                val treeResp = runCatching { SmbMessages.parseTreeConnectResponse(respPacket) }.getOrNull() ?: return
                val forceEncrypt = wasEncrypted ||
                    (config.encryptionPolicy != SmbEncryptionPolicy.DISABLED && treeResp.encryptData)
                val discReq = SmbMessages.buildTreeDisconnectRequest(
                    sessionId = sessionId,
                    treeId = treeResp.treeId,
                )
                CoroutineScope(clientJob + readerDispatcher).launch {
                    runCatching {
                        executeCommand(discReq, forceEncrypt = forceEncrypt, cancellable = false)
                    }
                }
            }
            else -> Unit
        }
    }

    private fun cleanupOrphanedCompoundResponses(
        responses: List<ByteArray>,
        closesHandleInCompound: Boolean,
        requestTreeId: UInt,
        wasEncrypted: Boolean,
    ) {
        if (responses.isEmpty()) return
        val firstHdr = runCatching { SmbHeader.decode(responses[0]) }.getOrNull() ?: return
        if (firstHdr.command != SmbCommand.CREATE || firstHdr.status != NtStatus.STATUS_SUCCESS) return
        val closedInCompound = closesHandleInCompound &&
            responses.size >= 2 &&
            runCatching {
                val lastHdr = SmbHeader.decode(responses.last())
                lastHdr.command == SmbCommand.CLOSE && lastHdr.status == NtStatus.STATUS_SUCCESS
            }.getOrDefault(false)
        if (!closedInCompound) {
            closeOrphanedCreateHandleAsync(responses[0], requestTreeId, wasEncrypted)
        }
    }

    private fun closeOrphanedCreateHandleAsync(
        createRespPacket: ByteArray,
        treeId: UInt,
        wasEncrypted: Boolean,
    ) {
        val createResp = runCatching { SmbMessages.parseCreateResponse(createRespPacket) }.getOrNull() ?: return
        val closeReq = SmbMessages.buildCloseRequest(
            sessionId = sessionId,
            treeId = treeId,
            fileId = createResp.fileId,
        )
        CoroutineScope(clientJob + readerDispatcher).launch {
            runCatching {
                executeCommand(closeReq, forceEncrypt = wasEncrypted, cancellable = false)
            }
        }
    }

    private suspend fun failConnection(cause: Throwable) = withContext(NonCancellable) {
        closed = true
        runCatching { transport.close() }
        val toFailExchanges = ArrayList<PendingExchange>()
        val toFailWaiters = ArrayList<CreditWaiter>()
        val failure = stateMutex.withLock {
            readerRunning = false
            echoProbeRunning = false
            inFlightSenders = 0
            val recorded = connectionError ?: cause.also { connectionError = it }
            val unique = LinkedHashSet(pendingExchanges.values)
            toFailExchanges.addAll(unique)
            pendingExchanges.clear()
            toFailWaiters.addAll(creditWaiters)
            creditWaiters.clear()
            recorded
        }
        clientJob.cancel()
        for (ex in toFailExchanges) {
            ex.fail(failure)
        }
        for (w in toFailWaiters) {
            w.deferred.completeExceptionally(failure)
        }
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
                    executeCommand(req, cancellable = false)
                }
            }
        } finally {
            failConnection(SmbException(NtStatus.STATUS_USER_SESSION_DELETED, "SMB client is already closed"))
        }
    }

    override fun close() {
        closed = true
        runCatching { transport.close() }
        clientJob.cancel()
        CoroutineScope(Dispatchers.Unconfined).launch {
            failConnection(SmbException(NtStatus.STATUS_USER_SESSION_DELETED, "SMB client is already closed"))
        }
    }

    companion object {
        private const val TARGET_CREDITS = 128

        /**
         * Connects to the specified SMB server over TCP and completes dialect negotiation and NTLMv2 authentication.
         */
        suspend fun connect(
            host: String,
            port: Int = 445,
            credentials: SmbCredentials = SmbCredentials.Anonymous,
            config: SmbConfig = SmbConfig(),
        ): SmbClient {
            val transport = KtorTcpSmbTransport.connect(host, port, config.connectTimeout)
            val client = SmbClient(
                host = host,
                port = port,
                config = config,
                transport = transport,
                readerDispatcher = KtorTcpSmbTransport.transportDispatcher,
            )
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
