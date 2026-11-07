package com.sorrowblue.kmcifs.client.protocol

import com.sorrowblue.kmcifs.client.protocol.ByteUtils.decodeFromUtf16LE
import com.sorrowblue.kmcifs.client.protocol.ByteUtils.encodeToUtf16LE
import com.sorrowblue.kmcifs.client.protocol.ByteUtils.filetimeToEpochMillis
import com.sorrowblue.kmcifs.client.protocol.ByteUtils.readUIntLE
import com.sorrowblue.kmcifs.client.protocol.ByteUtils.readULongLE
import com.sorrowblue.kmcifs.client.protocol.ByteUtils.readUShortLE
import com.sorrowblue.kmcifs.client.protocol.ByteUtils.writeUIntLE
import com.sorrowblue.kmcifs.client.protocol.ByteUtils.writeULongLE
import com.sorrowblue.kmcifs.client.protocol.ByteUtils.writeUShortLE
import kotlin.random.Random

/**
 * SMB2 / SMB3 各コマンドのリクエスト構築およびレスポンス解析。
 */
internal object SmbMessages {

    // Capabilities
    const val SMB2_GLOBAL_CAP_DFS: UInt = 0x00000001u
    const val SMB2_GLOBAL_CAP_LEASING: UInt = 0x00000002u
    const val SMB2_GLOBAL_CAP_LARGE_MTU: UInt = 0x00000004u
    const val SMB2_GLOBAL_CAP_ENCRYPTION: UInt = 0x00000040u

    // Security Mode
    const val SMB2_NEGOTIATE_SIGNING_ENABLED: UShort = 0x0001u
    const val SMB2_NEGOTIATE_SIGNING_REQUIRED: UShort = 0x0002u

    // Session Flags
    const val SMB2_SESSION_FLAG_IS_GUEST: UShort = 0x0001u
    const val SMB2_SESSION_FLAG_IS_NULL: UShort = 0x0002u
    const val SMB2_SESSION_FLAG_ENCRYPT_DATA: UShort = 0x0004u

    // Share Flags
    const val SMB2_SHAREFLAG_ENCRYPT_DATA: UInt = 0x00008000u

    // Negotiate Context Types (SMB 3.1.1)
    private const val SMB2_PREAUTH_INTEGRITY_CAPABILITIES: UShort = 0x0001u
    private const val SMB2_ENCRYPTION_CAPABILITIES: UShort = 0x0002u

    // Lock Flags
    const val SMB2_LOCKFLAG_SHARED_LOCK: UInt = 0x00000001u
    const val SMB2_LOCKFLAG_EXCLUSIVE_LOCK: UInt = 0x00000002u
    const val SMB2_LOCKFLAG_UNLOCK: UInt = 0x00000004u
    const val SMB2_LOCKFLAG_FAIL_IMMEDIATELY: UInt = 0x00000010u

    // IOCTL Codes
    const val FSCTL_PIPE_TRANSCEIVE: UInt = 0x0011C017u

    data class NegotiateResponse(
        val securityMode: UShort,
        val dialect: SmbDialect,
        val capabilities: UInt,
        val maxTransactSize: UInt,
        val maxReadSize: UInt,
        val maxWriteSize: UInt,
        val securityBuffer: ByteArray,
        val negotiatedCipher: SmbCipherId?,
    ) {
        val signingRequired: Boolean
            get() = (securityMode.toInt() and SMB2_NEGOTIATE_SIGNING_REQUIRED.toInt()) != 0
    }

    data class SessionSetupResponse(
        val status: UInt,
        val sessionId: ULong,
        val sessionFlags: UShort,
        val securityBuffer: ByteArray,
    ) {
        val encryptData: Boolean
            get() = (sessionFlags.toInt() and SMB2_SESSION_FLAG_ENCRYPT_DATA.toInt()) != 0

        val isGuestOrNull: Boolean
            get() = (sessionFlags.toInt() and (SMB2_SESSION_FLAG_IS_GUEST.toInt() or SMB2_SESSION_FLAG_IS_NULL.toInt())) != 0
    }

    data class TreeConnectResponse(
        val treeId: UInt,
        val shareType: UByte,
        val shareFlags: UInt,
        val capabilities: UInt,
        val maximalAccess: UInt,
    ) {
        val encryptData: Boolean
            get() = (shareFlags and SMB2_SHAREFLAG_ENCRYPT_DATA) != 0u
    }

    data class CreateResponse(
        val fileId: SmbFileId,
        val metadata: SmbFileMetadata,
    )

    // =========================================================================
    // 1. NEGOTIATE (0x0000)
    // =========================================================================

    fun buildNegotiateRequest(
        messageId: ULong,
        dialects: List<SmbDialect>,
        clientGuid: ByteArray = Random.Default.nextBytes(16),
        ciphers: List<SmbCipherId> = listOf(SmbCipherId.AES_128_GCM, SmbCipherId.AES_128_CCM),
    ): ByteArray {
        require(dialects.isNotEmpty()) { "At least one SMB dialect must be specified" }
        val hasSmb311 = dialects.contains(SmbDialect.SMB_3_1_1)
        val hasSmb3 = dialects.any { it.isSmb3 }

        val dialectsBytesLen = dialects.size * 2
        val baseBodySize = 36 + dialectsBytesLen

        val contextBlock: ByteArray
        val contextOffsetInPacket: Int
        val contextCount: Int
        if (hasSmb311) {
            val unalignedOffset = SmbHeader.SIZE + baseBodySize
            val padTo8 = (8 - (unalignedOffset % 8)) % 8
            contextOffsetInPacket = unalignedOffset + padTo8
            contextCount = 2

            // Context 1: SMB2_PREAUTH_INTEGRITY_CAPABILITIES (HashAlgorithmCount=1 (SHA-512=0x0001), SaltLength=32)
            val salt = Random.Default.nextBytes(32)
            val preauthData = ByteArray(6 + 32)
            preauthData.writeUShortLE(0, 1u) // HashAlgorithmCount = 1
            preauthData.writeUShortLE(2, 32u) // SaltLength = 32
            preauthData.writeUShortLE(4, 0x0001u) // SHA-512
            salt.copyInto(preauthData, 6)
            val ctx1 = buildNegotiateContext(SMB2_PREAUTH_INTEGRITY_CAPABILITIES, preauthData)
            val ctx1Pad = (8 - (ctx1.size % 8)) % 8

            // Context 2: SMB2_ENCRYPTION_CAPABILITIES
            val encData = ByteArray(2 + ciphers.size * 2)
            encData.writeUShortLE(0, ciphers.size.toUShort())
            ciphers.forEachIndexed { idx, cipher ->
                encData.writeUShortLE(2 + idx * 2, cipher.code)
            }
            val ctx2 = buildNegotiateContext(SMB2_ENCRYPTION_CAPABILITIES, encData)

            contextBlock = ByteArray(padTo8 + ctx1.size + ctx1Pad + ctx2.size)
            ctx1.copyInto(contextBlock, padTo8)
            ctx2.copyInto(contextBlock, padTo8 + ctx1.size + ctx1Pad)
        } else {
            contextBlock = ByteArray(0)
            contextOffsetInPacket = 0
            contextCount = 0
        }

        val packet = ByteArray(SmbHeader.SIZE + baseBodySize + contextBlock.size)
        val header = SmbHeader.withTreeId(
            command = SmbCommand.NEGOTIATE,
            messageId = messageId,
            creditCharge = 1u,
            creditRequest = 31u
        )
        header.encodeInto(packet, 0)

        val bodyOffset = SmbHeader.SIZE
        packet.writeUShortLE(bodyOffset, 36u) // StructureSize = 36
        packet.writeUShortLE(bodyOffset + 2, dialects.size.toUShort())
        packet.writeUShortLE(bodyOffset + 4, SMB2_NEGOTIATE_SIGNING_ENABLED)
        packet.writeUShortLE(bodyOffset + 6, 0u) // Reserved

        val capabilities = if (hasSmb3) {
            SMB2_GLOBAL_CAP_LARGE_MTU or SMB2_GLOBAL_CAP_ENCRYPTION
        } else {
            SMB2_GLOBAL_CAP_LARGE_MTU
        }
        packet.writeUIntLE(bodyOffset + 8, capabilities)
        clientGuid.copyInto(packet, bodyOffset + 12, 0, 16)

        if (hasSmb311) {
            packet.writeUIntLE(bodyOffset + 28, contextOffsetInPacket.toUInt())
            packet.writeUShortLE(bodyOffset + 32, contextCount.toUShort())
            packet.writeUShortLE(bodyOffset + 34, 0u)
        } else {
            packet.writeULongLE(bodyOffset + 28, 0uL)
        }

        dialects.forEachIndexed { index, dialect ->
            packet.writeUShortLE(bodyOffset + 36 + index * 2, dialect.code)
        }

        if (contextBlock.isNotEmpty()) {
            contextBlock.copyInto(packet, bodyOffset + baseBodySize)
        }
        return packet
    }

    private fun buildNegotiateContext(contextType: UShort, data: ByteArray): ByteArray {
        val out = ByteArray(8 + data.size)
        out.writeUShortLE(0, contextType)
        out.writeUShortLE(2, data.size.toUShort())
        out.writeUIntLE(4, 0u) // Reserved
        data.copyInto(out, 8)
        return out
    }

    private fun requireBodySize(packet: ByteArray, header: SmbHeader, expectedCommand: SmbCommand, minBodyBytes: Int) {
        if (header.command != expectedCommand) {
            throw SmbException(
                header.status,
                "Unexpected SMB command in response: expected $expectedCommand, got ${header.command}"
            )
        }
        val minPacketSize = SmbHeader.SIZE + minBodyBytes
        if (packet.size < minPacketSize) {
            throw SmbException(
                header.status,
                "Malformed $expectedCommand response: packet size (${packet.size}) < required ($minPacketSize)"
            )
        }
    }

    fun parseNegotiateResponse(packet: ByteArray): NegotiateResponse {
        val header = SmbHeader.decode(packet)
        if (header.status != NtStatus.STATUS_SUCCESS) {
            throw SmbException(header.status, "NEGOTIATE failed with ${NtStatus.nameOf(header.status)}")
        }
        requireBodySize(packet, header, SmbCommand.NEGOTIATE, 64)
        val bodyOffset = SmbHeader.SIZE
        val securityMode = packet.readUShortLE(bodyOffset + 2)
        val dialectCode = packet.readUShortLE(bodyOffset + 4)
        val dialect = SmbDialect.fromCode(dialectCode)
            ?: throw SmbException(
                NtStatus.STATUS_NOT_SUPPORTED,
                "Server selected unsupported dialect: 0x${dialectCode.toString(16)}"
            )
        val negotiateContextCount = packet.readUShortLE(bodyOffset + 6).toInt()
        val capabilities = packet.readUIntLE(bodyOffset + 24)
        val maxTransactSize = packet.readUIntLE(bodyOffset + 28)
        val maxReadSize = packet.readUIntLE(bodyOffset + 32)
        val maxWriteSize = packet.readUIntLE(bodyOffset + 36)
        val secBufOffset = packet.readUShortLE(bodyOffset + 56).toInt()
        val secBufLen = packet.readUShortLE(bodyOffset + 58).toInt()
        val negotiateContextOffset = packet.readUIntLE(bodyOffset + 60).toInt()

        val secBuffer = if (secBufLen > 0 && secBufOffset + secBufLen <= packet.size) {
            packet.copyOfRange(secBufOffset, secBufOffset + secBufLen)
        } else {
            ByteArray(0)
        }

        var selectedCipher: SmbCipherId? = null
        if (dialect == SmbDialect.SMB_3_1_1 && negotiateContextCount > 0 && negotiateContextOffset > 0) {
            var pos = negotiateContextOffset
            for (i in 0 until negotiateContextCount) {
                if (pos + 8 > packet.size) break
                val ctxType = packet.readUShortLE(pos)
                val ctxLen = packet.readUShortLE(pos + 2).toInt()
                val dataStart = pos + 8
                if (dataStart + ctxLen > packet.size) break
                if (ctxType == SMB2_ENCRYPTION_CAPABILITIES && ctxLen >= 4) {
                    val cipherCount = packet.readUShortLE(dataStart).toInt()
                    if (cipherCount >= 1) {
                        val cipherCode = packet.readUShortLE(dataStart + 2)
                        selectedCipher = SmbCipherId.fromCode(cipherCode)
                    }
                }
                val nextPos = dataStart + ctxLen
                val pad = (8 - (nextPos % 8)) % 8
                pos = nextPos + pad
            }
        } else if (dialect == SmbDialect.SMB_3_0_0 || dialect == SmbDialect.SMB_3_0_2) {
            if ((capabilities and SMB2_GLOBAL_CAP_ENCRYPTION) != 0u) {
                selectedCipher = SmbCipherId.AES_128_CCM
            }
        }

        return NegotiateResponse(
            securityMode = securityMode,
            dialect = dialect,
            capabilities = capabilities,
            maxTransactSize = maxTransactSize,
            maxReadSize = maxReadSize,
            maxWriteSize = maxWriteSize,
            securityBuffer = secBuffer,
            negotiatedCipher = selectedCipher,
        )
    }

    // =========================================================================
    // 2. SESSION_SETUP (0x0001) & LOGOFF (0x0002)
    // =========================================================================

    fun buildSessionSetupRequest(
        messageId: ULong,
        sessionId: ULong,
        securityBuffer: ByteArray,
        securityMode: UShort = SMB2_NEGOTIATE_SIGNING_ENABLED,
    ): ByteArray {
        val bodyFixedSize = 24
        val packet = ByteArray(SmbHeader.SIZE + bodyFixedSize + securityBuffer.size)
        val header = SmbHeader.withTreeId(
            command = SmbCommand.SESSION_SETUP,
            messageId = messageId,
            sessionId = sessionId,
        )
        header.encodeInto(packet, 0)

        val bodyOffset = SmbHeader.SIZE
        packet.writeUShortLE(bodyOffset, 25u) // StructureSize = 25
        packet[bodyOffset + 2] = 0 // Flags = 0
        packet[bodyOffset + 3] = securityMode.toByte()
        packet.writeUIntLE(bodyOffset + 4, 0u) // Capabilities
        packet.writeUIntLE(bodyOffset + 8, 0u) // Channel = 0
        packet.writeUShortLE(bodyOffset + 12, (SmbHeader.SIZE + bodyFixedSize).toUShort()) // SecurityBufferOffset = 88
        packet.writeUShortLE(bodyOffset + 14, securityBuffer.size.toUShort())
        packet.writeULongLE(bodyOffset + 16, 0uL) // PreviousSessionId = 0

        securityBuffer.copyInto(packet, SmbHeader.SIZE + bodyFixedSize)
        return packet
    }

    fun parseSessionSetupResponse(packet: ByteArray): SessionSetupResponse {
        val header = SmbHeader.decode(packet)
        if (header.status != NtStatus.STATUS_SUCCESS && header.status != NtStatus.STATUS_MORE_PROCESSING_REQUIRED) {
            throw SmbException(header.status, "SESSION_SETUP failed with ${NtStatus.nameOf(header.status)}")
        }
        requireBodySize(packet, header, SmbCommand.SESSION_SETUP, 8)
        val bodyOffset = SmbHeader.SIZE
        val sessionFlags = packet.readUShortLE(bodyOffset + 2)
        val secBufOffset = packet.readUShortLE(bodyOffset + 4).toInt()
        val secBufLen = packet.readUShortLE(bodyOffset + 6).toInt()

        val secBuffer = if (secBufLen > 0 && secBufOffset + secBufLen <= packet.size) {
            packet.copyOfRange(secBufOffset, secBufOffset + secBufLen)
        } else {
            ByteArray(0)
        }

        return SessionSetupResponse(
            status = header.status,
            sessionId = header.sessionId,
            sessionFlags = sessionFlags,
            securityBuffer = secBuffer,
        )
    }

    fun buildLogoffRequest(messageId: ULong, sessionId: ULong): ByteArray {
        val packet = ByteArray(SmbHeader.SIZE + 4)
        val header = SmbHeader.withTreeId(
            command = SmbCommand.LOGOFF,
            messageId = messageId,
            sessionId = sessionId,
        )
        header.encodeInto(packet, 0)
        packet.writeUShortLE(SmbHeader.SIZE, 4u)
        packet.writeUShortLE(SmbHeader.SIZE + 2, 0u)
        return packet
    }

    // =========================================================================
    // 3. TREE_CONNECT (0x0003) & TREE_DISCONNECT (0x0004)
    // =========================================================================

    fun buildTreeConnectRequest(
        messageId: ULong,
        sessionId: ULong,
        uncPath: String,
    ): ByteArray {
        val pathBytes = uncPath.encodeToUtf16LE()
        val bodyFixedSize = 8
        val payload = if (pathBytes.isEmpty()) ByteArray(2) else pathBytes
        val packet = ByteArray(SmbHeader.SIZE + bodyFixedSize + payload.size)

        val header = SmbHeader.withTreeId(
            command = SmbCommand.TREE_CONNECT,
            messageId = messageId,
            sessionId = sessionId,
        )
        header.encodeInto(packet, 0)

        val bodyOffset = SmbHeader.SIZE
        packet.writeUShortLE(bodyOffset, 9u) // StructureSize = 9
        packet.writeUShortLE(bodyOffset + 2, 0u) // Flags = 0
        packet.writeUShortLE(bodyOffset + 4, (SmbHeader.SIZE + bodyFixedSize).toUShort()) // PathOffset = 72
        packet.writeUShortLE(bodyOffset + 6, pathBytes.size.toUShort()) // PathLength
        payload.copyInto(packet, SmbHeader.SIZE + bodyFixedSize)
        return packet
    }

    fun parseTreeConnectResponse(packet: ByteArray): TreeConnectResponse {
        val header = SmbHeader.decode(packet)
        if (header.status != NtStatus.STATUS_SUCCESS) {
            throw SmbException(header.status, "TREE_CONNECT failed with ${NtStatus.nameOf(header.status)}")
        }
        requireBodySize(packet, header, SmbCommand.TREE_CONNECT, 16)
        val bodyOffset = SmbHeader.SIZE
        val shareType = packet[bodyOffset + 2].toUByte()
        val shareFlags = packet.readUIntLE(bodyOffset + 4)
        val capabilities = packet.readUIntLE(bodyOffset + 8)
        val maximalAccess = packet.readUIntLE(bodyOffset + 12)

        return TreeConnectResponse(
            treeId = header.treeId,
            shareType = shareType,
            shareFlags = shareFlags,
            capabilities = capabilities,
            maximalAccess = maximalAccess,
        )
    }

    fun buildTreeDisconnectRequest(messageId: ULong, sessionId: ULong, treeId: UInt): ByteArray {
        val packet = ByteArray(SmbHeader.SIZE + 4)
        val header = SmbHeader.withTreeId(
            command = SmbCommand.TREE_DISCONNECT,
            messageId = messageId,
            treeId = treeId,
            sessionId = sessionId,
        )
        header.encodeInto(packet, 0)
        packet.writeUShortLE(SmbHeader.SIZE, 4u)
        packet.writeUShortLE(SmbHeader.SIZE + 2, 0u)
        return packet
    }

    // =========================================================================
    // 4. CREATE (0x0005), CLOSE (0x0006), FLUSH (0x0007)
    // =========================================================================

    fun buildCreateRequest(
        messageId: ULong,
        sessionId: ULong,
        treeId: UInt,
        path: String,
        desiredAccess: UInt,
        fileAttributes: UInt,
        shareAccess: UInt,
        createDisposition: SmbCreateDisposition,
        createOptions: UInt,
    ): ByteArray {
        val normalizedPath = path.trimStart('/', '\\').replace('/', '\\')
        val nameBytes = normalizedPath.encodeToUtf16LE()
        // CREATE StructureSize is 57 (56 bytes fixed + at least 1 byte variable buffer)
        val bodyFixedSize = 56
        val variableBuffer = if (nameBytes.isEmpty()) ByteArray(8) else nameBytes
        val packet = ByteArray(SmbHeader.SIZE + bodyFixedSize + variableBuffer.size)

        val header = SmbHeader.withTreeId(
            command = SmbCommand.CREATE,
            messageId = messageId,
            treeId = treeId,
            sessionId = sessionId,
        )
        header.encodeInto(packet, 0)

        val bodyOffset = SmbHeader.SIZE
        packet.writeUShortLE(bodyOffset, 57u) // StructureSize = 57
        packet[bodyOffset + 2] = 0 // SecurityFlags = 0
        packet[bodyOffset + 3] = 0 // RequestedOplockLevel = SMB2_OPLOCK_LEVEL_NONE (0)
        packet.writeUIntLE(bodyOffset + 4, 2u) // ImpersonationLevel = Impersonation (2)
        packet.writeULongLE(bodyOffset + 8, 0uL) // SmbCreateFlags = 0
        packet.writeULongLE(bodyOffset + 16, 0uL) // Reserved = 0
        packet.writeUIntLE(bodyOffset + 24, desiredAccess)
        packet.writeUIntLE(bodyOffset + 28, fileAttributes)
        packet.writeUIntLE(bodyOffset + 32, shareAccess)
        packet.writeUIntLE(bodyOffset + 36, createDisposition.code)
        packet.writeUIntLE(bodyOffset + 40, createOptions)
        packet.writeUShortLE(bodyOffset + 44, (SmbHeader.SIZE + bodyFixedSize).toUShort()) // NameOffset = 120
        packet.writeUShortLE(bodyOffset + 46, nameBytes.size.toUShort()) // NameLength
        packet.writeUIntLE(bodyOffset + 48, 0u) // CreateContextsOffset = 0
        packet.writeUIntLE(bodyOffset + 52, 0u) // CreateContextsLength = 0

        variableBuffer.copyInto(packet, SmbHeader.SIZE + bodyFixedSize)
        return packet
    }

    fun parseCreateResponse(packet: ByteArray): CreateResponse {
        val header = SmbHeader.decode(packet)
        if (header.status != NtStatus.STATUS_SUCCESS) {
            throw SmbException(header.status, "CREATE failed with ${NtStatus.nameOf(header.status)}")
        }
        requireBodySize(packet, header, SmbCommand.CREATE, 80)
        val bodyOffset = SmbHeader.SIZE
        val creationTime = filetimeToEpochMillis(packet.readULongLE(bodyOffset + 8))
        val lastAccessTime = filetimeToEpochMillis(packet.readULongLE(bodyOffset + 16))
        val lastWriteTime = filetimeToEpochMillis(packet.readULongLE(bodyOffset + 24))
        val changeTime = filetimeToEpochMillis(packet.readULongLE(bodyOffset + 32))
        val allocationSize = packet.readULongLE(bodyOffset + 40).toLong()
        val endOfFile = packet.readULongLE(bodyOffset + 48).toLong()
        val fileAttributes = packet.readUIntLE(bodyOffset + 56)
        val persistentId = packet.readULongLE(bodyOffset + 64)
        val volatileId = packet.readULongLE(bodyOffset + 72)

        return CreateResponse(
            fileId = SmbFileId(persistentId, volatileId),
            metadata = SmbFileMetadata(
                size = endOfFile,
                allocationSize = allocationSize,
                fileAttributes = fileAttributes,
                creationTimeMillis = creationTime,
                lastAccessTimeMillis = lastAccessTime,
                lastWriteTimeMillis = lastWriteTime,
                changeTimeMillis = changeTime,
            )
        )
    }

    fun buildCloseRequest(
        messageId: ULong,
        sessionId: ULong,
        treeId: UInt,
        fileId: SmbFileId,
    ): ByteArray {
        val packet = ByteArray(SmbHeader.SIZE + 24)
        val header = SmbHeader.withTreeId(
            command = SmbCommand.CLOSE,
            messageId = messageId,
            treeId = treeId,
            sessionId = sessionId,
        )
        header.encodeInto(packet, 0)

        val bodyOffset = SmbHeader.SIZE
        packet.writeUShortLE(bodyOffset, 24u)
        packet.writeUShortLE(bodyOffset + 2, 0u) // Flags = 0
        packet.writeUIntLE(bodyOffset + 4, 0u) // Reserved
        packet.writeULongLE(bodyOffset + 8, fileId.persistent)
        packet.writeULongLE(bodyOffset + 16, fileId.volatile)
        return packet
    }

    fun buildFlushRequest(
        messageId: ULong,
        sessionId: ULong,
        treeId: UInt,
        fileId: SmbFileId,
    ): ByteArray {
        val packet = ByteArray(SmbHeader.SIZE + 24)
        val header = SmbHeader.withTreeId(
            command = SmbCommand.FLUSH,
            messageId = messageId,
            treeId = treeId,
            sessionId = sessionId,
        )
        header.encodeInto(packet, 0)

        val bodyOffset = SmbHeader.SIZE
        packet.writeUShortLE(bodyOffset, 24u)
        packet.writeUShortLE(bodyOffset + 2, 0u)
        packet.writeUIntLE(bodyOffset + 4, 0u)
        packet.writeULongLE(bodyOffset + 8, fileId.persistent)
        packet.writeULongLE(bodyOffset + 16, fileId.volatile)
        return packet
    }

    // =========================================================================
    // 5. QUERY_DIRECTORY (0x000E)
    // =========================================================================

    fun buildQueryDirectoryRequest(
        messageId: ULong,
        sessionId: ULong,
        treeId: UInt,
        fileId: SmbFileId,
        searchPattern: String = "*",
        flags: UByte = 0u,
        outputBufferLength: Int = 65536,
    ): ByteArray {
        val patternBytes = searchPattern.encodeToUtf16LE()
        val bodyFixedSize = 32
        val payload = if (patternBytes.isEmpty()) ByteArray(2) else patternBytes
        val credits = maxOf(1, (outputBufferLength + 65535) / 65536).toUShort()

        val packet = ByteArray(SmbHeader.SIZE + bodyFixedSize + payload.size)
        val header = SmbHeader.withTreeId(
            command = SmbCommand.QUERY_DIRECTORY,
            messageId = messageId,
            treeId = treeId,
            sessionId = sessionId,
            creditCharge = credits,
            creditRequest = maxOf(credits, 31u.toUShort()),
        )
        header.encodeInto(packet, 0)

        val bodyOffset = SmbHeader.SIZE
        packet.writeUShortLE(bodyOffset, 33u) // StructureSize = 33
        packet[bodyOffset + 2] = 0x25 // FileIdBothDirectoryInformation (0x25)
        packet[bodyOffset + 3] = flags.toByte()
        packet.writeUIntLE(bodyOffset + 4, 0u) // FileIndex = 0
        packet.writeULongLE(bodyOffset + 8, fileId.persistent)
        packet.writeULongLE(bodyOffset + 16, fileId.volatile)
        packet.writeUShortLE(bodyOffset + 24, (SmbHeader.SIZE + bodyFixedSize).toUShort()) // FileNameOffset = 96
        packet.writeUShortLE(bodyOffset + 26, patternBytes.size.toUShort())
        packet.writeUIntLE(bodyOffset + 28, outputBufferLength.toUInt())

        payload.copyInto(packet, SmbHeader.SIZE + bodyFixedSize)
        return packet
    }

    /**
     * QUERY_DIRECTORY レスポンスからエントリ一覧を解析する。
     * `STATUS_NO_MORE_FILES` の場合は空リストを返す。
     */
    fun parseQueryDirectoryResponse(packet: ByteArray, excludeDotEntries: Boolean = true): List<SmbDirectoryEntry>? {
        val header = SmbHeader.decode(packet)
        if (header.status == NtStatus.STATUS_NO_MORE_FILES) {
            return null
        }
        if (header.status != NtStatus.STATUS_SUCCESS) {
            throw SmbException(header.status, "QUERY_DIRECTORY failed with ${NtStatus.nameOf(header.status)}")
        }
        requireBodySize(packet, header, SmbCommand.QUERY_DIRECTORY, 8)

        val bodyOffset = SmbHeader.SIZE
        val outBufOffset = packet.readUShortLE(bodyOffset + 2).toInt()
        val outBufLen = packet.readUIntLE(bodyOffset + 4).toInt()
        if (outBufLen <= 0 || outBufOffset + outBufLen > packet.size) {
            return emptyList()
        }

        val result = mutableListOf<SmbDirectoryEntry>()
        var entryPos = outBufOffset
        val endPos = outBufOffset + outBufLen

        while (entryPos + 104 <= endPos) {
            val nextEntryOffset = packet.readUIntLE(entryPos).toInt()
            val creationTime = filetimeToEpochMillis(packet.readULongLE(entryPos + 8))
            val lastAccessTime = filetimeToEpochMillis(packet.readULongLE(entryPos + 16))
            val lastWriteTime = filetimeToEpochMillis(packet.readULongLE(entryPos + 24))
            val changeTime = filetimeToEpochMillis(packet.readULongLE(entryPos + 32))
            val endOfFile = packet.readULongLE(entryPos + 40).toLong()
            val allocationSize = packet.readULongLE(entryPos + 48).toLong()
            val fileAttributes = packet.readUIntLE(entryPos + 56)
            val fileNameLength = packet.readUIntLE(entryPos + 60).toInt()
            val fileId = packet.readULongLE(entryPos + 96)

            val nameStart = entryPos + 104
            if (nameStart + fileNameLength <= endPos) {
                val name = packet.decodeFromUtf16LE(nameStart, fileNameLength)
                if (!excludeDotEntries || (name != "." && name != "..")) {
                    result.add(
                        SmbDirectoryEntry(
                            name = name,
                            size = endOfFile,
                            allocationSize = allocationSize,
                            fileAttributes = fileAttributes,
                            creationTimeMillis = creationTime,
                            lastAccessTimeMillis = lastAccessTime,
                            lastWriteTimeMillis = lastWriteTime,
                            changeTimeMillis = changeTime,
                            fileId = fileId,
                        )
                    )
                }
            }

            if (nextEntryOffset == 0) break
            entryPos += nextEntryOffset
        }

        return result
    }

    // =========================================================================
    // 6. READ (0x0008) & WRITE (0x0009)
    // =========================================================================

    fun buildReadRequest(
        messageId: ULong,
        sessionId: ULong,
        treeId: UInt,
        fileId: SmbFileId,
        offset: Long,
        length: Int,
    ): ByteArray {
        val credits = maxOf(1, (length + 65535) / 65536).toUShort()
        val packet = ByteArray(SmbHeader.SIZE + 49)
        val header = SmbHeader.withTreeId(
            command = SmbCommand.READ,
            messageId = messageId,
            treeId = treeId,
            sessionId = sessionId,
            creditCharge = credits,
            creditRequest = maxOf(credits, 31u.toUShort()),
        )
        header.encodeInto(packet, 0)

        val bodyOffset = SmbHeader.SIZE
        packet.writeUShortLE(bodyOffset, 49u) // StructureSize = 49
        packet[bodyOffset + 2] = 0x50 // Padding = 80
        packet[bodyOffset + 3] = 0 // Flags = 0
        packet.writeUIntLE(bodyOffset + 4, length.toUInt())
        packet.writeULongLE(bodyOffset + 8, offset.toULong())
        packet.writeULongLE(bodyOffset + 16, fileId.persistent)
        packet.writeULongLE(bodyOffset + 24, fileId.volatile)
        packet.writeUIntLE(bodyOffset + 32, 0u) // MinimumCount = 0
        packet.writeUIntLE(bodyOffset + 36, 0u) // Channel = 0
        packet.writeUIntLE(bodyOffset + 40, 0u) // RemainingBytes = 0
        packet.writeUShortLE(bodyOffset + 44, 0u) // ReadChannelInfoOffset = 0
        packet.writeUShortLE(bodyOffset + 46, 0u) // ReadChannelInfoLength = 0
        packet[bodyOffset + 48] = 0 // Buffer[0]
        return packet
    }

    fun parseReadResponse(packet: ByteArray): ByteArray {
        val header = SmbHeader.decode(packet)
        if (header.status == NtStatus.STATUS_END_OF_FILE) {
            return ByteArray(0)
        }
        if (header.status != NtStatus.STATUS_SUCCESS) {
            throw SmbException(header.status, "READ failed with ${NtStatus.nameOf(header.status)}")
        }
        requireBodySize(packet, header, SmbCommand.READ, 16)
        val bodyOffset = SmbHeader.SIZE
        val dataOffset = packet[bodyOffset + 2].toInt() and 0xFF
        val dataLength = packet.readUIntLE(bodyOffset + 4).toInt()
        if (dataLength <= 0 || dataOffset + dataLength > packet.size) {
            return ByteArray(0)
        }
        return packet.copyOfRange(dataOffset, dataOffset + dataLength)
    }

    fun buildWriteRequest(
        messageId: ULong,
        sessionId: ULong,
        treeId: UInt,
        fileId: SmbFileId,
        offset: Long,
        data: ByteArray,
        startIndex: Int = 0,
        length: Int = data.size - startIndex,
    ): ByteArray {
        val credits = maxOf(1, (length + 65535) / 65536).toUShort()
        val bodyFixedSize = 48
        val packet = ByteArray(SmbHeader.SIZE + bodyFixedSize + maxOf(1, length))
        val header = SmbHeader.withTreeId(
            command = SmbCommand.WRITE,
            messageId = messageId,
            treeId = treeId,
            sessionId = sessionId,
            creditCharge = credits,
            creditRequest = maxOf(credits, 31u.toUShort()),
        )
        header.encodeInto(packet, 0)

        val bodyOffset = SmbHeader.SIZE
        packet.writeUShortLE(bodyOffset, 49u) // StructureSize = 49
        packet.writeUShortLE(bodyOffset + 2, (SmbHeader.SIZE + bodyFixedSize).toUShort()) // DataOffset = 112
        packet.writeUIntLE(bodyOffset + 4, length.toUInt())
        packet.writeULongLE(bodyOffset + 8, offset.toULong())
        packet.writeULongLE(bodyOffset + 16, fileId.persistent)
        packet.writeULongLE(bodyOffset + 24, fileId.volatile)
        packet.writeUIntLE(bodyOffset + 32, 0u) // Channel = 0
        packet.writeUIntLE(bodyOffset + 36, 0u) // RemainingBytes = 0
        packet.writeUShortLE(bodyOffset + 40, 0u) // WriteChannelInfoOffset = 0
        packet.writeUShortLE(bodyOffset + 42, 0u) // WriteChannelInfoLength = 0
        packet.writeUIntLE(bodyOffset + 44, 0u) // Flags = 0

        if (length > 0) {
            data.copyInto(packet, SmbHeader.SIZE + bodyFixedSize, startIndex, startIndex + length)
        }
        return packet
    }

    fun parseWriteResponse(packet: ByteArray): Int {
        val header = SmbHeader.decode(packet)
        if (header.status != NtStatus.STATUS_SUCCESS) {
            throw SmbException(header.status, "WRITE failed with ${NtStatus.nameOf(header.status)}")
        }
        requireBodySize(packet, header, SmbCommand.WRITE, 8)
        return packet.readUIntLE(SmbHeader.SIZE + 4).toInt()
    }

    // =========================================================================
    // 7. LOCK (0x000A)
    // =========================================================================

    fun buildLockRequest(
        messageId: ULong,
        sessionId: ULong,
        treeId: UInt,
        fileId: SmbFileId,
        offset: Long,
        length: Long,
        flags: UInt,
    ): ByteArray {
        val packet = ByteArray(SmbHeader.SIZE + 48)
        val header = SmbHeader.withTreeId(
            command = SmbCommand.LOCK,
            messageId = messageId,
            treeId = treeId,
            sessionId = sessionId,
        )
        header.encodeInto(packet, 0)

        val bodyOffset = SmbHeader.SIZE
        packet.writeUShortLE(bodyOffset, 48u) // StructureSize = 48
        packet.writeUShortLE(bodyOffset + 2, 1u) // LockCount = 1
        packet.writeUIntLE(bodyOffset + 4, 0u) // LockSequenceNumber = 0
        packet.writeULongLE(bodyOffset + 8, fileId.persistent)
        packet.writeULongLE(bodyOffset + 16, fileId.volatile)

        // SMB2_LOCK_ELEMENT (24 bytes)
        packet.writeULongLE(bodyOffset + 24, offset.toULong())
        packet.writeULongLE(bodyOffset + 32, length.toULong())
        packet.writeUIntLE(bodyOffset + 40, flags)
        packet.writeUIntLE(bodyOffset + 44, 0u) // Reserved
        return packet
    }

    fun parseSimpleSuccessResponse(packet: ByteArray, commandName: String) {
        val header = SmbHeader.decode(packet)
        if (header.status != NtStatus.STATUS_SUCCESS) {
            throw SmbException(header.status, "$commandName failed with ${NtStatus.nameOf(header.status)}")
        }
    }

    // =========================================================================
    // 8. SET_INFO (0x0011)
    // =========================================================================

    fun buildSetInfoRequest(
        messageId: ULong,
        sessionId: ULong,
        treeId: UInt,
        fileId: SmbFileId,
        fileInfoClass: UByte,
        infoBuffer: ByteArray,
    ): ByteArray {
        val bodyFixedSize = 32
        val packet = ByteArray(SmbHeader.SIZE + bodyFixedSize + infoBuffer.size)
        val header = SmbHeader.withTreeId(
            command = SmbCommand.SET_INFO,
            messageId = messageId,
            treeId = treeId,
            sessionId = sessionId,
        )
        header.encodeInto(packet, 0)

        val bodyOffset = SmbHeader.SIZE
        packet.writeUShortLE(bodyOffset, 33u) // StructureSize = 33
        packet[bodyOffset + 2] = 0x01 // InfoType = SMB2_0_INFO_FILE (1)
        packet[bodyOffset + 3] = fileInfoClass.toByte()
        packet.writeUIntLE(bodyOffset + 4, infoBuffer.size.toUInt())
        packet.writeUShortLE(bodyOffset + 8, (SmbHeader.SIZE + bodyFixedSize).toUShort()) // BufferOffset = 96
        packet.writeUShortLE(bodyOffset + 10, 0u) // Reserved
        packet.writeUIntLE(bodyOffset + 12, 0u) // AdditionalInformation = 0
        packet.writeULongLE(bodyOffset + 16, fileId.persistent)
        packet.writeULongLE(bodyOffset + 24, fileId.volatile)

        infoBuffer.copyInto(packet, SmbHeader.SIZE + bodyFixedSize)
        return packet
    }

    /**
     * `FileDispositionInformation` (Class 13): ファイルまたは空ディレクトリの削除フラグ。
     */
    fun buildFileDispositionPayload(deletePending: Boolean = true): ByteArray =
        byteArrayOf(if (deletePending) 1 else 0)

    /**
     * `FileRenameInformation` (Class 10): ファイルまたはディレクトリのリネーム・移動。
     */
    fun buildFileRenamePayload(newTargetPath: String, replaceIfExists: Boolean = true): ByteArray {
        val normalized = newTargetPath.trimStart('/', '\\').replace('/', '\\')
        val nameBytes = normalized.encodeToUtf16LE()
        val buf = ByteArray(20 + nameBytes.size)
        buf[0] = if (replaceIfExists) 1 else 0
        // 1..7 Reserved = 0, 8..15 RootDirectory = 0
        buf.writeUIntLE(16, nameBytes.size.toUInt())
        nameBytes.copyInto(buf, 20)
        return buf
    }

    /**
     * `FileEndOfFileInformation` (Class 20): ファイルサイズの変更・トランケート。
     */
    fun buildFileEndOfFilePayload(newSize: Long): ByteArray {
        val buf = ByteArray(8)
        buf.writeULongLE(0, newSize.toULong())
        return buf
    }

    // =========================================================================
    // 9. IOCTL (0x000B)
    // =========================================================================

    fun buildIoctlRequest(
        messageId: ULong,
        sessionId: ULong,
        treeId: UInt,
        fileId: SmbFileId,
        ctlCode: UInt,
        inputData: ByteArray,
        maxOutputResponse: Int = 65536,
    ): ByteArray {
        val bodyFixedSize = 56
        val credits = maxOf(1, (maxOf(inputData.size, maxOutputResponse) + 65535) / 65536).toUShort()
        val packet = ByteArray(SmbHeader.SIZE + bodyFixedSize + maxOf(1, inputData.size))
        val header = SmbHeader.withTreeId(
            command = SmbCommand.IOCTL,
            messageId = messageId,
            treeId = treeId,
            sessionId = sessionId,
            creditCharge = credits,
            creditRequest = maxOf(credits, 31u.toUShort()),
        )
        header.encodeInto(packet, 0)

        val bodyOffset = SmbHeader.SIZE
        packet.writeUShortLE(bodyOffset, 57u) // StructureSize = 57
        packet.writeUShortLE(bodyOffset + 2, 0u) // Reserved
        packet.writeUIntLE(bodyOffset + 4, ctlCode)
        packet.writeULongLE(bodyOffset + 8, fileId.persistent)
        packet.writeULongLE(bodyOffset + 16, fileId.volatile)
        packet.writeUIntLE(bodyOffset + 24, (SmbHeader.SIZE + bodyFixedSize).toUInt()) // InputOffset = 120
        packet.writeUIntLE(bodyOffset + 28, inputData.size.toUInt()) // InputCount
        packet.writeUIntLE(bodyOffset + 32, 0u) // MaxInputResponse = 0
        packet.writeUIntLE(bodyOffset + 36, 0u) // OutputOffset = 0
        packet.writeUIntLE(bodyOffset + 40, 0u) // OutputCount = 0
        packet.writeUIntLE(bodyOffset + 44, maxOutputResponse.toUInt())
        packet.writeUIntLE(bodyOffset + 48, 0x00000001u) // Flags = SMB2_0_IOCTL_IS_FSCTL (1)
        packet.writeUIntLE(bodyOffset + 52, 0u) // Reserved2

        if (inputData.isNotEmpty()) {
            inputData.copyInto(packet, SmbHeader.SIZE + bodyFixedSize)
        }
        return packet
    }

    fun parseIoctlResponse(packet: ByteArray): ByteArray {
        val header = SmbHeader.decode(packet)
        if (header.status != NtStatus.STATUS_SUCCESS && header.status != NtStatus.STATUS_BUFFER_OVERFLOW) {
            throw SmbException(header.status, "IOCTL failed with ${NtStatus.nameOf(header.status)}")
        }
        requireBodySize(packet, header, SmbCommand.IOCTL, 40)
        val bodyOffset = SmbHeader.SIZE
        val outputOffset = packet.readUIntLE(bodyOffset + 32).toInt()
        val outputCount = packet.readUIntLE(bodyOffset + 36).toInt()
        if (outputCount <= 0 || outputOffset + outputCount > packet.size) {
            return ByteArray(0)
        }
        return packet.copyOfRange(outputOffset, outputOffset + outputCount)
    }
}
