package com.sorrowblue.kmcifs.client.protocol

import com.sorrowblue.kmcifs.client.crypto.Aes
import com.sorrowblue.kmcifs.client.crypto.Sha256
import com.sorrowblue.kmcifs.client.protocol.ByteUtils.readUIntLE
import com.sorrowblue.kmcifs.client.protocol.ByteUtils.readULongLE
import com.sorrowblue.kmcifs.client.protocol.ByteUtils.readUShortLE
import com.sorrowblue.kmcifs.client.protocol.ByteUtils.writeUIntLE
import com.sorrowblue.kmcifs.client.protocol.ByteUtils.writeULongLE
import com.sorrowblue.kmcifs.client.protocol.ByteUtils.writeUShortLE

/**
 * SMB2 / SMB3 コマンドコード。
 */
enum class SmbCommand(val code: UShort) {
    NEGOTIATE(0x0000u),
    SESSION_SETUP(0x0001u),
    LOGOFF(0x0002u),
    TREE_CONNECT(0x0003u),
    TREE_DISCONNECT(0x0004u),
    CREATE(0x0005u),
    CLOSE(0x0006u),
    FLUSH(0x0007u),
    READ(0x0008u),
    WRITE(0x0009u),
    LOCK(0x000Au),
    IOCTL(0x000Bu),
    CANCEL(0x000Cu),
    ECHO(0x000Du),
    QUERY_DIRECTORY(0x000Eu),
    CHANGE_NOTIFY(0x000Fu),
    QUERY_INFO(0x0010u),
    SET_INFO(0x0011u),
    OPLOCK_BREAK(0x0012u);

    companion object {
        fun fromCode(code: UShort): SmbCommand? = entries.firstOrNull { it.code == code }
    }
}

/**
 * 64 バイト固定長の SMB2 パケットヘッダ。
 */
internal data class SmbHeader(
    val creditCharge: UShort = 1u,
    val status: UInt = 0u,
    val command: SmbCommand,
    val creditRequestResponse: UShort = 31u,
    val flags: UInt = 0u,
    val nextCommand: UInt = 0u,
    val messageId: ULong,
    val asyncIdOrTreeId: ULong = 0uL,
    val sessionId: ULong = 0uL,
    val signature: ByteArray = ByteArray(16),
) {
    val isResponse: Boolean
        get() = (flags and SMB2_FLAGS_SERVER_TO_REDIR) != 0u

    val isAsync: Boolean
        get() = (flags and SMB2_FLAGS_ASYNC_COMMAND) != 0u

    val isSigned: Boolean
        get() = (flags and SMB2_FLAGS_SIGNED) != 0u

    val treeId: UInt
        get() = (asyncIdOrTreeId shr 32).toUInt()

    fun encodeInto(buffer: ByteArray, offset: Int = 0) {
        PROTOCOL_ID.copyInto(buffer, offset)
        buffer.writeUShortLE(offset + 4, 64u) // StructureSize = 64
        buffer.writeUShortLE(offset + 6, creditCharge)
        buffer.writeUIntLE(offset + 8, status)
        buffer.writeUShortLE(offset + 12, command.code)
        buffer.writeUShortLE(offset + 14, creditRequestResponse)
        buffer.writeUIntLE(offset + 16, flags)
        buffer.writeUIntLE(offset + 20, nextCommand)
        buffer.writeULongLE(offset + 24, messageId)
        if (isAsync) {
            buffer.writeULongLE(offset + 32, asyncIdOrTreeId)
        } else {
            buffer.writeUIntLE(offset + 32, 0u) // Reserved / ProcessId
            buffer.writeUIntLE(offset + 36, treeId)
        }
        buffer.writeULongLE(offset + 40, sessionId)
        signature.copyInto(buffer, offset + 48, 0, 16)
    }

    companion object {
        const val SIZE = 64
        val PROTOCOL_ID = byteArrayOf(0xFE.toByte(), 'S'.code.toByte(), 'M'.code.toByte(), 'B'.code.toByte())

        const val SMB2_FLAGS_SERVER_TO_REDIR: UInt = 0x00000001u
        const val SMB2_FLAGS_ASYNC_COMMAND: UInt = 0x00000002u
        const val SMB2_FLAGS_RELATED_OPERATIONS: UInt = 0x00000004u
        const val SMB2_FLAGS_SIGNED: UInt = 0x00000008u

        fun withTreeId(
            command: SmbCommand,
            messageId: ULong,
            treeId: UInt = 0u,
            sessionId: ULong = 0uL,
            flags: UInt = 0u,
            creditCharge: UShort = 1u,
            creditRequest: UShort = 31u,
        ): SmbHeader = SmbHeader(
            creditCharge = creditCharge,
            command = command,
            creditRequestResponse = creditRequest,
            flags = flags,
            messageId = messageId,
            asyncIdOrTreeId = (treeId.toULong() shl 32),
            sessionId = sessionId,
        )

        fun decode(buffer: ByteArray, offset: Int = 0): SmbHeader {
            require(buffer.size - offset >= SIZE) { "Buffer too small for SMB2 header" }
            for (i in 0 until 4) {
                require(buffer[offset + i] == PROTOCOL_ID[i]) { "Invalid SMB2 header magic at offset $offset" }
            }
            val structSize = buffer.readUShortLE(offset + 4)
            require(structSize == 64u.toUShort()) { "Invalid SMB2 header StructureSize: $structSize" }

            val creditCharge = buffer.readUShortLE(offset + 6)
            val status = buffer.readUIntLE(offset + 8)
            val cmdCode = buffer.readUShortLE(offset + 12)
            val command = SmbCommand.fromCode(cmdCode)
                ?: throw IllegalArgumentException("Unknown SMB2 command code: 0x${cmdCode.toString(16)}")
            val creditReqResp = buffer.readUShortLE(offset + 14)
            val flags = buffer.readUIntLE(offset + 16)
            val nextCommand = buffer.readUIntLE(offset + 20)
            val messageId = buffer.readULongLE(offset + 24)
            val asyncIdOrTreeId = if ((flags and SMB2_FLAGS_ASYNC_COMMAND) != 0u) {
                buffer.readULongLE(offset + 32)
            } else {
                val treeId = buffer.readUIntLE(offset + 36)
                treeId.toULong() shl 32
            }
            val sessionId = buffer.readULongLE(offset + 40)
            val signature = buffer.copyOfRange(offset + 48, offset + 64)

            return SmbHeader(
                creditCharge = creditCharge,
                status = status,
                command = command,
                creditRequestResponse = creditReqResp,
                flags = flags,
                nextCommand = nextCommand,
                messageId = messageId,
                asyncIdOrTreeId = asyncIdOrTreeId,
                sessionId = sessionId,
                signature = signature,
            )
        }

        /**
         * SMB パケット（ヘッダ + ボディ）の署名フィールド (offset 48..63) を計算して書き込む。
         * - SMB 2.0.2 / 2.1: HMAC-SHA256 の先頭 16 バイト
         * - SMB 3.x: AES-128-CMAC (16 バイト)
         */
        fun signPacket(packet: ByteArray, dialect: SmbDialect, signingKey: ByteArray) {
            val currentFlags = packet.readUIntLE(16)
            packet.writeUIntLE(16, currentFlags or SMB2_FLAGS_SIGNED)
            for (i in 48 until 64) {
                packet[i] = 0
            }
            val sig = computeSignature(packet, dialect, signingKey)
            sig.copyInto(packet, 48, 0, 16)
        }

        /**
         * 受信した SMB パケットの署名を検証する。
         */
        fun verifyPacketSignature(packet: ByteArray, dialect: SmbDialect, signingKey: ByteArray): Boolean {
            val receivedSig = packet.copyOfRange(48, 64)
            val copy = packet.copyOf()
            for (i in 48 until 64) {
                copy[i] = 0
            }
            val expectedSig = computeSignature(copy, dialect, signingKey)
            return Aes.constantTimeEquals(receivedSig, expectedSig)
        }

        private fun computeSignature(zeroedPacket: ByteArray, dialect: SmbDialect, signingKey: ByteArray): ByteArray {
            val key16 = if (signingKey.size >= 16) signingKey.copyOfRange(0, 16) else signingKey.copyOf(16)
            return if (dialect.isSmb3) {
                Aes.cmac(key16, zeroedPacket)
            } else {
                Sha256.hmac(key16, zeroedPacket).copyOfRange(0, 16)
            }
        }
    }
}
