package com.sorrowblue.kmcifs.client.protocol

import com.sorrowblue.kmcifs.client.crypto.Aes
import com.sorrowblue.kmcifs.client.protocol.ByteUtils.readUIntLE
import com.sorrowblue.kmcifs.client.protocol.ByteUtils.readULongLE
import com.sorrowblue.kmcifs.client.protocol.ByteUtils.readUShortLE
import com.sorrowblue.kmcifs.client.protocol.ByteUtils.writeUIntLE
import com.sorrowblue.kmcifs.client.protocol.ByteUtils.writeULongLE
import com.sorrowblue.kmcifs.client.protocol.ByteUtils.writeUShortLE
import kotlin.random.Random

/**
 * SMB 3.x の暗号化通信で使用される 52 バイトの SMB2_TRANSFORM_HEADER (`0xFD 'S' 'M' 'B'`)。
 */
internal object SmbTransformHeader {

    const val SIZE = 52
    val PROTOCOL_ID = byteArrayOf(0xFD.toByte(), 'S'.code.toByte(), 'M'.code.toByte(), 'B'.code.toByte())

    fun isTransformPacket(packet: ByteArray): Boolean {
        if (packet.size < SIZE) return false
        for (i in 0 until 4) {
            if (packet[i] != PROTOCOL_ID[i]) return false
        }
        return true
    }

    /**
     * 平文の SMB2 パケットを SMB3 Transform Header でラップして AEAD 暗号化する。
     */
    fun encryptPacket(
        plainSmbPacket: ByteArray,
        sessionId: ULong,
        cipherId: SmbCipherId,
        encryptionKey: ByteArray,
        nonceBytes: ByteArray? = null,
    ): ByteArray {
        val nonceSize = if (cipherId == SmbCipherId.AES_128_GCM) 12 else 11
        val rawNonce = nonceBytes ?: Random.Default.nextBytes(nonceSize)
        require(rawNonce.size == nonceSize) { "Nonce size must be $nonceSize bytes for $cipherId" }

        // Transform Header (52 bytes):
        // 0..3: ProtocolId (0xFD 'S' 'M' 'B')
        // 4..19: Signature (16 bytes)
        // 20..35: Nonce (16 bytes, padded with zeros)
        // 36..39: OriginalMessageSize (4 bytes)
        // 40..41: Reserved (2 bytes = 0)
        // 42..43: Flags / EncryptionAlgorithm (2 bytes = 0x0001)
        // 44..51: SessionId (8 bytes)
        val header = ByteArray(SIZE)
        PROTOCOL_ID.copyInto(header, 0)
        rawNonce.copyInto(header, 20, 0, nonceSize)
        header.writeUIntLE(36, plainSmbPacket.size.toUInt())
        header.writeUShortLE(40, 0u)
        header.writeUShortLE(42, 0x0001u)
        header.writeULongLE(44, sessionId)

        // AAD is bytes 20..51 of Transform Header (32 bytes)
        val aad = header.copyOfRange(20, 52)

        val (ciphertext, tag) = when (cipherId) {
            SmbCipherId.AES_128_CCM -> Aes.ccmEncrypt(encryptionKey, rawNonce, aad, plainSmbPacket)
            SmbCipherId.AES_128_GCM -> Aes.gcmEncrypt(encryptionKey, rawNonce, aad, plainSmbPacket)
        }

        tag.copyInto(header, 4, 0, 16)

        val out = ByteArray(SIZE + ciphertext.size)
        header.copyInto(out, 0)
        ciphertext.copyInto(out, SIZE)
        return out
    }

    /**
     * SMB3 Transform Header 付きパケットを復号・認証検証し、平文の SMB2 パケットを取り出す。
     */
    fun decryptPacket(
        transformPacket: ByteArray,
        cipherId: SmbCipherId,
        decryptionKey: ByteArray,
    ): ByteArray {
        require(isTransformPacket(transformPacket)) { "Packet does not start with SMB3 Transform Header" }
        val signature = transformPacket.copyOfRange(4, 20)
        val nonceSize = if (cipherId == SmbCipherId.AES_128_GCM) 12 else 11
        val rawNonce = transformPacket.copyOfRange(20, 20 + nonceSize)
        val originalSize = transformPacket.readUIntLE(36).toInt()
        val flags = transformPacket.readUShortLE(42)
        require(flags == 0x0001u.toUShort()) { "Unsupported SMB3 Transform Header flags: 0x${flags.toString(16)}" }

        val aad = transformPacket.copyOfRange(20, 52)
        require(originalSize >= SmbHeader.SIZE && originalSize <= transformPacket.size - SIZE) {
            "Transform packet invalid or truncated: originalSize=$originalSize, packetSize=${transformPacket.size}"
        }
        val ciphertext = if (transformPacket.size == SIZE + originalSize) {
            transformPacket.copyOfRange(SIZE, transformPacket.size)
        } else {
            transformPacket.copyOfRange(SIZE, SIZE + originalSize)
        }

        return when (cipherId) {
            SmbCipherId.AES_128_CCM -> Aes.ccmDecrypt(decryptionKey, rawNonce, aad, ciphertext, signature)
            SmbCipherId.AES_128_GCM -> Aes.gcmDecrypt(decryptionKey, rawNonce, aad, ciphertext, signature)
        }
    }
}
