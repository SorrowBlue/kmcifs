package com.sorrowblue.kmcifs.sample

import com.sorrowblue.kmcifs.client.SmbEncryptionPolicy
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlin.random.Random

/**
 * サンプルアプリで保存・復元する SMB 接続設定。
 */
data class SmbSavedConnection(
    val host: String = "192.168.1.100",
    val port: Int = 445,
    val username: String = "",
    val password: String = "",
    val domain: String = "",
    val shareName: String = "",
    val directoryPath: String = "",
    val encryptionPolicy: SmbEncryptionPolicy = SmbEncryptionPolicy.NEGOTIATE,
)

/**
 * 接続設定のシリアライズと AES-128-GCM による暗号化・復号を担当するオブジェクト。
 *
 * 平文の設定データを UTF-8 バイナリへ変換した上で、12 バイトのランダム IV と 16 バイトの認証タグを付与して
 * Base64 文字列へエンコードする。改ざんや鍵の不一致があった場合は復号時に例外を送出する。
 */
object SmbCredentialCipher {

    private const val FORMAT_VERSION: Byte = 1
    private const val IV_LENGTH = 12
    private const val TAG_LENGTH = 16
    private val AAD = "kmcifs-sample-credentials-v1".encodeToByteArray()

    @OptIn(ExperimentalEncodingApi::class)
    fun encryptToBase64(
        connection: SmbSavedConnection,
        key16: ByteArray,
        iv: ByteArray = Random.Default.nextBytes(IV_LENGTH),
    ): String {
        require(key16.size == 16) { "AES-128 key must be 16 bytes" }
        require(iv.size == IV_LENGTH) { "GCM IV must be $IV_LENGTH bytes" }

        val plainBytes = serialize(connection)
        val (cipherBytes, tag) = Aes128Gcm.encrypt(
            key = key16,
            iv = iv,
            aad = AAD,
            plaintext = plainBytes,
        )

        val payload = ByteArray(1 + IV_LENGTH + TAG_LENGTH + cipherBytes.size)
        payload[0] = FORMAT_VERSION
        iv.copyInto(payload, destinationOffset = 1)
        tag.copyInto(payload, destinationOffset = 1 + IV_LENGTH)
        cipherBytes.copyInto(payload, destinationOffset = 1 + IV_LENGTH + TAG_LENGTH)
        return Base64.encode(payload)
    }

    @OptIn(ExperimentalEncodingApi::class)
    fun decryptFromBase64(encoded: String, key16: ByteArray): SmbSavedConnection {
        require(key16.size == 16) { "AES-128 key must be 16 bytes" }
        val payload = Base64.decode(encoded.trim())
        require(payload.size >= 1 + IV_LENGTH + TAG_LENGTH) { "Encrypted payload is too short" }
        require(payload[0] == FORMAT_VERSION) { "Unsupported credential payload version: ${payload[0]}" }

        val iv = payload.copyOfRange(1, 1 + IV_LENGTH)
        val tag = payload.copyOfRange(1 + IV_LENGTH, 1 + IV_LENGTH + TAG_LENGTH)
        val cipherBytes = payload.copyOfRange(1 + IV_LENGTH + TAG_LENGTH, payload.size)

        val plainBytes = Aes128Gcm.decrypt(
            key = key16,
            iv = iv,
            aad = AAD,
            ciphertext = cipherBytes,
            expectedTag = tag,
        )
        return deserialize(plainBytes)
    }

    fun serialize(connection: SmbSavedConnection): ByteArray {
        val fields = listOf(
            connection.host,
            connection.port.toString(),
            connection.username,
            connection.password,
            connection.domain,
            connection.shareName,
            connection.directoryPath,
            connection.encryptionPolicy.name,
        ).map { it.encodeToByteArray() }

        val totalSize = 4 + fields.sumOf { 4 + it.size }
        val buffer = ByteArray(totalSize)
        var offset = 0

        writeIntBE(buffer, offset, fields.size)
        offset += 4

        for (field in fields) {
            writeIntBE(buffer, offset, field.size)
            offset += 4
            field.copyInto(buffer, offset)
            offset += field.size
        }
        return buffer
    }

    fun deserialize(bytes: ByteArray): SmbSavedConnection {
        require(bytes.size >= 4) { "Corrupted credential data" }
        var offset = 0
        val count = readIntBE(bytes, offset)
        offset += 4
        require(count >= 7) { "Unexpected field count: $count" }

        val values = ArrayList<String>(count)
        for (i in 0 until count) {
            require(offset + 4 <= bytes.size) { "Corrupted credential field length" }
            val len = readIntBE(bytes, offset)
            offset += 4
            require(len >= 0 && offset + len <= bytes.size) { "Corrupted credential field content" }
            values.add(bytes.decodeToString(offset, offset + len))
            offset += len
        }

        val policyName = values.getOrNull(7).orEmpty()
        val policy = SmbEncryptionPolicy.entries.firstOrNull { it.name == policyName }
            ?: SmbEncryptionPolicy.NEGOTIATE

        return SmbSavedConnection(
            host = values[0],
            port = values[1].toIntOrNull() ?: 445,
            username = values[2],
            password = values[3],
            domain = values[4],
            shareName = values[5],
            directoryPath = values[6],
            encryptionPolicy = policy,
        )
    }

    private fun writeIntBE(buf: ByteArray, offset: Int, value: Int) {
        buf[offset] = ((value ushr 24) and 0xFF).toByte()
        buf[offset + 1] = ((value ushr 16) and 0xFF).toByte()
        buf[offset + 2] = ((value ushr 8) and 0xFF).toByte()
        buf[offset + 3] = (value and 0xFF).toByte()
    }

    private fun readIntBE(buf: ByteArray, offset: Int): Int {
        return ((buf[offset].toInt() and 0xFF) shl 24) or
            ((buf[offset + 1].toInt() and 0xFF) shl 16) or
            ((buf[offset + 2].toInt() and 0xFF) shl 8) or
            (buf[offset + 3].toInt() and 0xFF)
    }
}

/**
 * 共通コード内で完結する AES-128-GCM 実装。
 */
internal object Aes128Gcm {

    private val SBOX = intArrayOf(
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
    )

    private val RCON = intArrayOf(0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36)

    fun encrypt(key: ByteArray, iv: ByteArray, aad: ByteArray, plaintext: ByteArray): Pair<ByteArray, ByteArray> {
        val roundKeys = expandKey(key)
        val h = encryptBlock(roundKeys, ByteArray(16))

        val j0 = ByteArray(16)
        iv.copyInto(j0, 0, 0, 12)
        j0[15] = 1

        val ciphertext = ByteArray(plaintext.size)
        processCtr(roundKeys, j0, plaintext, ciphertext)
        val tag = computeTag(roundKeys, h, j0, aad, ciphertext)
        return ciphertext to tag
    }

    fun decrypt(key: ByteArray, iv: ByteArray, aad: ByteArray, ciphertext: ByteArray, expectedTag: ByteArray): ByteArray {
        val roundKeys = expandKey(key)
        val h = encryptBlock(roundKeys, ByteArray(16))

        val j0 = ByteArray(16)
        iv.copyInto(j0, 0, 0, 12)
        j0[15] = 1

        val computedTag = computeTag(roundKeys, h, j0, aad, ciphertext)
        var diff = 0
        for (i in 0 until 16) {
            diff = diff or (computedTag[i].toInt() xor expectedTag[i].toInt())
        }
        check(diff == 0) { "Credential decryption failed: authentication tag mismatch" }

        val plaintext = ByteArray(ciphertext.size)
        processCtr(roundKeys, j0, ciphertext, plaintext)
        return plaintext
    }

    private fun expandKey(key: ByteArray): ByteArray {
        val roundKeys = ByteArray(176)
        key.copyInto(roundKeys, 0, 0, 16)
        val temp = IntArray(4)
        var bytesGenerated = 16
        var rconIteration = 1
        while (bytesGenerated < 176) {
            for (i in 0 until 4) {
                temp[i] = roundKeys[bytesGenerated - 4 + i].toInt() and 0xFF
            }
            if (bytesGenerated % 16 == 0) {
                val k = temp[0]
                temp[0] = SBOX[temp[1]] xor RCON[rconIteration]
                temp[1] = SBOX[temp[2]]
                temp[2] = SBOX[temp[3]]
                temp[3] = SBOX[k]
                rconIteration++
            }
            for (i in 0 until 4) {
                roundKeys[bytesGenerated] = ((roundKeys[bytesGenerated - 16].toInt() and 0xFF) xor temp[i]).toByte()
                bytesGenerated++
            }
        }
        return roundKeys
    }

    private fun encryptBlock(roundKeys: ByteArray, input: ByteArray, output: ByteArray = ByteArray(16)): ByteArray {
        val s = IntArray(16)
        for (i in 0 until 16) {
            s[i] = (input[i].toInt() and 0xFF) xor (roundKeys[i].toInt() and 0xFF)
        }
        for (round in 1..9) {
            subBytesAndShiftRows(s)
            mixColumns(s)
            addRoundKey(s, roundKeys, round * 16)
        }
        subBytesAndShiftRows(s)
        addRoundKey(s, roundKeys, 160)
        for (i in 0 until 16) {
            output[i] = s[i].toByte()
        }
        return output
    }

    private fun subBytesAndShiftRows(s: IntArray) {
        for (i in 0 until 16) s[i] = SBOX[s[i]]
        val t1 = s[1]; s[1] = s[5]; s[5] = s[9]; s[9] = s[13]; s[13] = t1
        val t2a = s[2]; val t2b = s[6]; s[2] = s[10]; s[6] = s[14]; s[10] = t2a; s[14] = t2b
        val t3 = s[15]; s[15] = s[11]; s[11] = s[7]; s[7] = s[3]; s[3] = t3
    }

    private fun mixColumns(s: IntArray) {
        for (c in 0 until 4) {
            val i = c * 4
            val a0 = s[i]; val a1 = s[i + 1]; val a2 = s[i + 2]; val a3 = s[i + 3]
            val allXor = a0 xor a1 xor a2 xor a3
            s[i] = a0 xor allXor xor xtime(a0 xor a1)
            s[i + 1] = a1 xor allXor xor xtime(a1 xor a2)
            s[i + 2] = a2 xor allXor xor xtime(a2 xor a3)
            s[i + 3] = a3 xor allXor xor xtime(a3 xor a0)
        }
    }

    private fun xtime(x: Int): Int {
        val shifted = (x shl 1) and 0xFF
        return if ((x and 0x80) != 0) shifted xor 0x1B else shifted
    }

    private fun addRoundKey(s: IntArray, roundKeys: ByteArray, offset: Int) {
        for (i in 0 until 16) {
            s[i] = s[i] xor (roundKeys[offset + i].toInt() and 0xFF)
        }
    }

    private fun processCtr(roundKeys: ByteArray, j0: ByteArray, input: ByteArray, output: ByteArray) {
        val cb = j0.copyOf()
        val keystream = ByteArray(16)
        var counter = 2u
        var offset = 0
        while (offset < input.size) {
            cb[12] = ((counter shr 24) and 0xFFu).toByte()
            cb[13] = ((counter shr 16) and 0xFFu).toByte()
            cb[14] = ((counter shr 8) and 0xFFu).toByte()
            cb[15] = (counter and 0xFFu).toByte()
            encryptBlock(roundKeys, cb, keystream)
            val chunk = minOf(16, input.size - offset)
            for (i in 0 until chunk) {
                output[offset + i] = (input[offset + i].toInt() xor keystream[i].toInt()).toByte()
            }
            offset += 16
            counter++
        }
    }

    private fun computeTag(roundKeys: ByteArray, h: ByteArray, j0: ByteArray, aad: ByteArray, ciphertext: ByteArray): ByteArray {
        val y = ByteArray(16)
        ghashUpdate(y, h, aad)
        ghashUpdate(y, h, ciphertext)

        val lenBlock = ByteArray(16)
        val aadBits = aad.size.toULong() * 8uL
        val ctBits = ciphertext.size.toULong() * 8uL
        for (i in 0 until 8) {
            lenBlock[i] = ((aadBits shr ((7 - i) * 8)) and 0xFFuL).toByte()
            lenBlock[8 + i] = ((ctBits shr ((7 - i) * 8)) and 0xFFuL).toByte()
        }
        for (i in 0 until 16) {
            y[i] = (y[i].toInt() xor lenBlock[i].toInt()).toByte()
        }
        gfMultiply(y, h)

        val s = encryptBlock(roundKeys, j0)
        for (i in 0 until 16) {
            y[i] = (y[i].toInt() xor s[i].toInt()).toByte()
        }
        return y
    }

    private fun ghashUpdate(y: ByteArray, h: ByteArray, data: ByteArray) {
        var offset = 0
        while (offset < data.size) {
            val chunk = minOf(16, data.size - offset)
            for (i in 0 until chunk) {
                y[i] = (y[i].toInt() xor data[offset + i].toInt()).toByte()
            }
            gfMultiply(y, h)
            offset += 16
        }
    }

    private fun gfMultiply(x: ByteArray, y: ByteArray) {
        var z0 = 0uL
        var z1 = 0uL
        var v0 = readULongBE(y, 0)
        var v1 = readULongBE(y, 8)

        for (i in 0 until 16) {
            val byteVal = x[i].toInt() and 0xFF
            for (bit in 7 downTo 0) {
                if (((byteVal ushr bit) and 1) != 0) {
                    z0 = z0 xor v0
                    z1 = z1 xor v1
                }
                val lsb = (v1 and 1uL) != 0uL
                v1 = (v1 shr 1) or (v0 shl 63)
                v0 = v0 shr 1
                if (lsb) {
                    v0 = v0 xor 0xe100000000000000uL
                }
            }
        }
        writeULongBE(x, 0, z0)
        writeULongBE(x, 8, z1)
    }

    private fun readULongBE(buf: ByteArray, offset: Int): ULong {
        var v = 0uL
        for (i in 0 until 8) {
            v = (v shl 8) or (buf[offset + i].toULong() and 0xFFuL)
        }
        return v
    }

    private fun writeULongBE(buf: ByteArray, offset: Int, value: ULong) {
        for (i in 0 until 8) {
            buf[offset + i] = ((value shr ((7 - i) * 8)) and 0xFFuL).toByte()
        }
    }
}
