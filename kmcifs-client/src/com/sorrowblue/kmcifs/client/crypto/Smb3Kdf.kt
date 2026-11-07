package com.sorrowblue.kmcifs.client.crypto

import com.sorrowblue.kmcifs.client.protocol.SmbDialect

/**
 * SMB 3.0 / 3.0.2 / 3.1.1 用の NIST SP800-108 Counter Mode (HMAC-SHA256) 鍵導出実装。
 */
internal object Smb3Kdf {

    data class DerivedKeys(
        val signingKey: ByteArray,
        val encryptionKey: ByteArray, // Client-to-Server (ServerInKey)
        val decryptionKey: ByteArray, // Server-to-Client (ServerOutKey)
    )

    /**
     * NTLMSSP で導出された 16 バイトの SessionKey から、SMB 3.x の署名鍵・暗号化鍵・復号鍵を導出する。
     */
    fun deriveKeys(
        dialect: SmbDialect,
        sessionKey: ByteArray,
        preauthIntegrityHash: ByteArray? = null,
    ): DerivedKeys {
        val key16 = if (sessionKey.size >= 16) sessionKey.copyOfRange(0, 16) else sessionKey.copyOf(16)

        return if (dialect == SmbDialect.SMB_3_1_1) {
            val hash = requireNotNull(preauthIntegrityHash) {
                "PreauthIntegrityHash is required for SMB 3.1.1 key derivation"
            }
            DerivedKeys(
                signingKey = kdfSp800108(key16, "SMBSigningKey\u0000".encodeToByteArray(), hash),
                encryptionKey = kdfSp800108(key16, "SMBC2SCipherKey\u0000".encodeToByteArray(), hash),
                decryptionKey = kdfSp800108(key16, "SMBS2CCipherKey\u0000".encodeToByteArray(), hash),
            )
        } else {
            // SMB 3.0 / 3.0.2
            DerivedKeys(
                signingKey = kdfSp800108(
                    key16,
                    "SMB2AESCMAC\u0000".encodeToByteArray(),
                    "SmbSign\u0000".encodeToByteArray()
                ),
                encryptionKey = kdfSp800108(
                    key16,
                    "SMB2AESCCM\u0000".encodeToByteArray(),
                    "ServerIn \u0000".encodeToByteArray()
                ),
                decryptionKey = kdfSp800108(
                    key16,
                    "SMB2AESCCM\u0000".encodeToByteArray(),
                    "ServerOut\u0000".encodeToByteArray()
                ),
            )
        }
    }

    /**
     * NIST SP800-108 Counter Mode KDF (r = 32 bits big-endian, L = 128 bits big-endian).
     * Input = [i]_4 || Label || 0x00 || Context || [L]_4
     */
    fun kdfSp800108(ki: ByteArray, labelWithNull: ByteArray, context: ByteArray, bitLength: Int = 128): ByteArray {
        val counter = byteArrayOf(0x00, 0x00, 0x00, 0x01)
        val separator = byteArrayOf(0x00)
        val lengthBytes = byteArrayOf(
            ((bitLength ushr 24) and 0xFF).toByte(),
            ((bitLength ushr 16) and 0xFF).toByte(),
            ((bitLength ushr 8) and 0xFF).toByte(),
            (bitLength and 0xFF).toByte()
        )
        val hmacOut = Sha256.hmac(ki, counter, labelWithNull, separator, context, lengthBytes)
        return hmacOut.copyOfRange(0, bitLength / 8)
    }
}
