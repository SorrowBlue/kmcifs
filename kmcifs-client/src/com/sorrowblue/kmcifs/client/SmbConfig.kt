package com.sorrowblue.kmcifs.client

import com.sorrowblue.kmcifs.client.protocol.SmbCipherId
import com.sorrowblue.kmcifs.client.protocol.SmbDialect

/**
 * Policy for applying SMB3 packet encryption (`SMB2_TRANSFORM_HEADER`).
 */
enum class SmbEncryptionPolicy {
    /**
     * Encrypts traffic when required by the server (session or share) or when
     * [SmbConfig.preferEncryption] is enabled and the server supports SMB 3.x encryption.
     */
    NEGOTIATE,

    /**
     * Forces SMB 3.x packet encryption. Throws an exception during connection if the server
     * or credentials do not support encryption.
     */
    REQUIRED,

    /**
     * Never initiates encryption from the client. The server will reject the connection or share
     * access if encryption is mandatory on the server side.
     */
    DISABLED,
}

/**
 * Configuration options for an [SmbClient] connection.
 *
 * @property dialects SMB dialects offered during `SMB2 NEGOTIATE`, ordered by preference.
 * @property ciphers SMB 3.1.1 encryption ciphers offered during negotiation, ordered by preference.
 * @property encryptionPolicy Policy governing SMB 3.x packet encryption.
 * @property preferEncryption Whether to proactively enable encryption under [SmbEncryptionPolicy.NEGOTIATE]
 *   whenever the server supports SMB 3.x encryption.
 * @property alwaysSign Whether to sign all unencrypted SMB packets even when the server does not require signing.
 * @property verifyServerSignatures Whether to verify cryptographic signatures on signed responses from the server.
 * @property queryDirectoryBufferSize Default maximum output buffer size in bytes for each `SMB2 QUERY_DIRECTORY` request.
 * @property randomAccessBufferSize Default read buffer size in bytes for [SmbRandomAccessFile].
 * @property connectTimeoutMillis TCP socket connection timeout in milliseconds.
 * @property requestTimeoutMillis Timeout in milliseconds for each SMB request/response exchange.
 */
data class SmbConfig(
    val dialects: List<SmbDialect> = listOf(
        SmbDialect.SMB_3_1_1,
        SmbDialect.SMB_3_0_2,
        SmbDialect.SMB_3_0_0,
        SmbDialect.SMB_2_1_0,
        SmbDialect.SMB_2_0_2,
    ),
    val ciphers: List<SmbCipherId> = listOf(
        SmbCipherId.AES_128_GCM,
        SmbCipherId.AES_128_CCM,
    ),
    val encryptionPolicy: SmbEncryptionPolicy = SmbEncryptionPolicy.NEGOTIATE,
    val preferEncryption: Boolean = false,
    val alwaysSign: Boolean = false,
    val verifyServerSignatures: Boolean = true,
    val queryDirectoryBufferSize: Int = 64 * 1024,
    val randomAccessBufferSize: Int = SmbRandomAccessFile.DEFAULT_BUFFER_SIZE,
    val connectTimeoutMillis: Long = 10_000L,
    val requestTimeoutMillis: Long = 30_000L,
)
