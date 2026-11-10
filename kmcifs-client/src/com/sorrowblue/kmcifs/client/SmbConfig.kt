package com.sorrowblue.kmcifs.client

import com.sorrowblue.kmcifs.client.protocol.SmbCipherId
import com.sorrowblue.kmcifs.client.protocol.SmbDialect
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

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
 * @property connectTimeout TCP socket connection timeout.
 * @property requestTimeout Timeout for each SMB request/response exchange.
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
    val connectTimeout: Duration = 10.seconds,
    val requestTimeout: Duration = 30.seconds,
) {
    init {
        require(connectTimeout.isPositive()) { "connectTimeout must be positive: $connectTimeout" }
        require(requestTimeout.isPositive()) { "requestTimeout must be positive: $requestTimeout" }
    }

    /**
     * TCP socket connection timeout in milliseconds.
     */
    @Deprecated(
        message = "Use connectTimeout instead.",
        replaceWith = ReplaceWith("connectTimeout.inWholeMilliseconds"),
    )
    val connectTimeoutMillis: Long
        get() = connectTimeout.inWholeMilliseconds

    /**
     * Timeout in milliseconds for each SMB request/response exchange.
     */
    @Deprecated(
        message = "Use requestTimeout instead.",
        replaceWith = ReplaceWith("requestTimeout.inWholeMilliseconds"),
    )
    val requestTimeoutMillis: Long
        get() = requestTimeout.inWholeMilliseconds

    /**
     * Creates an [SmbConfig] specifying [connectTimeoutMillis] (and optionally [requestTimeoutMillis]) in milliseconds.
     */
    @Deprecated(
        message = "Use Duration-based connectTimeout and requestTimeout instead.",
        replaceWith = ReplaceWith(
            "SmbConfig(dialects, ciphers, encryptionPolicy, preferEncryption, alwaysSign, verifyServerSignatures, queryDirectoryBufferSize, randomAccessBufferSize, connectTimeoutMillis.milliseconds, requestTimeoutMillis.milliseconds)",
            "kotlin.time.Duration.Companion.milliseconds",
        ),
    )
    constructor(
        dialects: List<SmbDialect> = listOf(
            SmbDialect.SMB_3_1_1,
            SmbDialect.SMB_3_0_2,
            SmbDialect.SMB_3_0_0,
            SmbDialect.SMB_2_1_0,
            SmbDialect.SMB_2_0_2,
        ),
        ciphers: List<SmbCipherId> = listOf(
            SmbCipherId.AES_128_GCM,
            SmbCipherId.AES_128_CCM,
        ),
        encryptionPolicy: SmbEncryptionPolicy = SmbEncryptionPolicy.NEGOTIATE,
        preferEncryption: Boolean = false,
        alwaysSign: Boolean = false,
        verifyServerSignatures: Boolean = true,
        queryDirectoryBufferSize: Int = 64 * 1024,
        randomAccessBufferSize: Int = SmbRandomAccessFile.DEFAULT_BUFFER_SIZE,
        connectTimeoutMillis: Long = 10_000L,
        requestTimeoutMillis: Long = 30_000L,
        deprecatedMarker: Unit = Unit,
    ) : this(
        dialects = dialects,
        ciphers = ciphers,
        encryptionPolicy = encryptionPolicy,
        preferEncryption = preferEncryption,
        alwaysSign = alwaysSign,
        verifyServerSignatures = verifyServerSignatures,
        queryDirectoryBufferSize = queryDirectoryBufferSize,
        randomAccessBufferSize = randomAccessBufferSize,
        connectTimeout = connectTimeoutMillis.milliseconds,
        requestTimeout = requestTimeoutMillis.milliseconds,
    )
}
