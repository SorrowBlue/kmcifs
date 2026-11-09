package com.sorrowblue.kmcifs.client.protocol

/**
 * Supported SMB2 and SMB3 protocol dialects (`[MS-SMB2] 2.2.3`).
 *
 * @property code 16-bit wire dialect revision code.
 */
enum class SmbDialect(val code: UShort) {
    SMB_2_0_2(0x0202u),
    SMB_2_1_0(0x0210u),
    SMB_3_0_0(0x0300u),
    SMB_3_0_2(0x0302u),
    SMB_3_1_1(0x0311u);

    /** Whether this dialect belongs to the SMB 3.x family (`0x0300` or higher). */
    val isSmb3: Boolean
        get() = code >= 0x0300u

    companion object {
        /** Resolves an [SmbDialect] from its 16-bit wire revision [code], or returns `null` if unknown. */
        fun fromCode(code: UShort): SmbDialect? = entries.firstOrNull { it.code == code }
    }
}

/**
 * Encryption cipher identifiers negotiated via `SMB2_ENCRYPTION_CAPABILITIES` in SMB 3.1.1 (`[MS-SMB2] 2.2.3.1.2`).
 *
 * @property code 16-bit wire cipher identifier.
 */
enum class SmbCipherId(val code: UShort) {
    AES_128_CCM(0x0001u),
    AES_128_GCM(0x0002u);

    companion object {
        /** Resolves an [SmbCipherId] from its 16-bit wire [code], or returns `null` if unknown. */
        fun fromCode(code: UShort): SmbCipherId? = entries.firstOrNull { it.code == code }
    }
}
