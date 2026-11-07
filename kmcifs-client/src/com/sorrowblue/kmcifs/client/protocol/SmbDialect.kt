package com.sorrowblue.kmcifs.client.protocol

/**
 * サポートする SMB2 / SMB3 プロトコルダイアレクト。
 */
enum class SmbDialect(val code: UShort) {
    SMB_2_0_2(0x0202u),
    SMB_2_1_0(0x0210u),
    SMB_3_0_0(0x0300u),
    SMB_3_0_2(0x0302u),
    SMB_3_1_1(0x0311u);

    val isSmb3: Boolean
        get() = code >= 0x0300u

    companion object {
        fun fromCode(code: UShort): SmbDialect? = entries.firstOrNull { it.code == code }
    }
}

/**
 * SMB 3.1.1 Negotiate Context で指定される暗号化アルゴリズム識別子。
 */
enum class SmbCipherId(val code: UShort) {
    AES_128_CCM(0x0001u),
    AES_128_GCM(0x0002u);

    companion object {
        fun fromCode(code: UShort): SmbCipherId? = entries.firstOrNull { it.code == code }
    }
}
