package com.sorrowblue.kmcifs.client.crypto

/**
 * RC4 (ARC4) stream cipher implementation used for NTLMSSP session key exchange (`NTLMSSP_NEGOTIATE_KEY_EXCH`).
 */
internal object Rc4 {

    fun process(key: ByteArray, data: ByteArray): ByteArray {
        val s = IntArray(256) { it }
        var j = 0
        for (i in 0 until 256) {
            j = (j + s[i] + (key[i % key.size].toInt() and 0xFF)) and 0xFF
            val tmp = s[i]
            s[i] = s[j]
            s[j] = tmp
        }

        val out = ByteArray(data.size)
        var i = 0
        j = 0
        for (idx in data.indices) {
            i = (i + 1) and 0xFF
            j = (j + s[i]) and 0xFF
            val tmp = s[i]
            s[i] = s[j]
            s[j] = tmp
            val k = s[(s[i] + s[j]) and 0xFF]
            out[idx] = ((data[idx].toInt() and 0xFF) xor k).toByte()
        }
        return out
    }
}
