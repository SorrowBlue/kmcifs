package com.sorrowblue.kmcifs.client.crypto

import com.sorrowblue.kmcifs.client.protocol.ByteUtils.encodeToUtf16LE
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class CryptoTest {

    private fun String.hexToBytes(): ByteArray {
        val clean = this.replace(" ", "")
        return ByteArray(clean.length / 2) { i ->
            clean.substring(i * 2, i * 2 + 2).toInt(16).toByte()
        }
    }

    private fun ByteArray.toHex(): String =
        joinToString("") { (it.toInt() and 0xFF).toString(16).padStart(2, '0') }

    @Test
    fun testMd4AndNtlmHash() {
        // RFC 1320: MD4("abc") = a448017aaf21d8525fc10ae87aa6729d
        assertEquals(
            "a448017aaf21d8525fc10ae87aa6729d",
            Md4.digest("abc".encodeToByteArray()).toHex()
        )
        // MS-NLMP 4.2.1.1: NTOWFv1("Password") = a4f49c406510bdcab6824ee7c30fd852
        assertEquals(
            "a4f49c406510bdcab6824ee7c30fd852",
            Md4.digest("Password".encodeToUtf16LE()).toHex()
        )
    }

    @Test
    fun testMd5AndHmacMd5() {
        // RFC 1321: MD5("abc") = 900150983cd24fb0d6963f7d28e17f72
        assertEquals(
            "900150983cd24fb0d6963f7d28e17f72",
            Md5.digest("abc".encodeToByteArray()).toHex()
        )
        // RFC 2104 Test Case 2: key = "Jefe", data = "what do ya want for nothing?"
        val hmac = Md5.hmac("Jefe".encodeToByteArray(), "what do ya want for nothing?".encodeToByteArray())
        assertEquals("750c783e6ab0b503eaa86e310a5db738", hmac.toHex())
    }

    @Test
    fun testSha256AndHmacSha256() {
        assertEquals(
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            Sha256.digest("abc".encodeToByteArray()).toHex()
        )
        // RFC 4231 Test Case 2: key = "Jefe", data = "what do ya want for nothing?"
        val hmac = Sha256.hmac("Jefe".encodeToByteArray(), "what do ya want for nothing?".encodeToByteArray())
        assertEquals(
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
            hmac.toHex()
        )
    }

    @Test
    fun testSha512() {
        assertEquals(
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
            Sha512.digest("abc".encodeToByteArray()).toHex()
        )
    }

    @Test
    fun testAes128BlockAndCmac() {
        // FIPS 197 Appendix B
        val key = "2b7e151628aed2a6abf7158809cf4f3c".hexToBytes()
        val block = "3243f6a8885a308d313198a2e0370734".hexToBytes()
        val cipher = Aes.Cipher(key)
        assertEquals("3925841d02dc09fbdc118597196a0b32", cipher.encryptBlock(block).toHex())

        // RFC 4493 Test Vectors for AES-128-CMAC
        // Example 1: len = 0
        assertEquals("bb1d6929e95937287fa37d129b756746", Aes.cmac(key, ByteArray(0)).toHex())
        // Example 2: len = 16
        val m16 = "6bc1bee22e409f96e93d7e117393172a".hexToBytes()
        assertEquals("070a16b46b4d4144f79bdd9dd04a287c", Aes.cmac(key, m16).toHex())
        // Example 3: len = 40
        val m40 = "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411".hexToBytes()
        assertEquals("dfa66747de9ae63030ca32611497c827", Aes.cmac(key, m40).toHex())
    }

    @Test
    fun testAes128GcmAndCcm() {
        // NIST SP 800-38D Test Case 2 (Key = 0^128, IV = 0^96, PT = 0^128, AAD = empty)
        val zeroKey = ByteArray(16)
        val zeroIv = ByteArray(12)
        val zeroPt = ByteArray(16)
        val (gcmCt, gcmTag) = Aes.gcmEncrypt(zeroKey, zeroIv, ByteArray(0), zeroPt)
        assertEquals("0388dace60b6a392f328c2b971b2fe78", gcmCt.toHex())
        assertEquals("ab6e47d42cec13bdf53a67b21257bddf", gcmTag.toHex())

        val gcmDec = Aes.gcmDecrypt(zeroKey, zeroIv, ByteArray(0), gcmCt, gcmTag)
        assertContentEquals(zeroPt, gcmDec)

        // Tamper tag test
        val badTag = gcmTag.copyOf().apply { this[0] = (this[0].toInt() xor 0xFF).toByte() }
        assertFailsWith<IllegalStateException> {
            Aes.gcmDecrypt(zeroKey, zeroIv, ByteArray(0), gcmCt, badTag)
        }

        // AES-128-CCM Round-trip (11-byte nonce as used in SMB3)
        val ccmKey = "2b7e151628aed2a6abf7158809cf4f3c".hexToBytes()
        val ccmNonce = ByteArray(11) { (it + 1).toByte() }
        val aad = ByteArray(32) { (it * 3).toByte() }
        val plaintext = "SMB3 encrypted payload test message!".encodeToByteArray()

        val (ccmCt, ccmTag) = Aes.ccmEncrypt(ccmKey, ccmNonce, aad, plaintext)
        val ccmDec = Aes.ccmDecrypt(ccmKey, ccmNonce, aad, ccmCt, ccmTag)
        assertContentEquals(plaintext, ccmDec)
    }
}
