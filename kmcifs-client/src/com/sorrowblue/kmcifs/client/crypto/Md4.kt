package com.sorrowblue.kmcifs.client.crypto

import com.sorrowblue.kmcifs.client.protocol.ByteUtils.readUIntLE
import com.sorrowblue.kmcifs.client.protocol.ByteUtils.writeUIntLE
import com.sorrowblue.kmcifs.client.protocol.ByteUtils.writeULongLE

/**
 * NTLM パスワードハッシュ計算で使用する MD4 (RFC 1320) 実装。
 */
internal object Md4 {

    fun digest(input: ByteArray): ByteArray {
        val bitLen = input.size.toULong() * 8uL
        val rem = (input.size + 1) % 64
        val padZeroBytes = if (rem <= 56) 56 - rem else 120 - rem
        val padded = ByteArray(input.size + 1 + padZeroBytes + 8)
        input.copyInto(padded, 0)
        padded[input.size] = 0x80.toByte()
        padded.writeULongLE(padded.size - 8, bitLen)

        var a = 0x67452301u
        var b = 0xEFCDAB89u
        var c = 0x98BADCFEu
        var d = 0x10325476u

        val x = UIntArray(16)
        var offset = 0
        while (offset < padded.size) {
            for (i in 0 until 16) {
                x[i] = padded.readUIntLE(offset + i * 4)
            }

            val aa = a
            val bb = b
            val cc = c
            val dd = d

            // Round 1
            a = r1(a, b, c, d, x[0], 3); d = r1(d, a, b, c, x[1], 7); c = r1(c, d, a, b, x[2], 11); b = r1(b, c, d, a, x[3], 19)
            a = r1(a, b, c, d, x[4], 3); d = r1(d, a, b, c, x[5], 7); c = r1(c, d, a, b, x[6], 11); b = r1(b, c, d, a, x[7], 19)
            a = r1(a, b, c, d, x[8], 3); d = r1(d, a, b, c, x[9], 7); c = r1(c, d, a, b, x[10], 11); b = r1(b, c, d, a, x[11], 19)
            a = r1(a, b, c, d, x[12], 3); d = r1(d, a, b, c, x[13], 7); c = r1(c, d, a, b, x[14], 11); b = r1(b, c, d, a, x[15], 19)

            // Round 2
            a = r2(a, b, c, d, x[0], 3); d = r2(d, a, b, c, x[4], 5); c = r2(c, d, a, b, x[8], 9); b = r2(b, c, d, a, x[12], 13)
            a = r2(a, b, c, d, x[1], 3); d = r2(d, a, b, c, x[5], 5); c = r2(c, d, a, b, x[9], 9); b = r2(b, c, d, a, x[13], 13)
            a = r2(a, b, c, d, x[2], 3); d = r2(d, a, b, c, x[6], 5); c = r2(c, d, a, b, x[10], 9); b = r2(b, c, d, a, x[14], 13)
            a = r2(a, b, c, d, x[3], 3); d = r2(d, a, b, c, x[7], 5); c = r2(c, d, a, b, x[11], 9); b = r2(b, c, d, a, x[15], 13)

            // Round 3
            a = r3(a, b, c, d, x[0], 3); d = r3(d, a, b, c, x[8], 9); c = r3(c, d, a, b, x[4], 11); b = r3(b, c, d, a, x[12], 15)
            a = r3(a, b, c, d, x[2], 3); d = r3(d, a, b, c, x[10], 9); c = r3(c, d, a, b, x[6], 11); b = r3(b, c, d, a, x[14], 15)
            a = r3(a, b, c, d, x[1], 3); d = r3(d, a, b, c, x[9], 9); c = r3(c, d, a, b, x[5], 11); b = r3(b, c, d, a, x[13], 15)
            a = r3(a, b, c, d, x[3], 3); d = r3(d, a, b, c, x[11], 9); c = r3(c, d, a, b, x[7], 11); b = r3(b, c, d, a, x[15], 15)

            a += aa
            b += bb
            c += cc
            d += dd
            offset += 64
        }

        val out = ByteArray(16)
        out.writeUIntLE(0, a)
        out.writeUIntLE(4, b)
        out.writeUIntLE(8, c)
        out.writeUIntLE(12, d)
        return out
    }

    private fun f(x: UInt, y: UInt, z: UInt): UInt = (x and y) or (x.inv() and z)
    private fun g(x: UInt, y: UInt, z: UInt): UInt = (x and y) or (x and z) or (y and z)
    private fun h(x: UInt, y: UInt, z: UInt): UInt = x xor y xor z

    private fun r1(a: UInt, b: UInt, c: UInt, d: UInt, xk: UInt, s: Int): UInt =
        (a + f(b, c, d) + xk).rotateLeft(s)

    private fun r2(a: UInt, b: UInt, c: UInt, d: UInt, xk: UInt, s: Int): UInt =
        (a + g(b, c, d) + xk + 0x5A827999u).rotateLeft(s)

    private fun r3(a: UInt, b: UInt, c: UInt, d: UInt, xk: UInt, s: Int): UInt =
        (a + h(b, c, d) + xk + 0x6ED9EBA1u).rotateLeft(s)
}
