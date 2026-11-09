package com.sorrowblue.kmcifs.client.crypto

/**
 * Pure Kotlin AES-128 implementation used for SMB 3.x message signing (`AES-128-CMAC`)
 * and packet encryption (`AES-128-CCM` / `AES-128-GCM`).
 */
internal object Aes {

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

    private val RCON = intArrayOf(
        0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
    )

    class Cipher(key: ByteArray) {
        private val roundKeys = IntArray(176)

        init {
            require(key.size == 16) { "AES-128 key must be 16 bytes" }
            for (i in 0 until 16) {
                roundKeys[i] = key[i].toInt() and 0xFF
            }
            val temp = IntArray(4)
            var bytesGenerated = 16
            var rconIteration = 1
            while (bytesGenerated < 176) {
                for (i in 0 until 4) {
                    temp[i] = roundKeys[bytesGenerated - 4 + i]
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
                    roundKeys[bytesGenerated] = roundKeys[bytesGenerated - 16] xor temp[i]
                    bytesGenerated++
                }
            }
        }

        fun encryptBlock(
            input: ByteArray,
            inOffset: Int = 0,
            output: ByteArray = ByteArray(16),
            outOffset: Int = 0,
            state: IntArray = IntArray(16),
        ): ByteArray {
            val rk = roundKeys
            for (i in 0 until 16) {
                state[i] = (input[inOffset + i].toInt() and 0xFF) xor rk[i]
            }

            for (round in 1..9) {
                subBytesAndShiftRows(state)
                mixColumns(state)
                addRoundKey(state, round * 16)
            }

            subBytesAndShiftRows(state)
            addRoundKey(state, 160)

            for (i in 0 until 16) {
                output[outOffset + i] = state[i].toByte()
            }
            return output
        }

        private fun subBytesAndShiftRows(s: IntArray) {
            for (i in 0 until 16) s[i] = SBOX[s[i]]
            // Row 1: shift left by 1
            val t1 = s[1]; s[1] = s[5]; s[5] = s[9]; s[9] = s[13]; s[13] = t1
            // Row 2: shift left by 2
            val t2a = s[2]; val t2b = s[6]; s[2] = s[10]; s[6] = s[14]; s[10] = t2a; s[14] = t2b
            // Row 3: shift left by 3 (right by 1)
            val t3 = s[15]; s[15] = s[11]; s[11] = s[7]; s[7] = s[3]; s[3] = t3
        }

        private fun mixColumns(s: IntArray) {
            for (c in 0 until 4) {
                val i = c * 4
                val a0 = s[i]
                val a1 = s[i + 1]
                val a2 = s[i + 2]
                val a3 = s[i + 3]
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

        private fun addRoundKey(s: IntArray, roundKeyOffset: Int) {
            val rk = roundKeys
            for (i in 0 until 16) {
                s[i] = s[i] xor rk[roundKeyOffset + i]
            }
        }
    }

    private class KeyContext(
        val k0: ULong,
        val k1: ULong,
        val cipher: Cipher,
        val h0: ULongArray,
        val h1: ULongArray,
        val cmacK1: ByteArray,
        val cmacK2: ByteArray,
    )

    private val keyCache = arrayOfNulls<KeyContext>(16)

    private fun contextForKey(key: ByteArray): KeyContext {
        require(key.size == 16) { "AES-128 key must be 16 bytes" }
        val k0 = readULongBE(key, 0)
        val k1 = readULongBE(key, 8)
        val slot = ((k0 xor (k0 shr 32) xor k1 xor (k1 shr 32)).toInt()) and 15
        val cached = keyCache[slot]
        if (cached != null && cached.k0 == k0 && cached.k1 == k1) {
            return cached
        }
        val cipher = Cipher(key)
        val h = cipher.encryptBlock(ByteArray(16))
        val (h0, h1) = buildGhashTable(h)
        val cmacK1 = doubleSubkey(h)
        val cmacK2 = doubleSubkey(cmacK1)
        val created = KeyContext(k0, k1, cipher, h0, h1, cmacK1, cmacK2)
        keyCache[slot] = created
        return created
    }

    /**
     * Computes AES-128-CMAC (RFC 4493) for SMB 3.x packet signing.
     */
    fun cmac(key: ByteArray, data: ByteArray): ByteArray {
        val ctx = contextForKey(key)
        val cipher = ctx.cipher
        val k1 = ctx.cmacK1
        val k2 = ctx.cmacK2

        val n = if (data.isEmpty()) 1 else (data.size + 15) / 16
        val flagComplete = data.isNotEmpty() && (data.size % 16 == 0)

        val mLast = ByteArray(16)
        val lastOffset = (n - 1) * 16
        if (flagComplete) {
            for (i in 0 until 16) {
                mLast[i] = (data[lastOffset + i].toInt() xor k1[i].toInt()).toByte()
            }
        } else {
            val rem = data.size - lastOffset
            for (i in 0 until 16) {
                val paddedByte = when {
                    i < rem -> data[lastOffset + i].toInt()
                    i == rem -> 0x80
                    else -> 0x00
                }
                mLast[i] = (paddedByte xor k2[i].toInt()).toByte()
            }
        }

        val x = ByteArray(16)
        val y = ByteArray(16)
        val state = IntArray(16)
        for (blockIdx in 0 until n - 1) {
            val base = blockIdx * 16
            for (i in 0 until 16) {
                y[i] = (x[i].toInt() xor data[base + i].toInt()).toByte()
            }
            cipher.encryptBlock(y, 0, x, 0, state)
        }

        for (i in 0 until 16) {
            y[i] = (x[i].toInt() xor mLast[i].toInt()).toByte()
        }
        return cipher.encryptBlock(y, 0, x, 0, state)
    }

    private fun doubleSubkey(input: ByteArray): ByteArray {
        val out = ByteArray(16)
        var carry = 0
        for (i in 15 downTo 0) {
            val b = input[i].toInt() and 0xFF
            out[i] = ((b shl 1) or carry).toByte()
            carry = (b ushr 7) and 1
        }
        if ((input[0].toInt() and 0x80) != 0) {
            out[15] = (out[15].toInt() xor 0x87).toByte()
        }
        return out
    }

    /**
     * Encrypts [plaintext] using AES-128-CCM (RFC 3610).
     * SMB 3.0 / 3.0.2 / 3.1.1 uses an 11-byte nonce (`L = 4`) and a 16-byte authentication tag (`M = 16`).
     *
     * @return Pair of `(Ciphertext, 16-byte Tag)`.
     */
    fun ccmEncrypt(key: ByteArray, nonce: ByteArray, aad: ByteArray, plaintext: ByteArray): Pair<ByteArray, ByteArray> {
        require(nonce.size in 7..13) { "CCM nonce must be 7..13 bytes" }
        val cipher = contextForKey(key).cipher
        val state = IntArray(16)
        val tag = computeCcmMac(cipher, nonce, aad, plaintext, state)
        val ciphertext = ByteArray(plaintext.size)
        val s0 = ByteArray(16)
        processCcmCtr(cipher, nonce, plaintext, ciphertext, s0, state)
        for (i in 0 until 16) {
            tag[i] = (tag[i].toInt() xor s0[i].toInt()).toByte()
        }
        return ciphertext to tag
    }

    /**
     * Decrypts [ciphertext] and verifies its 16-byte authentication tag using AES-128-CCM.
     */
    fun ccmDecrypt(key: ByteArray, nonce: ByteArray, aad: ByteArray, ciphertext: ByteArray, expectedTag: ByteArray): ByteArray {
        require(nonce.size in 7..13) { "CCM nonce must be 7..13 bytes" }
        require(expectedTag.size == 16) { "CCM tag must be 16 bytes" }
        val cipher = contextForKey(key).cipher
        val state = IntArray(16)
        val plaintext = ByteArray(ciphertext.size)
        val s0 = ByteArray(16)
        processCcmCtr(cipher, nonce, ciphertext, plaintext, s0, state)

        val computedTag = computeCcmMac(cipher, nonce, aad, plaintext, state)
        for (i in 0 until 16) {
            computedTag[i] = (computedTag[i].toInt() xor s0[i].toInt()).toByte()
        }
        if (!constantTimeEquals(computedTag, expectedTag)) {
            throw IllegalStateException("SMB3 AES-128-CCM authentication tag mismatch")
        }
        return plaintext
    }

    private fun computeCcmMac(cipher: Cipher, nonce: ByteArray, aad: ByteArray, plaintext: ByteArray, state: IntArray): ByteArray {
        val q = 15 - nonce.size // L (for 11-byte nonce, q = 4)
        val flags = (if (aad.isNotEmpty()) 0x40 else 0x00) or (((16 - 2) / 2) shl 3) or (q - 1)
        val b0 = ByteArray(16)
        b0[0] = flags.toByte()
        nonce.copyInto(b0, 1)
        var lenVal = plaintext.size.toLong()
        for (i in 0 until q) {
            b0[15 - i] = (lenVal and 0xFFL).toByte()
            lenVal = lenVal ushr 8
        }

        val x = cipher.encryptBlock(b0, 0, ByteArray(16), 0, state)
        val block = ByteArray(16)

        if (aad.isNotEmpty()) {
            val aadEncoded: ByteArray
            if (aad.size < 0xFF00) {
                aadEncoded = ByteArray(2 + aad.size)
                aadEncoded[0] = ((aad.size ushr 8) and 0xFF).toByte()
                aadEncoded[1] = (aad.size and 0xFF).toByte()
                aad.copyInto(aadEncoded, 2)
            } else {
                aadEncoded = ByteArray(6 + aad.size)
                aadEncoded[0] = 0xFF.toByte()
                aadEncoded[1] = 0xFE.toByte()
                aadEncoded[2] = ((aad.size ushr 24) and 0xFF).toByte()
                aadEncoded[3] = ((aad.size ushr 16) and 0xFF).toByte()
                aadEncoded[4] = ((aad.size ushr 8) and 0xFF).toByte()
                aadEncoded[5] = (aad.size and 0xFF).toByte()
                aad.copyInto(aadEncoded, 6)
            }
            cbcMacUpdate(cipher, x, block, aadEncoded, state)
        }

        if (plaintext.isNotEmpty()) {
            cbcMacUpdate(cipher, x, block, plaintext, state)
        }
        return x
    }

    private fun cbcMacUpdate(cipher: Cipher, x: ByteArray, scratch: ByteArray, data: ByteArray, state: IntArray) {
        var offset = 0
        while (offset < data.size) {
            val chunk = minOf(16, data.size - offset)
            for (i in 0 until 16) {
                val b = if (i < chunk) data[offset + i].toInt() else 0
                scratch[i] = (x[i].toInt() xor b).toByte()
            }
            cipher.encryptBlock(scratch, 0, x, 0, state)
            offset += 16
        }
    }

    private fun processCcmCtr(cipher: Cipher, nonce: ByteArray, input: ByteArray, output: ByteArray, s0Out: ByteArray, state: IntArray) {
        val q = 15 - nonce.size
        val ctrBlock = ByteArray(16)
        ctrBlock[0] = (q - 1).toByte()
        nonce.copyInto(ctrBlock, 1)

        // Counter = 0 -> S_0
        cipher.encryptBlock(ctrBlock, 0, s0Out, 0, state)

        val keystream = ByteArray(16)
        var counter = 1L
        var offset = 0
        while (offset < input.size) {
            var c = counter
            for (i in 0 until q) {
                ctrBlock[15 - i] = (c and 0xFFL).toByte()
                c = c ushr 8
            }
            cipher.encryptBlock(ctrBlock, 0, keystream, 0, state)
            val chunk = minOf(16, input.size - offset)
            for (i in 0 until chunk) {
                output[offset + i] = (input[offset + i].toInt() xor keystream[i].toInt()).toByte()
            }
            offset += 16
            counter++
        }
    }

    /**
     * Encrypts [plaintext] using AES-128-GCM (NIST SP 800-38D).
     * SMB 3.1.1 uses a 12-byte nonce (IV) and a 16-byte authentication tag.
     */
    fun gcmEncrypt(key: ByteArray, iv: ByteArray, aad: ByteArray, plaintext: ByteArray): Pair<ByteArray, ByteArray> {
        require(iv.size == 12) { "GCM IV must be 12 bytes" }
        val ctx = contextForKey(key)
        val aesState = IntArray(16)

        val j0 = ByteArray(16)
        iv.copyInto(j0, 0, 0, 12)
        j0[15] = 1

        val ciphertext = ByteArray(plaintext.size)
        processGcmCtr(ctx.cipher, j0, plaintext, ciphertext, aesState)

        val tag = computeGcmTag(ctx, j0, aad, ciphertext, aesState)
        return ciphertext to tag
    }

    /**
     * Decrypts [ciphertext] and verifies its 16-byte authentication tag using AES-128-GCM.
     */
    fun gcmDecrypt(key: ByteArray, iv: ByteArray, aad: ByteArray, ciphertext: ByteArray, expectedTag: ByteArray): ByteArray {
        require(iv.size == 12) { "GCM IV must be 12 bytes" }
        require(expectedTag.size == 16) { "GCM tag must be 16 bytes" }
        val ctx = contextForKey(key)
        val aesState = IntArray(16)

        val j0 = ByteArray(16)
        iv.copyInto(j0, 0, 0, 12)
        j0[15] = 1

        val computedTag = computeGcmTag(ctx, j0, aad, ciphertext, aesState)
        if (!constantTimeEquals(computedTag, expectedTag)) {
            throw IllegalStateException("SMB3 AES-128-GCM authentication tag mismatch")
        }

        val plaintext = ByteArray(ciphertext.size)
        processGcmCtr(ctx.cipher, j0, ciphertext, plaintext, aesState)
        return plaintext
    }

    private fun processGcmCtr(cipher: Cipher, j0: ByteArray, input: ByteArray, output: ByteArray, state: IntArray) {
        val cb = j0.copyOf()
        val keystream = ByteArray(16)
        var counter = 2u
        var offset = 0
        while (offset < input.size) {
            cb[12] = ((counter shr 24) and 0xFFu).toByte()
            cb[13] = ((counter shr 16) and 0xFFu).toByte()
            cb[14] = ((counter shr 8) and 0xFFu).toByte()
            cb[15] = (counter and 0xFFu).toByte()
            cipher.encryptBlock(cb, 0, keystream, 0, state)
            val chunk = minOf(16, input.size - offset)
            for (i in 0 until chunk) {
                output[offset + i] = (input[offset + i].toInt() xor keystream[i].toInt()).toByte()
            }
            offset += 16
            counter++
        }
    }

    private val GCM_REDUCE_TABLE = ulongArrayOf(
        0x0000000000000000uL, 0x1c20000000000000uL, 0x3840000000000000uL, 0x2460000000000000uL,
        0x7080000000000000uL, 0x6ca0000000000000uL, 0x48c0000000000000uL, 0x54e0000000000000uL,
        0xe100000000000000uL, 0xfd20000000000000uL, 0xd940000000000000uL, 0xc560000000000000uL,
        0x9180000000000000uL, 0x8da0000000000000uL, 0xa9c0000000000000uL, 0xb5e0000000000000uL,
    )

    private fun buildGhashTable(h: ByteArray): Pair<ULongArray, ULongArray> {
        val h0 = ULongArray(16)
        val h1 = ULongArray(16)
        h0[8] = readULongBE(h, 0)
        h1[8] = readULongBE(h, 8)
        for (i in listOf(4, 2, 1)) {
            val prev0 = h0[i * 2]
            val prev1 = h1[i * 2]
            val lsb = (prev1 and 1uL) != 0uL
            h1[i] = (prev1 shr 1) or (prev0 shl 63)
            h0[i] = (prev0 shr 1) xor (if (lsb) 0xe100000000000000uL else 0uL)
        }
        var i = 2
        while (i <= 8) {
            for (j in 1 until i) {
                h0[i + j] = h0[i] xor h0[j]
                h1[i + j] = h1[i] xor h1[j]
            }
            i *= 2
        }
        return h0 to h1
    }

    private fun computeGcmTag(ctx: KeyContext, j0: ByteArray, aad: ByteArray, ciphertext: ByteArray, aesState: IntArray): ByteArray {
        val h0 = ctx.h0
        val h1 = ctx.h1
        val state = ULongArray(2)
        ghashUpdate(state, h0, h1, aad)
        ghashUpdate(state, h0, h1, ciphertext)

        val aadBits = aad.size.toULong() * 8uL
        val ctBits = ciphertext.size.toULong() * 8uL
        state[0] = state[0] xor aadBits
        state[1] = state[1] xor ctBits
        gfMultiplyShoup(state, h0, h1)

        val out = ByteArray(16)
        val s = ctx.cipher.encryptBlock(j0, 0, out, 0, aesState)
        val tag0 = state[0] xor readULongBE(s, 0)
        val tag1 = state[1] xor readULongBE(s, 8)
        writeULongBE(out, 0, tag0)
        writeULongBE(out, 8, tag1)
        return out
    }

    private fun ghashUpdate(state: ULongArray, h0: ULongArray, h1: ULongArray, data: ByteArray) {
        var offset = 0
        val fullLimit = data.size - 16
        while (offset <= fullLimit) {
            state[0] = state[0] xor readULongBE(data, offset)
            state[1] = state[1] xor readULongBE(data, offset + 8)
            gfMultiplyShoup(state, h0, h1)
            offset += 16
        }
        if (offset < data.size) {
            var b0 = 0uL
            var b1 = 0uL
            val rem = data.size - offset
            for (i in 0 until rem) {
                val v = data[offset + i].toULong() and 0xFFuL
                if (i < 8) {
                    b0 = b0 or (v shl ((7 - i) * 8))
                } else {
                    b1 = b1 or (v shl ((15 - i) * 8))
                }
            }
            state[0] = state[0] xor b0
            state[1] = state[1] xor b1
            gfMultiplyShoup(state, h0, h1)
        }
    }

    private fun gfMultiplyShoup(state: ULongArray, h0: ULongArray, h1: ULongArray) {
        val x0 = state[0]
        val x1 = state[1]
        var z0 = 0uL
        var z1 = 0uL

        for (i in 0 until 8) {
            val b = ((x1 shr (i * 8)) and 0xFFuL).toInt()
            val lo = b and 0x0F
            var rem = (z1 and 0x0FuL).toInt()
            z1 = (z1 shr 4) or (z0 shl 60)
            z0 = (z0 shr 4) xor GCM_REDUCE_TABLE[rem] xor h0[lo]
            z1 = z1 xor h1[lo]

            val hi = b ushr 4
            rem = (z1 and 0x0FuL).toInt()
            z1 = (z1 shr 4) or (z0 shl 60)
            z0 = (z0 shr 4) xor GCM_REDUCE_TABLE[rem] xor h0[hi]
            z1 = z1 xor h1[hi]
        }

        for (i in 0 until 8) {
            val b = ((x0 shr (i * 8)) and 0xFFuL).toInt()
            val lo = b and 0x0F
            var rem = (z1 and 0x0FuL).toInt()
            z1 = (z1 shr 4) or (z0 shl 60)
            z0 = (z0 shr 4) xor GCM_REDUCE_TABLE[rem] xor h0[lo]
            z1 = z1 xor h1[lo]

            val hi = b ushr 4
            rem = (z1 and 0x0FuL).toInt()
            z1 = (z1 shr 4) or (z0 shl 60)
            z0 = (z0 shr 4) xor GCM_REDUCE_TABLE[rem] xor h0[hi]
            z1 = z1 xor h1[hi]
        }

        state[0] = z0
        state[1] = z1
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

    internal fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean {
        if (a.size != b.size) return false
        var diff = 0
        for (i in a.indices) {
            diff = diff or (a[i].toInt() xor b[i].toInt())
        }
        return diff == 0
    }
}
