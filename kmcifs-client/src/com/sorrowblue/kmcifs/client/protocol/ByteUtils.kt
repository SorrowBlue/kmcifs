package com.sorrowblue.kmcifs.client.protocol

/**
 * SMB プロトコルで使用するリトルエンディアン形式のバイト操作と文字列変換ユーティリティ。
 */
internal object ByteUtils {

    fun ByteArray.readUShortLE(offset: Int): UShort {
        val b0 = this[offset].toInt() and 0xFF
        val b1 = this[offset + 1].toInt() and 0xFF
        return ((b1 shl 8) or b0).toUShort()
    }

    fun ByteArray.readUIntLE(offset: Int): UInt {
        val b0 = this[offset].toUInt() and 0xFFu
        val b1 = this[offset + 1].toUInt() and 0xFFu
        val b2 = this[offset + 2].toUInt() and 0xFFu
        val b3 = this[offset + 3].toUInt() and 0xFFu
        return (b3 shl 24) or (b2 shl 16) or (b1 shl 8) or b0
    }

    fun ByteArray.readULongLE(offset: Int): ULong {
        val low = readUIntLE(offset).toULong()
        val high = readUIntLE(offset + 4).toULong()
        return (high shl 32) or low
    }

    fun ByteArray.writeUShortLE(offset: Int, value: UShort) {
        val v = value.toInt()
        this[offset] = (v and 0xFF).toByte()
        this[offset + 1] = ((v ushr 8) and 0xFF).toByte()
    }

    fun ByteArray.writeUIntLE(offset: Int, value: UInt) {
        this[offset] = (value and 0xFFu).toByte()
        this[offset + 1] = ((value shr 8) and 0xFFu).toByte()
        this[offset + 2] = ((value shr 16) and 0xFFu).toByte()
        this[offset + 3] = ((value shr 24) and 0xFFu).toByte()
    }

    fun ByteArray.writeULongLE(offset: Int, value: ULong) {
        writeUIntLE(offset, (value and 0xFFFFFFFFuL).toUInt())
        writeUIntLE(offset + 4, (value shr 32).toUInt())
    }

    /**
     * 文字列を UTF-16LE バイト配列にエンコードする。
     */
    fun String.encodeToUtf16LE(): ByteArray {
        val out = ByteArray(this.length * 2)
        for (i in indices) {
            val code = this[i].code
            out[i * 2] = (code and 0xFF).toByte()
            out[i * 2 + 1] = ((code ushr 8) and 0xFF).toByte()
        }
        return out
    }

    /**
     * UTF-16LE バイト配列の指定範囲を文字列にデコードする。
     */
    fun ByteArray.decodeFromUtf16LE(offset: Int = 0, byteLength: Int = this.size - offset): String {
        if (byteLength <= 0) return ""
        val charCount = byteLength / 2
        val chars = CharArray(charCount)
        for (i in 0 until charCount) {
            val idx = offset + i * 2
            val low = this[idx].toInt() and 0xFF
            val high = this[idx + 1].toInt() and 0xFF
            chars[i] = ((high shl 8) or low).toChar()
        }
        return chars.concatToString()
    }

    /**
     * Windows FILETIME (1601-01-01 00:00:00 UTC からの 100 ナノ秒単位) を
     * Unix エポックミリ秒 (1970-01-01 00:00:00 UTC からのミリ秒) に変換する。
     */
    fun filetimeToEpochMillis(filetime: ULong): Long {
        if (filetime == 0uL) return 0L
        val unixDiff100ns = 116444736000000000uL
        return if (filetime > unixDiff100ns) {
            ((filetime - unixDiff100ns) / 10000uL).toLong()
        } else {
            0L
        }
    }

    /**
     * Unix エポックミリ秒を Windows FILETIME に変換する。
     */
    fun epochMillisToFiletime(epochMillis: Long): ULong {
        if (epochMillis <= 0L) return 0uL
        val unixDiff100ns = 116444736000000000uL
        return epochMillis.toULong() * 10000uL + unixDiff100ns
    }
}
