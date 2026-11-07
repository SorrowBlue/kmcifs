package com.sorrowblue.kmcifs.client.auth

import com.sorrowblue.kmcifs.client.crypto.Md4
import com.sorrowblue.kmcifs.client.crypto.Md5
import com.sorrowblue.kmcifs.client.crypto.Rc4
import com.sorrowblue.kmcifs.client.protocol.ByteUtils.encodeToUtf16LE
import com.sorrowblue.kmcifs.client.protocol.ByteUtils.readUIntLE
import com.sorrowblue.kmcifs.client.protocol.ByteUtils.readULongLE
import com.sorrowblue.kmcifs.client.protocol.ByteUtils.readUShortLE
import com.sorrowblue.kmcifs.client.protocol.ByteUtils.writeUIntLE
import com.sorrowblue.kmcifs.client.protocol.ByteUtils.writeULongLE
import com.sorrowblue.kmcifs.client.protocol.ByteUtils.writeUShortLE
import kotlin.random.Random

/**
 * NTLMSSP (NTLMv2) 認証および SPNEGO (ASN.1 DER) ラッピングを処理するクラス。
 */
internal object NtlmAuthenticator {

    private val NTLMSSP_SIGNATURE = byteArrayOf(
        'N'.code.toByte(), 'T'.code.toByte(), 'L'.code.toByte(), 'M'.code.toByte(),
        'S'.code.toByte(), 'S'.code.toByte(), 'P'.code.toByte(), 0x00
    )

    // Negotiate Flags
    private const val NTLMSSP_NEGOTIATE_UNICODE = 0x00000001u
    private const val NTLMSSP_REQUEST_TARGET = 0x00000004u
    private const val NTLMSSP_NEGOTIATE_SIGN = 0x00000010u
    private const val NTLMSSP_NEGOTIATE_NTLM = 0x00000200u
    private const val NTLMSSP_NEGOTIATE_ALWAYS_SIGN = 0x00008000u
    private const val NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY = 0x00080000u
    private const val NTLMSSP_NEGOTIATE_TARGET_INFO = 0x00800000u
    private const val NTLMSSP_NEGOTIATE_VERSION = 0x02000000u
    private const val NTLMSSP_NEGOTIATE_128 = 0x20000000u
    private const val NTLMSSP_NEGOTIATE_KEY_EXCH = 0x40000000u
    private const val NTLMSSP_NEGOTIATE_56 = 0x80000000u

    private val DEFAULT_NEGOTIATE_FLAGS =
        NTLMSSP_NEGOTIATE_UNICODE or
            NTLMSSP_REQUEST_TARGET or
            NTLMSSP_NEGOTIATE_SIGN or
            NTLMSSP_NEGOTIATE_NTLM or
            NTLMSSP_NEGOTIATE_ALWAYS_SIGN or
            NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY or
            NTLMSSP_NEGOTIATE_TARGET_INFO or
            NTLMSSP_NEGOTIATE_VERSION or
            NTLMSSP_NEGOTIATE_128 or
            NTLMSSP_NEGOTIATE_KEY_EXCH or
            NTLMSSP_NEGOTIATE_56

    // AV_PAIR IDs
    private const val MSV_AV_EOL: UShort = 0u
    private const val MSV_AV_FLAGS: UShort = 6u
    private const val MSV_AV_TIMESTAMP: UShort = 7u

    data class ChallengeInfo(
        val rawType2Message: ByteArray,
        val negotiateFlags: UInt,
        val serverChallenge: ByteArray,
        val targetInfo: ByteArray,
        val serverTimestamp: ULong?,
    )

    data class AuthenticateResult(
        val rawType3Message: ByteArray,
        val spnegoTokenResp: ByteArray,
        val exportedSessionKey: ByteArray,
    )

    /**
     * NTLMSSP Type 1 (NEGOTIATE_MESSAGE) を生成する。
     */
    fun createType1Message(flags: UInt = DEFAULT_NEGOTIATE_FLAGS): ByteArray {
        val msg = ByteArray(40)
        NTLMSSP_SIGNATURE.copyInto(msg, 0)
        msg.writeUIntLE(8, 1u) // MessageType = 1
        msg.writeUIntLE(12, flags)
        // DomainNameFields (16..23) = 0, WorkstationFields (24..31) = 0
        // Version (32..39): Windows 10.0 Build 19041, NTLMRevisionCurrent = 15
        msg[32] = 10
        msg[33] = 0
        msg.writeUShortLE(34, 19041u)
        msg[39] = 15
        return msg
    }

    private val SPNEGO_OID = byteArrayOf(0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02)
    private val NTLMSSP_OID = byteArrayOf(0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82.toByte(), 0x37, 0x02, 0x02, 0x0a)
    private val MECH_TYPE_LIST_DER = asn1Wrap(0x30, NTLMSSP_OID)

    /**
     * Type 1 メッセージを SPNEGO negTokenInit (ASN.1 DER) でラップする。
     */
    fun wrapType1InSpnego(type1Message: ByteArray): ByteArray {
        val mechTypesField = asn1Wrap(0xA0, MECH_TYPE_LIST_DER)
        val mechTokenOctet = asn1Wrap(0x04, type1Message)
        val mechTokenField = asn1Wrap(0xA2, mechTokenOctet)

        val negTokenInitSeq = asn1Wrap(0x30, mechTypesField + mechTokenField)
        val negTokenInitChoice = asn1Wrap(0xA0, negTokenInitSeq)
        return asn1Wrap(0x60, SPNEGO_OID + negTokenInitChoice)
    }

    /**
     * サーバーから受信したセキュリティブロブ (SPNEGO または生 NTLMSSP) から Type 2 (CHALLENGE_MESSAGE) を解析する。
     */
    fun parseType2Challenge(securityBlob: ByteArray): ChallengeInfo {
        val ntlmOffset = findNtlmsspOffset(securityBlob)
            ?: throw IllegalArgumentException("NTLMSSP signature not found in challenge security blob")
        val type2 = securityBlob.copyOfRange(ntlmOffset, securityBlob.size)

        val msgType = type2.readUIntLE(8)
        require(msgType == 2u) { "Expected NTLMSSP Type 2 message, but got type $msgType" }

        val flags = type2.readUIntLE(20)
        val serverChallenge = type2.copyOfRange(24, 32)

        var targetInfo = ByteArray(0)
        var serverTimestamp: ULong? = null

        if (type2.size >= 48 && (flags and NTLMSSP_NEGOTIATE_TARGET_INFO) != 0u) {
            val targetInfoLen = type2.readUShortLE(40).toInt()
            val targetInfoOffset = type2.readUIntLE(44).toInt()
            if (targetInfoLen > 0 && targetInfoOffset + targetInfoLen <= type2.size) {
                targetInfo = type2.copyOfRange(targetInfoOffset, targetInfoOffset + targetInfoLen)
                serverTimestamp = extractTimestampFromTargetInfo(targetInfo)
            }
        }

        return ChallengeInfo(
            rawType2Message = type2,
            negotiateFlags = flags,
            serverChallenge = serverChallenge,
            targetInfo = targetInfo,
            serverTimestamp = serverTimestamp
        )
    }

    /**
     * NTLMv2 認証応答 (Type 3 AUTHENTICATE_MESSAGE) とセッション鍵を生成する。
     */
    fun createType3Authenticate(
        credentials: SmbCredentials,
        type1Message: ByteArray,
        challenge: ChallengeInfo,
        clientChallenge: ByteArray = Random.Default.nextBytes(8),
        randomSessionKey: ByteArray = Random.Default.nextBytes(16),
        currentTimeFiletime: ULong = 133485408000000000uL, // Fallback Filetime if server didn't provide one
    ): AuthenticateResult {
        val domainBytes = credentials.domain.encodeToUtf16LE()
        val userBytes = credentials.username.encodeToUtf16LE()
        val workstationBytes = credentials.workstation.encodeToUtf16LE()

        val flags = DEFAULT_NEGOTIATE_FLAGS and challenge.negotiateFlags

        if (credentials.isAnonymous) {
            val emptyKey = ByteArray(16)
            val rawType3 = buildType3Packet(
                lmResponse = ByteArray(0),
                ntlmResponse = ByteArray(0),
                domainBytes = ByteArray(0),
                userBytes = ByteArray(0),
                workstationBytes = workstationBytes,
                encryptedRandomSessionKey = ByteArray(0),
                flags = flags,
                includeMic = false
            )
            return AuthenticateResult(
                rawType3Message = rawType3,
                spnegoTokenResp = wrapType3InSpnego(rawType3),
                exportedSessionKey = emptyKey
            )
        }

        // 1. NTOWFv2(Passwd, User, UserDom)
        val ntlmHash = Md4.digest(credentials.password.encodeToUtf16LE())
        val userDomainUpper = (credentials.username.uppercase() + credentials.domain).encodeToUtf16LE()
        val responseKeyNT = Md5.hmac(ntlmHash, userDomainUpper)

        // 2. TargetInfo の調整（Timestamp が存在する場合は MIC フラグ MsvAvFlags = 0x00000002 を設定）
        val includeMic = challenge.serverTimestamp != null
        val adjustedTargetInfo = if (includeMic) {
            addOrUpdateMicFlagInTargetInfo(challenge.targetInfo)
        } else {
            challenge.targetInfo
        }

        val timestamp = challenge.serverTimestamp ?: currentTimeFiletime

        // 3. NTLMv2 Client Challenge (temp blob)
        // RespType(1)=1, HiRespType(1)=1, Reserved1(2)=0, Reserved2(4)=0, TimeStamp(8), ChallengeFromClient(8), Reserved3(4)=0, AvPairs, Reserved4(4)=0
        val temp = ByteArray(28 + adjustedTargetInfo.size + 4)
        temp[0] = 0x01
        temp[1] = 0x01
        temp.writeULongLE(8, timestamp)
        clientChallenge.copyInto(temp, 16, 0, 8)
        adjustedTargetInfo.copyInto(temp, 28)

        // 4. NTProofStr = HMAC_MD5(ResponseKeyNT, ServerChallenge || temp)
        val ntProofStr = Md5.hmac(responseKeyNT, challenge.serverChallenge, temp)
        val ntChallengeResponse = ByteArray(16 + temp.size)
        ntProofStr.copyInto(ntChallengeResponse, 0)
        temp.copyInto(ntChallengeResponse, 16)

        // 5. LMv2 Response (Timestamp がサーバーから提供されている場合は Z(24) にする仕様: MS-NLMP 3.3.2)
        val lmChallengeResponse = if (includeMic) {
            ByteArray(24)
        } else {
            val lmProof = Md5.hmac(responseKeyNT, challenge.serverChallenge, clientChallenge)
            ByteArray(24).apply {
                lmProof.copyInto(this, 0)
                clientChallenge.copyInto(this, 16)
            }
        }

        // 6. SessionBaseKey = HMAC_MD5(ResponseKeyNT, NTProofStr)
        val sessionBaseKey = Md5.hmac(responseKeyNT, ntProofStr)
        val keyExchangeKey = sessionBaseKey

        val exportedSessionKey: ByteArray
        val encryptedRandomSessionKey: ByteArray
        if ((flags and NTLMSSP_NEGOTIATE_KEY_EXCH) != 0u) {
            exportedSessionKey = randomSessionKey
            encryptedRandomSessionKey = Rc4.process(keyExchangeKey, exportedSessionKey)
        } else {
            exportedSessionKey = keyExchangeKey
            encryptedRandomSessionKey = ByteArray(0)
        }

        // 7. Type 3 パケットの組み立てと MIC 計算
        val rawType3 = buildType3Packet(
            lmResponse = lmChallengeResponse,
            ntlmResponse = ntChallengeResponse,
            domainBytes = domainBytes,
            userBytes = userBytes,
            workstationBytes = workstationBytes,
            encryptedRandomSessionKey = encryptedRandomSessionKey,
            flags = flags,
            includeMic = includeMic
        )

        if (includeMic) {
            // MIC (offset 72..87) = HMAC_MD5(ExportedSessionKey, Type1 || Type2 || Type3_with_zero_MIC)
            val mic = Md5.hmac(exportedSessionKey, type1Message, challenge.rawType2Message, rawType3)
            mic.copyInto(rawType3, 72)
        }

        val mechListMic = computeSpnegoMechListMic(exportedSessionKey, flags)

        return AuthenticateResult(
            rawType3Message = rawType3,
            spnegoTokenResp = wrapType3InSpnego(rawType3, mechListMic),
            exportedSessionKey = exportedSessionKey
        )
    }

    /**
     * SPNEGO の `mechListMIC` フィールド用 NTLMv2 署名 (16 バイト, MS-NLMP 3.4.4.2) を計算する。
     */
    private fun computeSpnegoMechListMic(exportedSessionKey: ByteArray, flags: UInt): ByteArray {
        val signMagic = "session key to client-to-server signing key magic constant\u0000".encodeToByteArray()
        val sealMagic = "session key to client-to-server sealing key magic constant\u0000".encodeToByteArray()

        val clientSigningKey = Md5.digest(exportedSessionKey + signMagic)
        val clientSealingKey = Md5.digest(exportedSessionKey + sealMagic)

        val seqNumBytes = ByteArray(4) // SeqNum = 0
        val hmac = Md5.hmac(clientSigningKey, seqNumBytes, MECH_TYPE_LIST_DER)
        val hash8 = hmac.copyOfRange(0, 8)

        val checksum = if ((flags and NTLMSSP_NEGOTIATE_KEY_EXCH) != 0u) {
            Rc4.process(clientSealingKey, hash8)
        } else {
            hash8
        }

        val sig = ByteArray(16)
        sig.writeUIntLE(0, 1u) // Version = 1
        checksum.copyInto(sig, 4, 0, 8)
        sig.writeUIntLE(12, 0u) // SeqNum = 0
        return sig
    }

    private fun buildType3Packet(
        lmResponse: ByteArray,
        ntlmResponse: ByteArray,
        domainBytes: ByteArray,
        userBytes: ByteArray,
        workstationBytes: ByteArray,
        encryptedRandomSessionKey: ByteArray,
        flags: UInt,
        includeMic: Boolean,
    ): ByteArray {
        val headerSize = if (includeMic) 88 else 72
        val totalSize = headerSize +
            domainBytes.size +
            userBytes.size +
            workstationBytes.size +
            lmResponse.size +
            ntlmResponse.size +
            encryptedRandomSessionKey.size

        val buf = ByteArray(totalSize)
        NTLMSSP_SIGNATURE.copyInto(buf, 0)
        buf.writeUIntLE(8, 3u) // MessageType = 3

        var payloadOffset = headerSize

        fun writeSecBuf(fieldOffset: Int, data: ByteArray) {
            buf.writeUShortLE(fieldOffset, data.size.toUShort())
            buf.writeUShortLE(fieldOffset + 2, data.size.toUShort())
            buf.writeUIntLE(fieldOffset + 4, payloadOffset.toUInt())
            if (data.isNotEmpty()) {
                data.copyInto(buf, payloadOffset)
                payloadOffset += data.size
            }
        }

        // Payload は Domain -> User -> Workstation -> LmResponse -> NtResponse -> EncryptedRandomSessionKey の順で配置
        writeSecBuf(28, domainBytes)
        writeSecBuf(36, userBytes)
        writeSecBuf(44, workstationBytes)
        writeSecBuf(12, lmResponse)
        writeSecBuf(20, ntlmResponse)
        writeSecBuf(52, encryptedRandomSessionKey)

        buf.writeUIntLE(60, flags)
        // Version (64..71)
        buf[64] = 10
        buf[65] = 0
        buf.writeUShortLE(66, 19041u)
        buf[71] = 15
        // MIC (72..87) stays 0 until filled by caller

        return buf
    }

    /**
     * Type 3 メッセージを SPNEGO negTokenResp (ASN.1 DER) でラップする。
     */
    fun wrapType3InSpnego(type3Message: ByteArray, mechListMic: ByteArray? = null): ByteArray {
        val responseTokenOctet = asn1Wrap(0x04, type3Message)
        val responseTokenField = asn1Wrap(0xA2, responseTokenOctet)
        val seqContent = if (mechListMic != null && mechListMic.isNotEmpty()) {
            val micOctet = asn1Wrap(0x04, mechListMic)
            val micField = asn1Wrap(0xA3, micOctet)
            responseTokenField + micField
        } else {
            responseTokenField
        }
        val negTokenRespSeq = asn1Wrap(0x30, seqContent)
        return asn1Wrap(0xA1, negTokenRespSeq)
    }

    private fun findNtlmsspOffset(blob: ByteArray): Int? {
        outer@ for (i in 0..blob.size - NTLMSSP_SIGNATURE.size) {
            for (j in NTLMSSP_SIGNATURE.indices) {
                if (blob[i + j] != NTLMSSP_SIGNATURE[j]) continue@outer
            }
            return i
        }
        return null
    }

    private fun extractTimestampFromTargetInfo(targetInfo: ByteArray): ULong? {
        var pos = 0
        while (pos + 4 <= targetInfo.size) {
            val avId = targetInfo.readUShortLE(pos)
            val avLen = targetInfo.readUShortLE(pos + 2).toInt()
            pos += 4
            if (avId == MSV_AV_EOL) break
            if (pos + avLen > targetInfo.size) break
            if (avId == MSV_AV_TIMESTAMP && avLen == 8) {
                return targetInfo.readULongLE(pos)
            }
            pos += avLen
        }
        return null
    }

    private fun addOrUpdateMicFlagInTargetInfo(targetInfo: ByteArray): ByteArray {
        var pos = 0
        var flagsValueOffset = -1
        var eolOffset = -1
        while (pos + 4 <= targetInfo.size) {
            val avId = targetInfo.readUShortLE(pos)
            val avLen = targetInfo.readUShortLE(pos + 2).toInt()
            if (avId == MSV_AV_EOL) {
                eolOffset = pos
                break
            }
            if (avId == MSV_AV_FLAGS && avLen == 4) {
                flagsValueOffset = pos + 4
            }
            pos += 4 + avLen
        }

        if (flagsValueOffset >= 0) {
            val copy = targetInfo.copyOf()
            val existing = copy.readUIntLE(flagsValueOffset)
            copy.writeUIntLE(flagsValueOffset, existing or 0x00000002u)
            return copy
        }

        val insertPos = if (eolOffset >= 0) eolOffset else targetInfo.size
        val out = ByteArray(insertPos + 8 + 4)
        targetInfo.copyInto(out, 0, 0, insertPos)
        out.writeUShortLE(insertPos, MSV_AV_FLAGS)
        out.writeUShortLE(insertPos + 2, 4u)
        out.writeUIntLE(insertPos + 4, 0x00000002u)
        // Trailing 4 bytes are MSV_AV_EOL (0x0000, len 0x0000)
        return out
    }

    private fun asn1Wrap(tag: Int, content: ByteArray): ByteArray {
        val lenBytes = encodeAsn1Length(content.size)
        val out = ByteArray(1 + lenBytes.size + content.size)
        out[0] = tag.toByte()
        lenBytes.copyInto(out, 1)
        content.copyInto(out, 1 + lenBytes.size)
        return out
    }

    private fun encodeAsn1Length(length: Int): ByteArray {
        return when {
            length < 0x80 -> byteArrayOf(length.toByte())
            length <= 0xFF -> byteArrayOf(0x81.toByte(), length.toByte())
            length <= 0xFFFF -> byteArrayOf(
                0x82.toByte(),
                ((length ushr 8) and 0xFF).toByte(),
                (length and 0xFF).toByte()
            )
            else -> byteArrayOf(
                0x83.toByte(),
                ((length ushr 16) and 0xFF).toByte(),
                ((length ushr 8) and 0xFF).toByte(),
                (length and 0xFF).toByte()
            )
        }
    }
}
