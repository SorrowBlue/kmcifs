package com.sorrowblue.kmcifs.client.protocol

import com.sorrowblue.kmcifs.client.protocol.ByteUtils.decodeFromUtf16LE
import com.sorrowblue.kmcifs.client.protocol.ByteUtils.encodeToUtf16LE
import com.sorrowblue.kmcifs.client.protocol.ByteUtils.readUIntLE
import com.sorrowblue.kmcifs.client.protocol.ByteUtils.writeUIntLE
import com.sorrowblue.kmcifs.client.protocol.ByteUtils.writeUShortLE

/**
 * Executes DCE/RPC `NetrShareEnum` (Level 1) over the `srvsvc` named pipe on `IPC$`
 * to enumerate shared folders ([SmbShareInfo]) on the server (`[MS-SRVS] 3.1.4.8`).
 */
internal object DceRpcSrvSvc {

    // SRVSVC UUID: 4b324fc8-1670-01d3-1278-5a47bf6ee188, v3.0
    private val SRVSVC_UUID_BYTES = byteArrayOf(
        0xc8.toByte(), 0x4f, 0x32, 0x4b,
        0x70, 0x16,
        0xd3.toByte(), 0x01,
        0x12, 0x78,
        0x5a, 0x47, 0xbf.toByte(), 0x6e, 0xe1.toByte(), 0x88.toByte()
    )

    // NDR Transfer Syntax UUID: 8a885d04-1ceb-11c9-9fe8-08002b104860, v2.0
    private val NDR32_UUID_BYTES = byteArrayOf(
        0x04, 0x5d, 0x88.toByte(), 0x8a.toByte(),
        0xeb.toByte(), 0x1c,
        0xc9.toByte(), 0x11,
        0x9f.toByte(), 0xe8.toByte(),
        0x08, 0x00, 0x2b, 0x10, 0x48, 0x60
    )

    /**
     * Builds a 72-byte DCE/RPC `Bind` PDU.
     */
    fun buildBindPdu(callId: UInt = 1u): ByteArray {
        val pdu = ByteArray(72)
        pdu[0] = 5 // rpc_vers = 5
        pdu[1] = 0 // rpc_vers_minor = 0
        pdu[2] = 11 // PTYPE = bind (11)
        pdu[3] = 0x03 // pfc_flags = PFC_FIRST_FRAG | PFC_LAST_FRAG
        // Packed Data Representation: Little-endian, ASCII, IEEE float (0x10, 0x00, 0x00, 0x00)
        pdu[4] = 0x10
        pdu.writeUShortLE(8, 72u) // frag_length = 72
        pdu.writeUShortLE(10, 0u) // auth_length = 0
        pdu.writeUIntLE(12, callId)
        pdu.writeUShortLE(16, 4280u) // max_xmit_frag
        pdu.writeUShortLE(18, 4280u) // max_recv_frag
        pdu.writeUIntLE(20, 0u) // assoc_group_id = 0

        // p_context_elem_t: n_context_elem = 1
        pdu[24] = 1
        // p_cont_elem_t (offset 28): p_cont_id = 0, n_transfer_syn = 1
        pdu.writeUShortLE(28, 0u)
        pdu[30] = 1
        // abstract_syntax: SRVSVC v3.0 (offset 32..51)
        SRVSVC_UUID_BYTES.copyInto(pdu, 32)
        pdu.writeUShortLE(48, 3u) // version 3
        pdu.writeUShortLE(50, 0u) // minor 0
        // transfer_syntax: NDR32 v2.0 (offset 52..71)
        NDR32_UUID_BYTES.copyInto(pdu, 52)
        pdu.writeUIntLE(68, 2u) // version 2.0

        return pdu
    }

    /**
     * Validates a DCE/RPC `Bind_ack` PDU (`PTYPE = 12`).
     */
    fun verifyBindAck(pdu: ByteArray) {
        require(pdu.size >= 24 && pdu[0].toInt() == 5 && pdu[2].toInt() == 12) {
            "Invalid DCE/RPC Bind_ack PDU received"
        }
    }

    /**
     * Builds a `NetrShareEnum` (`Opnum = 15`, `Level = 1`) request PDU.
     */
    fun buildNetrShareEnumRequest(serverName: String, callId: UInt = 2u): ByteArray {
        val uncServer = "\\\\${serverName.trimStart('\\')}\u0000"
        val charCount = uncServer.length
        val utf16Bytes = uncServer.encodeToUtf16LE()
        val padLen = (4 - (utf16Bytes.size % 4)) % 4

        // NDR Stub Data:
        // - ServerName Referent ID (4 bytes: 0x00020000)
        // - MaxCount (4 bytes), Offset (4 bytes = 0), ActualCount (4 bytes)
        // - UTF-16LE chars + 4-byte alignment padding
        // - InfoStruct.Level (4 bytes = 1)
        // - InfoStruct.ShareInfo Union Switch (4 bytes = 1)
        // - InfoStruct.ShareInfo.ShareInfo1 Ptr Referent ID (4 bytes: 0x00020004)
        // - ShareInfo1Container.EntriesRead (4 bytes = 0)
        // - ShareInfo1Container.Buffer Ptr (4 bytes = 0)
        // - PreferedMaximumLength (4 bytes = 0xFFFFFFFF)
        // - ResumeHandle Referent ID (4 bytes: 0x00020008)
        // - ResumeHandle Value (4 bytes = 0)
        val stubSize = 16 + utf16Bytes.size + padLen + 32
        val stub = ByteArray(stubSize)
        var pos = 0

        stub.writeUIntLE(pos, 0x00020000u); pos += 4
        stub.writeUIntLE(pos, charCount.toUInt()); pos += 4
        stub.writeUIntLE(pos, 0u); pos += 4
        stub.writeUIntLE(pos, charCount.toUInt()); pos += 4
        utf16Bytes.copyInto(stub, pos); pos += utf16Bytes.size + padLen

        stub.writeUIntLE(pos, 1u); pos += 4 // Level = 1
        stub.writeUIntLE(pos, 1u); pos += 4 // Switch = 1
        stub.writeUIntLE(pos, 0x00020004u); pos += 4 // Container Ptr
        stub.writeUIntLE(pos, 0u); pos += 4 // EntriesRead = 0
        stub.writeUIntLE(pos, 0u); pos += 4 // Buffer Ptr = NULL
        stub.writeUIntLE(pos, 0xFFFFFFFFu); pos += 4 // PreferedMaximumLength = -1
        stub.writeUIntLE(pos, 0x00020008u); pos += 4 // ResumeHandle Ptr
        stub.writeUIntLE(pos, 0u) // ResumeHandle = 0

        val totalSize = 24 + stub.size
        val pdu = ByteArray(totalSize)
        pdu[0] = 5
        pdu[1] = 0
        pdu[2] = 0 // PTYPE = request (0)
        pdu[3] = 0x03 // PFC_FIRST_FRAG | PFC_LAST_FRAG
        pdu[4] = 0x10 // Little-endian NDR
        pdu.writeUShortLE(8, totalSize.toUShort())
        pdu.writeUShortLE(10, 0u)
        pdu.writeUIntLE(12, callId)
        pdu.writeUIntLE(16, stub.size.toUInt()) // alloc_hint
        pdu.writeUShortLE(20, 0u) // p_cont_id = 0
        pdu.writeUShortLE(22, 15u) // opnum = 15 (NetrShareEnum)
        stub.copyInto(pdu, 24)
        return pdu
    }

    /**
     * Extracts the list of shared folders from the reassembled NDR stub data of a `NetrShareEnum` DCE/RPC response.
     */
    fun parseNetrShareEnumResponse(stubData: ByteArray): List<SmbShareInfo> {
        if (stubData.size < 20) return emptyList()
        var pos = 0
        val level = stubData.readUIntLE(pos); pos += 4
        val switchLevel = stubData.readUIntLE(pos); pos += 4
        val containerPtr = stubData.readUIntLE(pos); pos += 4
        if (level != 1u || switchLevel != 1u || containerPtr == 0u) return emptyList()

        val entriesRead = stubData.readUIntLE(pos).toInt(); pos += 4
        val bufferPtr = stubData.readUIntLE(pos); pos += 4
        if (entriesRead <= 0 || bufferPtr == 0u) return emptyList()

        // Conformant array MaxCount
        if (pos > stubData.size - 4) return emptyList()
        val maxCount = stubData.readUIntLE(pos).toInt(); pos += 4
        if (maxCount <= 0) return emptyList()
        val maxPossibleEntries = (stubData.size - pos) / 12
        val count = minOf(entriesRead, maxCount, maxPossibleEntries)

        // Each SHARE_INFO_1 fixed header in NDR is 12 bytes:
        // shi1_netname (ptr 4B), shi1_type (uint32 4B), shi1_remark (ptr 4B)
        data class RawEntry(val namePtr: UInt, val type: UInt, val remarkPtr: UInt)
        val rawEntries = ArrayList<RawEntry>(count)
        for (i in 0 until count) {
            if (pos > stubData.size - 12) break
            val namePtr = stubData.readUIntLE(pos)
            val shareType = stubData.readUIntLE(pos + 4)
            val remarkPtr = stubData.readUIntLE(pos + 8)
            pos += 12
            rawEntries.add(RawEntry(namePtr, shareType, remarkPtr))
        }

        fun readNdrString(): String {
            // Align to 4 bytes
            pos = (pos + 3) and 3.inv()
            if (pos > stubData.size - 12) return ""
            // maxCount, offset, actualCount
            val actualCount = stubData.readUIntLE(pos + 8).toInt()
            pos += 12
            if (actualCount <= 0 || actualCount > (stubData.size - pos) / 2) return ""
            val byteLen = actualCount * 2
            val str = stubData.decodeFromUtf16LE(pos, byteLen).trimEnd('\u0000')
            pos += byteLen
            pos = (pos + 3) and 3.inv()
            return str
        }

        val shares = ArrayList<SmbShareInfo>(rawEntries.size)
        for ((namePtr, type, remarkPtr) in rawEntries) {
            val name = if (namePtr != 0u) readNdrString() else ""
            val comment = if (remarkPtr != 0u) readNdrString() else ""
            shares.add(
                SmbShareInfo(
                    name = name,
                    rawType = type,
                    comment = comment
                )
            )
        }
        return shares
    }
}
