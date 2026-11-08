package com.sorrowblue.kmcifs.client

import com.sorrowblue.kmcifs.client.auth.SmbCredentials
import com.sorrowblue.kmcifs.client.crypto.Md4
import com.sorrowblue.kmcifs.client.crypto.Md5
import com.sorrowblue.kmcifs.client.crypto.Rc4
import com.sorrowblue.kmcifs.client.crypto.Sha512
import com.sorrowblue.kmcifs.client.crypto.Smb3Kdf
import com.sorrowblue.kmcifs.client.protocol.ByteUtils.decodeFromUtf16LE
import com.sorrowblue.kmcifs.client.protocol.ByteUtils.encodeToUtf16LE
import com.sorrowblue.kmcifs.client.protocol.ByteUtils.readUIntLE
import com.sorrowblue.kmcifs.client.protocol.ByteUtils.readULongLE
import com.sorrowblue.kmcifs.client.protocol.ByteUtils.readUShortLE
import com.sorrowblue.kmcifs.client.protocol.ByteUtils.writeUIntLE
import com.sorrowblue.kmcifs.client.protocol.ByteUtils.writeULongLE
import com.sorrowblue.kmcifs.client.protocol.ByteUtils.writeUShortLE
import com.sorrowblue.kmcifs.client.protocol.NtStatus
import com.sorrowblue.kmcifs.client.protocol.SmbCipherId
import com.sorrowblue.kmcifs.client.protocol.SmbCommand
import com.sorrowblue.kmcifs.client.protocol.SmbCreateOptions
import com.sorrowblue.kmcifs.client.protocol.SmbDialect
import com.sorrowblue.kmcifs.client.protocol.SmbException
import com.sorrowblue.kmcifs.client.protocol.SmbFileAttributes
import com.sorrowblue.kmcifs.client.protocol.SmbHeader
import com.sorrowblue.kmcifs.client.protocol.SmbMessages
import com.sorrowblue.kmcifs.client.protocol.SmbPacketTransport
import com.sorrowblue.kmcifs.client.protocol.SmbShareType
import com.sorrowblue.kmcifs.client.protocol.SmbTransformHeader
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withContext
import kotlinx.io.readString
import kotlinx.io.writeString
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * SMB 3.1.1 (NTLMv2 認証 + Preauth Integrity Hash + AES-128-GCM 暗号化) の
 * 全コマンド（共有フォルダ一覧、ディレクトリ一覧、ファイル作成・読み書き、ロック、リネーム、削除）を検証するテスト。
 */
class SmbClientEndToEndTest {

    @Test
    fun testFullSmb311EncryptedWorkflow() = runTest {
        val credentials = SmbCredentials(
            username = "alice",
            password = "SecretPassword123!",
            domain = "WORKGROUP"
        )
        val mockTransport = MockSmb3ServerTransport(credentials)
        val config = SmbConfig(
            encryptionPolicy = SmbEncryptionPolicy.REQUIRED,
            preferEncryption = true
        )

        val client = SmbClient("192.168.1.10", 445, config, mockTransport)
        client.initializeSession(credentials)

        assertEquals(SmbDialect.SMB_3_1_1, client.negotiatedDialect)
        assertEquals(SmbCipherId.AES_128_GCM, client.negotiatedCipher)
        assertTrue(client.isSessionEncrypted)

        // 1. 共有フォルダ一覧の取得 (IPC$ -> srvsvc -> NetrShareEnum)
        val shares = client.listShares(includeHidden = false)
        assertEquals(1, shares.size)
        assertEquals("PublicDocs", shares[0].name)
        assertEquals(SmbShareType.DISKTREE, shares[0].type)
        assertEquals("Shared Documents", shares[0].comment)

        // 2. 共有フォルダへの接続とファイル操作
        val share = client.connectShare("PublicDocs")

        // 3. ファイルの書き込みと読み取り
        share.writeText("notes/hello.txt", "Hello Kotlin Multiplatform SMB3!")
        assertTrue(share.exists("notes/hello.txt"))
        val content = share.readText("notes/hello.txt")
        assertEquals("Hello Kotlin Multiplatform SMB3!", content)

        // 4. ディレクトリ一覧の取得
        val dirEntries = share.listDirectory("notes")
        assertEquals(1, dirEntries.size)
        assertEquals("hello.txt", dirEntries[0].name)
        assertEquals(32L, dirEntries[0].size)

        // 5. ファイルオープン・排他バイト範囲ロック・アンロック・サイズ変更
        val opened = share.openFile("notes/hello.txt")
        opened.lock(offset = 0L, length = 16L, exclusive = true)
        opened.unlock(offset = 0L, length = 16L)
        opened.setLength(5L)
        assertEquals("Hello", opened.readAll().decodeToString())
        opened.closeSuspend()

        // 6. リネームと削除
        share.rename("notes/hello.txt", "notes/greeting.txt")
        assertFalse(share.exists("notes/hello.txt"))
        assertTrue(share.exists("notes/greeting.txt"))

        share.deleteFile("notes/greeting.txt")
        assertFalse(share.exists("notes/greeting.txt"))

        share.closeSuspend()
        client.closeSuspend()

        assertTrue(mockTransport.encryptedPacketsCount >= 10, "All post-auth packets should be encrypted via SMB3 Transform Header")
    }

    @Test
    fun testRandomAccessFileOperations() = runTest {
        val credentials = SmbCredentials(
            username = "alice",
            password = "SecretPassword123!",
            domain = "WORKGROUP",
        )
        val mockTransport = MockSmb3ServerTransport(credentials)
        val config = SmbConfig(
            encryptionPolicy = SmbEncryptionPolicy.REQUIRED,
            preferEncryption = true,
        )

        val client = SmbClient("192.168.1.10", 445, config, mockTransport)
        client.initializeSession(credentials)
        val share = client.connectShare("PublicDocs")

        // 1. Open in "rw" mode, write bytes, seek, overwrite, check position & length
        val raf = share.openRandomAccessFile("data/random.bin", "rw")
        assertTrue(raf.isOpen)
        assertEquals(0L, raf.position)
        assertEquals(0L, raf.length)

        raf.write("ABCDEFGHIJ".encodeToByteArray())
        assertEquals(10L, raf.position)
        assertEquals(10L, raf.length)

        // Seek to offset 3 and overwrite 3 bytes ("DEF" -> "xyz")
        raf.seek(3L)
        assertEquals(3L, raf.position)
        raf.write("xyz".encodeToByteArray(), 0, 3)
        assertEquals(6L, raf.position)
        assertEquals(10L, raf.length)

        // Read single byte at position 6 ('G')
        assertEquals('G'.code.toByte(), raf.readByte())
        assertEquals(7L, raf.position)

        // Seek back to 0 and read into buffer
        raf.seek(0L)
        val buf = ByteArray(10)
        val bytesRead = raf.read(buf)
        assertEquals(10, bytesRead)
        assertEquals("ABCxyzGHIJ", buf.decodeToString())
        assertEquals(10L, raf.position)

        // At EOF: read() returns -1, read(buf) returns -1, readByte() throws SmbEndOfFileException
        assertEquals(-1, raf.read())
        assertEquals(-1, raf.read(buf))
        assertFailsWith<SmbEndOfFileException> {
            raf.readByte()
        }

        // Write primitive values & read them back
        raf.seek(10L)
        raf.writeByte(0x7F)
        raf.writeInt(0x12345678)
        raf.writeLong(0x0102030405060708L)
        assertEquals(23L, raf.length)

        raf.seek(10L)
        assertEquals(0x7F.toByte(), raf.readByte())
        assertEquals(0x12345678, raf.readInt())
        assertEquals(0x0102030405060708L, raf.readLong())
        assertEquals(23L, raf.position)

        // Truncate via setLength and verify position is clamped
        raf.setLength(6L)
        assertEquals(6L, raf.length)
        assertEquals(6L, raf.position)
        raf.closeSuspend()
        assertFalse(raf.isOpen)

        // 2. Re-open via SmbRandomAccessFile(share, path, "r", bufferSize = 4).open() in buffered read-only mode
        SmbRandomAccessFile(share, "data/random.bin", "r", bufferSize = 4).open().use { readOnlyRaf ->
            assertEquals(6L, readOnlyRaf.length)
            assertEquals('A'.code.toByte(), readOnlyRaf.readByte())
            assertEquals(1L, readOnlyRaf.position)

            val remaining = ByteArray(5)
            readOnlyRaf.readFully(remaining)
            assertEquals("BCxyz", remaining.decodeToString())
            assertEquals(6L, readOnlyRaf.position)

            assertFailsWith<IllegalStateException> {
                readOnlyRaf.write(0x41)
            }
        }

        share.closeSuspend()
        client.closeSuspend()
    }

    @Test
    fun testKotlinxIoSourceAndSink() = runTest {
        val credentials = SmbCredentials("alice", "SecretPassword123!", "WORKGROUP")
        val mockTransport = MockSmb3ServerTransport(credentials)
        val client = SmbClient("192.168.1.10", 445, SmbConfig(), mockTransport)
        client.initializeSession(credentials)
        val share = client.connectShare("PublicDocs")

        // Write via kotlinx.io.Sink
        share.openSink("streams/message.txt", overwrite = true).use { sink ->
            sink.writeString("Hello ")
            sink.flush()
        }

        // Append via kotlinx.io.Sink
        share.openSink("streams/message.txt", append = true).use { sink ->
            sink.writeString("kotlinx-io!")
            sink.flush()
        }

        // Read via kotlinx.io.Source
        val readBack = share.openSource("streams/message.txt").use { source ->
            source.readString()
        }
        assertEquals("Hello kotlinx-io!", readBack)

        share.close()
        client.closeSuspend()
    }

    @Test
    fun testDeleteRecursivelyAndPathNormalization() = runTest {
        val credentials = SmbCredentials("alice", "SecretPassword123!", "WORKGROUP")
        val mockTransport = MockSmb3ServerTransport(credentials)
        val client = SmbClient("192.168.1.10", 445, SmbConfig(), mockTransport)
        client.initializeSession(credentials)
        val share = client.connectShare("PublicDocs")

        share.createDirectory("/books/")
        share.createDirectory("/books/manga/")
        share.writeText("/books/manga/vol1.txt", "Volume 1")
        share.writeText("/books/manga/vol2.txt", "Volume 2")
        share.writeText("/books/readme.txt", "Readme")

        // Trailing slash in listDirectory & stat should be normalized properly
        val mangaEntries = share.listDirectory("/books/manga/")
        assertEquals(2, mangaEntries.size)
        assertTrue(share.exists("/books/manga/vol1.txt/"))

        // Recursive delete of /books/
        share.deleteRecursively("/books/")
        assertFalse(share.exists("/books/manga/vol1.txt"))
        assertFalse(share.exists("/books/readme.txt"))
        assertFalse(share.exists("/books"))

        share.closeSuspend()
        client.closeSuspend()
    }

    @Test
    fun testPacketSigningVerificationAndErrorHandling() = runTest {
        val credentials = SmbCredentials("alice", "SecretPassword123!", "WORKGROUP")
        val mockTransport = MockSmb3ServerTransport(credentials, encryptShare = false)
        val config = SmbConfig(
            encryptionPolicy = SmbEncryptionPolicy.DISABLED,
            alwaysSign = true,
            verifyServerSignatures = true,
        )
        val client = SmbClient("192.168.1.10", 445, config, mockTransport)
        client.initializeSession(credentials)
        val share = client.connectShare("PublicDocs")

        share.writeText("signed.txt", "Signed payload")
        assertEquals("Signed payload", share.readText("signed.txt"))

        val ex = assertFailsWith<SmbException> {
            share.stat("non_existent_file.txt")
        }
        assertEquals(NtStatus.STATUS_OBJECT_NAME_NOT_FOUND, ex.ntStatus)
        assertFalse(share.exists("non_existent_file.txt"))

        share.closeSuspend()
        client.closeSuspend()
    }

    @Test
    fun testConcurrentReadersAndOmittedCompoundErrorTail() = runTest {
        val credentials = SmbCredentials("alice", "SecretPassword123!", "WORKGROUP")
        val mockTransport = MockSmb3ServerTransport(
            expectedCredentials = credentials,
            encryptShare = true,
            omitRelatedErrorResponses = true,
        )
        val client = SmbClient("192.168.1.10", 445, SmbConfig(), mockTransport)
        client.initializeSession(credentials)
        val share = client.connectShare("PublicDocs")

        // 1. 先頭 CREATE 失敗時にサーバーが後続 CLOSE のレスポンスを省略してもハングせず即座にエラー返却されることを検証
        assertFalse(share.exists("missing_archive.cbz"))

        // 2. 複数のスレッド/コルーチンから同一 SmbClient 上で並列にランダムアクセス読み取りを実行しても MessageId の競合が起きないことを検証
        for (i in 0 until 4) {
            share.writeBytes("archive_$i.bin", ByteArray(4096) { idx -> ((i * 31 + idx) and 0xFF).toByte() })
        }

        withContext(Dispatchers.Default) {
            val jobs = (0 until 4).map { workerIdx ->
                async {
                    share.openRandomAccessFile("archive_$workerIdx.bin", "r", bufferSize = 0).use { raf ->
                        val buf = ByteArray(128)
                        for (step in 0 until 20) {
                            val offset = (step * 173L) % (4096 - buf.size)
                            raf.seek(offset)
                            raf.readFully(buf)
                            for (bIdx in buf.indices) {
                                val expected = ((workerIdx * 31 + offset.toInt() + bIdx) and 0xFF).toByte()
                                assertEquals(expected, buf[bIdx])
                            }
                        }
                    }
                }
            }
            jobs.awaitAll()
        }

        share.closeSuspend()
        client.closeSuspend()
    }

    /**
     * テスト用のインメモリ SMB 3.1.1 サーバートランスポート。
     */
    private class MockSmb3ServerTransport(
        private val expectedCredentials: SmbCredentials,
        private val encryptShare: Boolean = true,
        private val omitRelatedErrorResponses: Boolean = false,
    ) : SmbPacketTransport {

        private val responseQueue = ArrayDeque<ByteArray>()
        private var preauthHash = ByteArray(64)
        private val serverChallenge = ByteArray(8) { (0x11 * (it + 1)).toByte() }
        private var serverSigningKey: ByteArray? = null
        private var serverEncryptionKey: ByteArray? = null // ServerOutKey (SMBS2CCipherKey)
        private var serverDecryptionKey: ByteArray? = null // ServerInKey (SMBC2SCipherKey)
        private val sessionId: ULong = 0x1000200030004000uL

        private val files = mutableMapOf<String, ByteArray>()
        private val directories = mutableSetOf("", "notes", "data", "streams")
        private val openHandles = mutableMapOf<ULong, String>()
        private val queriedDirs = mutableSetOf<ULong>()
        private var nextHandleId: ULong = 100uL
        private var lastSeenMessageId: Long = -1L

        var encryptedPacketsCount: Int = 0
            private set

        override suspend fun sendPacket(packet: ByteArray) {
            val wasEncrypted = SmbTransformHeader.isTransformPacket(packet)
            val plainPacket = if (wasEncrypted) {
                encryptedPacketsCount++
                SmbTransformHeader.decryptPacket(packet, SmbCipherId.AES_128_GCM, serverDecryptionKey!!)
            } else {
                packet
            }

            val reqParts = SmbMessages.splitCompoundPacket(plainPacket)
            var lastCompoundHandleId: ULong = 0uL
            var compoundFailedStatus: UInt = NtStatus.STATUS_SUCCESS
            val respParts = mutableListOf<ByteArray>()

            for ((partIndex, rawPart) in reqParts.withIndex()) {
                val reqHeader = SmbHeader.decode(rawPart)
                val msgIdLong = reqHeader.messageId.toLong()
                check(msgIdLong > lastSeenMessageId) {
                    "Out-of-order or duplicate MessageId detected: received=$msgIdLong, lastSeen=$lastSeenMessageId"
                }
                lastSeenMessageId = msgIdLong

                val isRelated = (reqHeader.flags and SmbHeader.SMB2_FLAGS_RELATED_OPERATIONS) != 0u
                if (partIndex > 0 && isRelated) {
                    check(reqHeader.treeId == 0xFFFFFFFFu) {
                        "Related compound request must have TreeId=0xFFFFFFFF (got ${reqHeader.treeId})"
                    }
                    check(reqHeader.sessionId == 0xFFFF_FFFF_FFFF_FFFFuL) {
                        "Related compound request must have SessionId=0xFFFFFFFFFFFFFFFF (got ${reqHeader.sessionId})"
                    }
                }
                if (isRelated && compoundFailedStatus != NtStatus.STATUS_SUCCESS) {
                    if (omitRelatedErrorResponses) {
                        continue
                    }
                    respParts.add(buildSimpleResponse(reqHeader, 8, compoundFailedStatus))
                    continue
                }

                val plainReq = rawPart.copyOf()
                // Replace sentinel FileId (0xFFFF_FFFF_FFFF_FFFF) in related requests with lastCompoundHandleId
                if (isRelated && lastCompoundHandleId != 0uL) {
                    replaceRelatedFileId(reqHeader.command, plainReq, lastCompoundHandleId)
                }

                val singleResp = when (reqHeader.command) {
                    SmbCommand.NEGOTIATE -> {
                        preauthHash = updateHash(preauthHash, plainReq)
                        val resp = buildNegotiateResponse(reqHeader.messageId)
                        preauthHash = updateHash(preauthHash, resp)
                        resp
                    }
                    SmbCommand.SESSION_SETUP -> {
                        preauthHash = updateHash(preauthHash, plainReq)
                        val secBufOffset = plainReq.readUShortLE(SmbHeader.SIZE + 12).toInt()
                        val secBufLen = plainReq.readUShortLE(SmbHeader.SIZE + 14).toInt()
                        val secBlob = plainReq.copyOfRange(secBufOffset, secBufOffset + secBufLen)

                        if (reqHeader.sessionId == 0uL) {
                            val resp = buildSessionSetupChallenge(reqHeader.messageId)
                            preauthHash = updateHash(preauthHash, resp)
                            resp
                        } else {
                            deriveSessionKeysFromType3(secBlob)
                            buildSessionSetupSuccess(reqHeader.messageId)
                        }
                    }
                    SmbCommand.TREE_CONNECT -> buildTreeConnectResponse(reqHeader)
                    SmbCommand.TREE_DISCONNECT, SmbCommand.LOGOFF -> buildSimpleResponse(reqHeader, 4)
                    SmbCommand.CREATE -> {
                        val resp = handleCreate(reqHeader, plainReq)
                        val respHdr = SmbHeader.decode(resp)
                        if (respHdr.status == NtStatus.STATUS_SUCCESS) {
                            lastCompoundHandleId = resp.readULongLE(SmbHeader.SIZE + 72)
                        } else {
                            compoundFailedStatus = respHdr.status
                        }
                        resp
                    }
                    SmbCommand.CLOSE, SmbCommand.FLUSH -> {
                        val vId = plainReq.readULongLE(SmbHeader.SIZE + 16)
                        if (reqHeader.command == SmbCommand.CLOSE) {
                            openHandles.remove(vId)
                            queriedDirs.remove(vId)
                        }
                        buildSimpleResponse(reqHeader, if (reqHeader.command == SmbCommand.CLOSE) 60 else 4)
                    }
                    SmbCommand.WRITE -> handleWrite(reqHeader, plainReq)
                    SmbCommand.READ -> handleRead(reqHeader, plainReq)
                    SmbCommand.QUERY_DIRECTORY -> handleQueryDirectory(reqHeader, plainReq)
                    SmbCommand.LOCK -> buildSimpleResponse(reqHeader, 4)
                    SmbCommand.SET_INFO -> handleSetInfo(reqHeader, plainReq)
                    SmbCommand.IOCTL -> handleIoctl(reqHeader, plainReq)
                    else -> buildSimpleResponse(reqHeader, 4, NtStatus.STATUS_NOT_SUPPORTED)
                }
                respParts.add(singleResp)
            }

            val signEach: ((ByteArray) -> Unit)? = if (!wasEncrypted && serverSigningKey != null) {
                { slice ->
                    val hdr = SmbHeader.decode(slice)
                    if (hdr.command != SmbCommand.NEGOTIATE && hdr.command != SmbCommand.SESSION_SETUP) {
                        SmbHeader.signPacket(slice, SmbDialect.SMB_3_1_1, serverSigningKey!!)
                    }
                }
            } else {
                null
            }
            val plainResp = SmbMessages.buildCompoundRelatedPacket(respParts, signEach)

            val wireResp = if (wasEncrypted && serverEncryptionKey != null) {
                SmbTransformHeader.encryptPacket(
                    plainSmbPacket = plainResp,
                    sessionId = sessionId,
                    cipherId = SmbCipherId.AES_128_GCM,
                    encryptionKey = serverEncryptionKey!!
                )
            } else {
                plainResp
            }
            responseQueue.addLast(wireResp)
        }

        private fun replaceRelatedFileId(command: SmbCommand, packet: ByteArray, handleId: ULong) {
            val b = SmbHeader.SIZE
            val fileIdOffset = when (command) {
                SmbCommand.CLOSE, SmbCommand.FLUSH, SmbCommand.QUERY_DIRECTORY, SmbCommand.IOCTL -> b + 8
                SmbCommand.READ, SmbCommand.WRITE, SmbCommand.SET_INFO -> b + 16
                else -> return
            }
            if (packet.readULongLE(fileIdOffset) == 0xFFFF_FFFF_FFFF_FFFFuL) {
                packet.writeULongLE(fileIdOffset, handleId)
                packet.writeULongLE(fileIdOffset + 8, handleId)
            }
        }

        override suspend fun receivePacket(): ByteArray = responseQueue.removeFirst()

        override fun close() {
            responseQueue.clear()
        }

        private fun updateHash(h: ByteArray, p: ByteArray): ByteArray {
            val combined = ByteArray(h.size + p.size)
            h.copyInto(combined, 0)
            p.copyInto(combined, h.size)
            return Sha512.digest(combined)
        }

        private fun buildNegotiateResponse(messageId: ULong): ByteArray {
            // Negotiate Context: SMB2_ENCRYPTION_CAPABILITIES (0x0002), CipherCount=1, Cipher=AES_128_GCM (0x0002)
            val ctx = ByteArray(14)
            ctx.writeUShortLE(0, 0x0002u) // Type = SMB2_ENCRYPTION_CAPABILITIES
            ctx.writeUShortLE(2, 6u) // DataLength = 6
            ctx.writeUShortLE(8, 1u) // CipherCount = 1
            ctx.writeUShortLE(10, SmbCipherId.AES_128_GCM.code)
            ctx.writeUShortLE(12, 0u) // Padding

            val ctxOffset = 64 + 64 // 128 (8-byte aligned)
            val packet = ByteArray(ctxOffset + ctx.size)
            val header = SmbHeader(
                command = SmbCommand.NEGOTIATE,
                flags = SmbHeader.SMB2_FLAGS_SERVER_TO_REDIR,
                messageId = messageId,
            )
            header.encodeInto(packet, 0)

            val b = SmbHeader.SIZE
            packet.writeUShortLE(b, 65u)
            packet.writeUShortLE(b + 2, 0x0001u) // SigningEnabled
            packet.writeUShortLE(b + 4, SmbDialect.SMB_3_1_1.code)
            packet.writeUShortLE(b + 6, 1u) // NegotiateContextCount = 1
            packet.writeUIntLE(b + 24, SmbMessages.SMB2_GLOBAL_CAP_LARGE_MTU or SmbMessages.SMB2_GLOBAL_CAP_ENCRYPTION)
            packet.writeUIntLE(b + 28, 65536u)
            packet.writeUIntLE(b + 32, 65536u)
            packet.writeUIntLE(b + 36, 65536u)
            packet.writeUShortLE(b + 56, 128u) // SecurityBufferOffset
            packet.writeUShortLE(b + 58, 0u) // SecurityBufferLength
            packet.writeUIntLE(b + 60, ctxOffset.toUInt())

            ctx.copyInto(packet, ctxOffset)
            return packet
        }

        private fun buildSessionSetupChallenge(messageId: ULong): ByteArray {
            // Minimal NTLMSSP Type 2 message
            val type2 = ByteArray(56)
            "NTLMSSP\u0000".encodeToByteArray().copyInto(type2, 0)
            type2.writeUIntLE(8, 2u)
            val flags = 0x62888215u
            type2.writeUIntLE(20, flags)
            serverChallenge.copyInto(type2, 24)
            // TargetInfo: MSV_AV_EOL (4 bytes at offset 48)
            type2.writeUShortLE(40, 4u)
            type2.writeUShortLE(42, 4u)
            type2.writeUIntLE(44, 48u)

            val packet = ByteArray(SmbHeader.SIZE + 8 + type2.size)
            val header = SmbHeader(
                status = NtStatus.STATUS_MORE_PROCESSING_REQUIRED,
                command = SmbCommand.SESSION_SETUP,
                flags = SmbHeader.SMB2_FLAGS_SERVER_TO_REDIR,
                messageId = messageId,
                sessionId = sessionId,
            )
            header.encodeInto(packet, 0)
            val b = SmbHeader.SIZE
            packet.writeUShortLE(b, 9u)
            packet.writeUShortLE(b + 2, 0u)
            packet.writeUShortLE(b + 4, (SmbHeader.SIZE + 8).toUShort())
            packet.writeUShortLE(b + 6, type2.size.toUShort())
            type2.copyInto(packet, SmbHeader.SIZE + 8)
            return packet
        }

        private fun deriveSessionKeysFromType3(secBlob: ByteArray) {
            val sig = "NTLMSSP\u0000".encodeToByteArray()
            var ntlmStart = 0
            outer@ for (i in 0..secBlob.size - sig.size) {
                for (j in sig.indices) if (secBlob[i + j] != sig[j]) continue@outer
                ntlmStart = i
                break
            }
            val type3 = secBlob.copyOfRange(ntlmStart, secBlob.size)
            val ntRespLen = type3.readUShortLE(20).toInt()
            val ntRespOff = type3.readUIntLE(24).toInt()
            val ntProofStr = type3.copyOfRange(ntRespOff, ntRespOff + 16)
            require(ntRespLen > 16)

            val encSessionKeyLen = type3.readUShortLE(52).toInt()
            val encSessionKeyOff = type3.readUIntLE(56).toInt()
            val encSessionKey = type3.copyOfRange(encSessionKeyOff, encSessionKeyOff + encSessionKeyLen)

            val ntlmHash = Md4.digest(expectedCredentials.password.encodeToUtf16LE())
            val userDom = (expectedCredentials.username.uppercase() + expectedCredentials.domain).encodeToUtf16LE()
            val responseKeyNT = Md5.hmac(ntlmHash, userDom)
            val sessionBaseKey = Md5.hmac(responseKeyNT, ntProofStr)
            val exportedSessionKey = if (encSessionKey.isNotEmpty()) {
                Rc4.process(sessionBaseKey, encSessionKey)
            } else {
                sessionBaseKey
            }

            val derived = Smb3Kdf.deriveKeys(SmbDialect.SMB_3_1_1, exportedSessionKey, preauthHash)
            serverSigningKey = derived.signingKey
            // From server's perspective: client's encryptionKey (C2S) is server's decryptionKey, and S2C is server's encryptionKey
            serverDecryptionKey = derived.encryptionKey
            serverEncryptionKey = derived.decryptionKey
        }

        private fun buildSessionSetupSuccess(messageId: ULong): ByteArray {
            val packet = ByteArray(SmbHeader.SIZE + 8)
            val header = SmbHeader(
                status = NtStatus.STATUS_SUCCESS,
                command = SmbCommand.SESSION_SETUP,
                flags = SmbHeader.SMB2_FLAGS_SERVER_TO_REDIR,
                messageId = messageId,
                sessionId = sessionId,
            )
            header.encodeInto(packet, 0)
            val b = SmbHeader.SIZE
            packet.writeUShortLE(b, 9u)
            packet.writeUShortLE(b + 2, if (encryptShare) SmbMessages.SMB2_SESSION_FLAG_ENCRYPT_DATA else 0u)
            packet.writeUShortLE(b + 4, 72u)
            packet.writeUShortLE(b + 6, 0u)
            return packet
        }

        private fun buildTreeConnectResponse(reqHeader: SmbHeader): ByteArray {
            val packet = ByteArray(SmbHeader.SIZE + 16)
            val header = SmbHeader.withTreeId(
                command = SmbCommand.TREE_CONNECT,
                messageId = reqHeader.messageId,
                treeId = 1u,
                sessionId = sessionId,
                flags = SmbHeader.SMB2_FLAGS_SERVER_TO_REDIR,
            )
            header.encodeInto(packet, 0)
            val b = SmbHeader.SIZE
            packet.writeUShortLE(b, 16u)
            packet[b + 2] = 0x01 // ShareType
            packet.writeUIntLE(b + 4, if (encryptShare) SmbMessages.SMB2_SHAREFLAG_ENCRYPT_DATA else 0u)
            return packet
        }

        private fun handleCreate(reqHeader: SmbHeader, plainReq: ByteArray): ByteArray {
            val b = SmbHeader.SIZE
            val disposition = plainReq.readUIntLE(b + 36)
            val createOptions = plainReq.readUIntLE(b + 40)
            val isDirCreate = (createOptions and SmbCreateOptions.FILE_DIRECTORY_FILE) != 0u
            val nameOff = plainReq.readUShortLE(b + 44).toInt()
            val nameLen = plainReq.readUShortLE(b + 46).toInt()
            val path = if (nameLen > 0) plainReq.decodeFromUtf16LE(nameOff, nameLen) else ""

            val isKnownDir = path in directories
            val isKnownFile = files.containsKey(path)

            // disposition 1 = FILE_OPEN
            if (disposition == 1u && path.isNotEmpty() && path != "srvsvc" && !isKnownDir && !isKnownFile) {
                return buildSimpleResponse(reqHeader, 8, NtStatus.STATUS_OBJECT_NAME_NOT_FOUND)
            }
            if (disposition >= 2u && path.isNotEmpty()) {
                if (isDirCreate) {
                    directories.add(path)
                } else if (!isKnownFile) {
                    files[path] = ByteArray(0)
                }
            }

            val handleId = nextHandleId++
            openHandles[handleId] = path
            val fileBytes = files[path] ?: ByteArray(0)
            val isDirectory = isDirCreate || path in directories

            val packet = ByteArray(SmbHeader.SIZE + 88)
            val header = SmbHeader.withTreeId(
                command = SmbCommand.CREATE,
                messageId = reqHeader.messageId,
                treeId = reqHeader.treeId,
                sessionId = sessionId,
                flags = SmbHeader.SMB2_FLAGS_SERVER_TO_REDIR,
            )
            header.encodeInto(packet, 0)
            packet.writeUShortLE(b, 89u)
            packet.writeULongLE(b + 40, fileBytes.size.toULong())
            packet.writeULongLE(b + 48, fileBytes.size.toULong())
            packet.writeUIntLE(
                b + 56,
                if (isDirectory) SmbFileAttributes.DIRECTORY else SmbFileAttributes.NORMAL
            )
            packet.writeULongLE(b + 64, handleId)
            packet.writeULongLE(b + 72, handleId)
            return packet
        }

        private fun handleWrite(reqHeader: SmbHeader, plainReq: ByteArray): ByteArray {
            val b = SmbHeader.SIZE
            val dataOff = plainReq.readUShortLE(b + 2).toInt()
            val dataLen = plainReq.readUIntLE(b + 4).toInt()
            val fileOff = plainReq.readULongLE(b + 8).toInt()
            val handleId = plainReq.readULongLE(b + 24)
            val path = openHandles[handleId] ?: ""

            val existing = files[path] ?: ByteArray(0)
            val newBuf = ByteArray(maxOf(existing.size, fileOff + dataLen))
            existing.copyInto(newBuf, 0)
            plainReq.copyInto(newBuf, fileOff, dataOff, dataOff + dataLen)
            files[path] = newBuf

            val packet = ByteArray(SmbHeader.SIZE + 16)
            val header = SmbHeader.withTreeId(
                command = SmbCommand.WRITE,
                messageId = reqHeader.messageId,
                treeId = reqHeader.treeId,
                sessionId = sessionId,
                flags = SmbHeader.SMB2_FLAGS_SERVER_TO_REDIR,
            )
            header.encodeInto(packet, 0)
            packet.writeUShortLE(b, 17u)
            packet.writeUIntLE(b + 4, dataLen.toUInt())
            return packet
        }

        private fun handleRead(reqHeader: SmbHeader, plainReq: ByteArray): ByteArray {
            val b = SmbHeader.SIZE
            val reqLen = plainReq.readUIntLE(b + 4).toInt()
            val fileOff = plainReq.readULongLE(b + 8).toInt()
            val handleId = plainReq.readULongLE(b + 24)
            val path = openHandles[handleId] ?: ""
            val content = files[path] ?: ByteArray(0)

            val avail = (content.size - fileOff).coerceAtLeast(0).coerceAtMost(reqLen)
            val slice = if (avail > 0) content.copyOfRange(fileOff, fileOff + avail) else ByteArray(0)

            val packet = ByteArray(SmbHeader.SIZE + 16 + slice.size)
            val header = SmbHeader.withTreeId(
                command = SmbCommand.READ,
                messageId = reqHeader.messageId,
                treeId = reqHeader.treeId,
                sessionId = sessionId,
                flags = SmbHeader.SMB2_FLAGS_SERVER_TO_REDIR,
            )
            header.encodeInto(packet, 0)
            packet.writeUShortLE(b, 17u)
            packet[b + 2] = (SmbHeader.SIZE + 16).toByte()
            packet.writeUIntLE(b + 4, slice.size.toUInt())
            slice.copyInto(packet, SmbHeader.SIZE + 16)
            return packet
        }

        private fun handleQueryDirectory(reqHeader: SmbHeader, plainReq: ByteArray): ByteArray {
            val b = SmbHeader.SIZE
            val handleId = plainReq.readULongLE(b + 16)
            if (!queriedDirs.add(handleId)) {
                return buildSimpleResponse(reqHeader, 8, NtStatus.STATUS_NO_MORE_FILES)
            }
            val dirPath = openHandles[handleId] ?: ""
            val prefix = if (dirPath.isEmpty()) "" else "$dirPath\\"

            data class RawEntry(val name: String, val size: Long, val isDir: Boolean)
            val directEntries = mutableListOf<RawEntry>()

            for (d in directories) {
                if (d.isNotEmpty() && d.startsWith(prefix)) {
                    val rem = d.removePrefix(prefix)
                    if ('\\' !in rem && rem.isNotEmpty()) {
                        directEntries.add(RawEntry(rem, 0L, true))
                    }
                }
            }
            for ((fPath, fBytes) in files) {
                if (fPath.startsWith(prefix)) {
                    val rem = fPath.removePrefix(prefix)
                    if ('\\' !in rem && rem.isNotEmpty()) {
                        directEntries.add(RawEntry(rem, fBytes.size.toLong(), false))
                    }
                }
            }

            if (directEntries.isEmpty()) {
                return buildSimpleResponse(reqHeader, 8, NtStatus.STATUS_NO_MORE_FILES)
            }

            val encodedEntries = directEntries.mapIndexed { idx, item ->
                val nameBytes = item.name.encodeToUtf16LE()
                val rawLen = 104 + nameBytes.size
                val isLast = idx == directEntries.lastIndex
                val paddedLen = if (isLast) rawLen else (rawLen + 7) and -8
                val buf = ByteArray(paddedLen)
                buf.writeUIntLE(0, if (isLast) 0u else paddedLen.toUInt())
                buf.writeULongLE(40, item.size.toULong())
                buf.writeULongLE(48, item.size.toULong())
                buf.writeUIntLE(56, if (item.isDir) SmbFileAttributes.DIRECTORY else SmbFileAttributes.NORMAL)
                buf.writeUIntLE(60, nameBytes.size.toUInt())
                nameBytes.copyInto(buf, 104)
                buf
            }

            val totalEntriesSize = encodedEntries.sumOf { it.size }
            val allEntriesBuf = ByteArray(totalEntriesSize)
            var pos = 0
            for (eb in encodedEntries) {
                eb.copyInto(allEntriesBuf, pos)
                pos += eb.size
            }

            val packet = ByteArray(SmbHeader.SIZE + 8 + allEntriesBuf.size)
            val header = SmbHeader.withTreeId(
                command = SmbCommand.QUERY_DIRECTORY,
                messageId = reqHeader.messageId,
                treeId = reqHeader.treeId,
                sessionId = sessionId,
                flags = SmbHeader.SMB2_FLAGS_SERVER_TO_REDIR,
            )
            header.encodeInto(packet, 0)
            packet.writeUShortLE(b, 9u)
            packet.writeUShortLE(b + 2, (SmbHeader.SIZE + 8).toUShort())
            packet.writeUIntLE(b + 4, allEntriesBuf.size.toUInt())
            allEntriesBuf.copyInto(packet, SmbHeader.SIZE + 8)
            return packet
        }

        private fun handleSetInfo(reqHeader: SmbHeader, plainReq: ByteArray): ByteArray {
            val b = SmbHeader.SIZE
            val infoClass = plainReq[b + 3].toInt() and 0xFF
            val bufLen = plainReq.readUIntLE(b + 4).toInt()
            val bufOff = plainReq.readUShortLE(b + 8).toInt()
            val handleId = plainReq.readULongLE(b + 24)
            val path = openHandles[handleId] ?: ""

            when (infoClass) {
                13 -> { // FileDispositionInformation (Delete)
                    files.remove(path)
                    directories.remove(path)
                }
                10 -> { // FileRenameInformation
                    val newNameLen = plainReq.readUIntLE(bufOff + 16).toInt()
                    val newPath = plainReq.decodeFromUtf16LE(bufOff + 20, newNameLen)
                    val data = files.remove(path) ?: ByteArray(0)
                    files[newPath] = data
                    openHandles[handleId] = newPath
                }
                20 -> { // FileEndOfFileInformation
                    val newSize = plainReq.readULongLE(bufOff).toInt()
                    val data = files[path] ?: ByteArray(0)
                    files[path] = data.copyOf(newSize)
                }
            }
            return buildSimpleResponse(reqHeader, 2)
        }

        private fun handleIoctl(reqHeader: SmbHeader, plainReq: ByteArray): ByteArray {
            val b = SmbHeader.SIZE
            val inOff = plainReq.readUIntLE(b + 24).toInt()
            val inLen = plainReq.readUIntLE(b + 28).toInt()
            val rpcIn = plainReq.copyOfRange(inOff, inOff + inLen)
            val ptype = rpcIn[2].toInt()

            val rpcOut = if (ptype == 11) {
                // Bind_ack (PTYPE = 12)
                ByteArray(24).apply {
                    this[0] = 5
                    this[1] = 0
                    this[2] = 12
                    this[3] = 0x03
                    writeUShortLE(8, 24u)
                }
            } else {
                // NetrShareEnum Response PDU (PTYPE = 2) with 1 share: "PublicDocs" (DISKTREE), "Shared Documents"
                val nameStr = "PublicDocs\u0000"
                val nameBytes = nameStr.encodeToUtf16LE()
                val namePad = (4 - (nameBytes.size % 4)) % 4

                val remStr = "Shared Documents\u0000"
                val remBytes = remStr.encodeToUtf16LE()
                val remPad = (4 - (remBytes.size % 4)) % 4

                val stub = ByteArray(24 + 12 + (12 + nameBytes.size + namePad) + (12 + remBytes.size + remPad) + 12)
                var pos = 0
                stub.writeUIntLE(pos, 1u); pos += 4 // Level = 1
                stub.writeUIntLE(pos, 1u); pos += 4 // Switch = 1
                stub.writeUIntLE(pos, 0x00020000u); pos += 4 // Container Ptr
                stub.writeUIntLE(pos, 1u); pos += 4 // EntriesRead = 1
                stub.writeUIntLE(pos, 0x00020004u); pos += 4 // Buffer Ptr
                stub.writeUIntLE(pos, 1u); pos += 4 // MaxCount = 1

                // SHARE_INFO_1 entry
                stub.writeUIntLE(pos, 0x00020008u); pos += 4 // netname ptr
                stub.writeUIntLE(pos, 0u); pos += 4 // type = DISKTREE (0)
                stub.writeUIntLE(pos, 0x0002000Cu); pos += 4 // remark ptr

                // netname string
                stub.writeUIntLE(pos, nameStr.length.toUInt()); pos += 4
                stub.writeUIntLE(pos, 0u); pos += 4
                stub.writeUIntLE(pos, nameStr.length.toUInt()); pos += 4
                nameBytes.copyInto(stub, pos); pos += nameBytes.size + namePad

                // remark string
                stub.writeUIntLE(pos, remStr.length.toUInt()); pos += 4
                stub.writeUIntLE(pos, 0u); pos += 4
                stub.writeUIntLE(pos, remStr.length.toUInt()); pos += 4
                remBytes.copyInto(stub, pos); pos += remBytes.size + remPad

                val pdu = ByteArray(24 + stub.size)
                pdu[0] = 5
                pdu[2] = 2 // Response
                pdu[3] = 0x03 // First | Last
                pdu.writeUShortLE(8, pdu.size.toUShort())
                stub.copyInto(pdu, 24)
                pdu
            }

            val outOffset = SmbHeader.SIZE + 48
            val packet = ByteArray(outOffset + rpcOut.size)
            val header = SmbHeader.withTreeId(
                command = SmbCommand.IOCTL,
                messageId = reqHeader.messageId,
                treeId = reqHeader.treeId,
                sessionId = sessionId,
                flags = SmbHeader.SMB2_FLAGS_SERVER_TO_REDIR,
            )
            header.encodeInto(packet, 0)
            packet.writeUShortLE(b, 49u)
            packet.writeUIntLE(b + 32, outOffset.toUInt())
            packet.writeUIntLE(b + 36, rpcOut.size.toUInt())
            rpcOut.copyInto(packet, outOffset)
            return packet
        }

        private fun buildSimpleResponse(
            reqHeader: SmbHeader,
            bodySize: Int,
            status: UInt = NtStatus.STATUS_SUCCESS,
        ): ByteArray {
            val packet = ByteArray(SmbHeader.SIZE + bodySize)
            val header = SmbHeader.withTreeId(
                command = reqHeader.command,
                messageId = reqHeader.messageId,
                treeId = reqHeader.treeId,
                sessionId = sessionId,
                flags = SmbHeader.SMB2_FLAGS_SERVER_TO_REDIR,
            ).copy(status = status)
            header.encodeInto(packet, 0)
            packet.writeUShortLE(SmbHeader.SIZE, bodySize.toUShort())
            return packet
        }
    }
}
