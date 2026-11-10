package com.sorrowblue.kmcifs.client

import com.sorrowblue.kmcifs.client.auth.NtlmAuthenticator
import com.sorrowblue.kmcifs.client.auth.SmbCredentials
import com.sorrowblue.kmcifs.client.crypto.Md4
import com.sorrowblue.kmcifs.client.crypto.Md5
import com.sorrowblue.kmcifs.client.crypto.Rc4
import com.sorrowblue.kmcifs.client.crypto.Sha512
import com.sorrowblue.kmcifs.client.crypto.Smb3Kdf
import com.sorrowblue.kmcifs.client.protocol.ByteUtils.decodeFromUtf16LE
import com.sorrowblue.kmcifs.client.protocol.ByteUtils.encodeToUtf16LE
import com.sorrowblue.kmcifs.client.protocol.ByteUtils.epochMillisToFiletime
import com.sorrowblue.kmcifs.client.protocol.ByteUtils.filetimeToEpochMillis
import com.sorrowblue.kmcifs.client.protocol.ByteUtils.readUIntLE
import com.sorrowblue.kmcifs.client.protocol.ByteUtils.readULongLE
import com.sorrowblue.kmcifs.client.protocol.ByteUtils.readUShortLE
import com.sorrowblue.kmcifs.client.protocol.ByteUtils.writeUIntLE
import com.sorrowblue.kmcifs.client.protocol.ByteUtils.writeULongLE
import com.sorrowblue.kmcifs.client.protocol.ByteUtils.writeUShortLE
import com.sorrowblue.kmcifs.client.protocol.DceRpcSrvSvc
import com.sorrowblue.kmcifs.client.protocol.NtStatus
import com.sorrowblue.kmcifs.client.protocol.SmbAccessMask
import com.sorrowblue.kmcifs.client.protocol.SmbCipherId
import com.sorrowblue.kmcifs.client.protocol.SmbCommand
import com.sorrowblue.kmcifs.client.protocol.SmbCreateDisposition
import com.sorrowblue.kmcifs.client.protocol.SmbCreateOptions
import com.sorrowblue.kmcifs.client.protocol.SmbDialect
import com.sorrowblue.kmcifs.client.protocol.SmbException
import com.sorrowblue.kmcifs.client.protocol.SmbFileAttributes
import com.sorrowblue.kmcifs.client.protocol.SmbHeader
import com.sorrowblue.kmcifs.client.protocol.SmbMessages
import com.sorrowblue.kmcifs.client.protocol.SmbPacketTransport
import com.sorrowblue.kmcifs.client.protocol.SmbShareType
import com.sorrowblue.kmcifs.client.protocol.SmbTransformHeader
import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.network.sockets.aSocket
import io.ktor.network.sockets.openReadChannel
import io.ktor.network.sockets.openWriteChannel
import io.ktor.utils.io.readFully
import io.ktor.utils.io.writeFully
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.IO
import kotlinx.coroutines.Job
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withContext
import kotlinx.io.readByteArray
import kotlinx.io.readString
import kotlinx.io.writeString
import kotlin.test.Test
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * End-to-end tests verifying SMB 3.1.1 (NTLMv2 authentication, Preauthentication Integrity Hash,
 * and AES-128-GCM encryption) across share enumeration, directory listing, file creation, read/write,
 * byte-range locking, renaming, and deletion.
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

        // 1b. FSCTL_PIPE_TRANSCEIVE が STATUS_BUFFER_OVERFLOW で単一 DCE/RPC フラグメントの途中までしか返さず、
        //     残りを後続の SMB2 READ で取得する場合でもフラグメントが再結合されて共有フォルダ一覧を取得できることを検証
        mockTransport.splitRpcTransceiveResponse = true
        val splitShares = client.listShares(includeHidden = false)
        assertEquals(1, splitShares.size)
        assertEquals("PublicDocs", splitShares[0].name)
        assertEquals("Shared Documents", splitShares[0].comment)
        mockTransport.splitRpcTransceiveResponse = false

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
        assertTrue(opened.isClosed)
        val closedEx = assertFailsWith<SmbException> {
            opened.read(0L, 4)
        }
        assertEquals(NtStatus.STATUS_FILE_CLOSED, closedEx.ntStatus)

        // 6. リネームと削除
        share.rename("notes/hello.txt", "notes/greeting.txt")
        assertFalse(share.exists("notes/hello.txt"))
        assertTrue(share.exists("notes/greeting.txt"))

        share.deleteFile("notes/greeting.txt")
        assertFalse(share.exists("notes/greeting.txt"))

        share.closeSuspend()
        assertTrue(share.isClosed)
        val closedShareEx = assertFailsWith<SmbException> {
            share.stat("notes/greeting.txt")
        }
        assertEquals(NtStatus.STATUS_NETWORK_NAME_DELETED, closedShareEx.ntStatus)
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

        // 2. Re-open via SmbRandomAccessFile(share, path, "r", bufferSize = 4) without explicit open() in buffered read-only mode
        SmbRandomAccessFile(share, "data/random.bin", "r", bufferSize = 4).use { readOnlyRaf ->
            assertFalse(readOnlyRaf.isOpen)
            assertEquals(6L, readOnlyRaf.length)
            assertTrue(readOnlyRaf.isOpen)
            assertEquals('A'.code, readOnlyRaf.read())
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
        assertTrue(share.isClosed)
        val closedShareEx = assertFailsWith<SmbException> {
            share.stat("notes/greeting.txt")
        }
        assertEquals(NtStatus.STATUS_NETWORK_NAME_DELETED, closedShareEx.ntStatus)
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

        // Trailing slash in listDirectory, stat & rename should be normalized properly
        val mangaEntries = share.listDirectory("/books/manga/")
        assertEquals(2, mangaEntries.size)
        assertTrue(share.exists("/books/manga/vol1.txt/"))

        share.createDirectory("/books/old/")
        share.rename("/books/old/", "/books/new/")
        assertFalse(share.exists("/books/old/"))
        assertTrue(share.exists("/books/new/"))

        // Recursive delete of /books/
        share.deleteRecursively("/books/")
        assertFalse(share.exists("/books/manga/vol1.txt"))
        assertFalse(share.exists("/books/readme.txt"))
        assertFalse(share.exists("/books"))

        share.closeSuspend()
        assertTrue(share.isClosed)
        val closedShareEx = assertFailsWith<SmbException> {
            share.stat("notes/greeting.txt")
        }
        assertEquals(NtStatus.STATUS_NETWORK_NAME_DELETED, closedShareEx.ntStatus)
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
        assertTrue(share.isClosed)
        val closedShareEx = assertFailsWith<SmbException> {
            share.stat("notes/greeting.txt")
        }
        assertEquals(NtStatus.STATUS_NETWORK_NAME_DELETED, closedShareEx.ntStatus)
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
        assertTrue(share.isClosed)
        val closedShareEx = assertFailsWith<SmbException> {
            share.stat("notes/greeting.txt")
        }
        assertEquals(NtStatus.STATUS_NETWORK_NAME_DELETED, closedShareEx.ntStatus)
        client.closeSuspend()
    }

    @Test
    fun testMsSmb2ComplianceAndMalformedPacketGuards() {
        // 1. MS-SMB2 3.2.5.2: SMB 3.1.1 NEGOTIATE response without SMB2_PREAUTH_INTEGRITY_CAPABILITIES must fail
        val badNegPacket = ByteArray(SmbHeader.SIZE + 64)
        SmbHeader(
            command = SmbCommand.NEGOTIATE,
            flags = SmbHeader.SMB2_FLAGS_SERVER_TO_REDIR,
            messageId = 0uL,
        ).encodeInto(badNegPacket, 0)
        badNegPacket.writeUShortLE(SmbHeader.SIZE, 65u)
        badNegPacket.writeUShortLE(SmbHeader.SIZE + 4, SmbDialect.SMB_3_1_1.code)
        val negEx = assertFailsWith<SmbException> {
            SmbMessages.parseNegotiateResponse(badNegPacket)
        }
        assertEquals(NtStatus.STATUS_INVALID_NETWORK_RESPONSE, negEx.ntStatus)

        // 2. MS-FSCC 2.4.18: Malformed NextEntryOffset (negative when signed) must not cause an infinite loop
        val nameBytes = "item.txt".encodeToUtf16LE()
        val entrySize = 104 + nameBytes.size
        val queryPacket = ByteArray(SmbHeader.SIZE + 8 + entrySize)
        SmbHeader(
            command = SmbCommand.QUERY_DIRECTORY,
            flags = SmbHeader.SMB2_FLAGS_SERVER_TO_REDIR,
            messageId = 1uL,
        ).encodeInto(queryPacket, 0)
        queryPacket.writeUShortLE(SmbHeader.SIZE, 9u)
        queryPacket.writeUShortLE(SmbHeader.SIZE + 2, (SmbHeader.SIZE + 8).toUShort())
        queryPacket.writeUIntLE(SmbHeader.SIZE + 4, entrySize.toUInt())
        val entryOffset = SmbHeader.SIZE + 8
        queryPacket.writeUIntLE(entryOffset, 0xFFFFFF98u) // Negative Int (-104) if unchecked
        queryPacket.writeUIntLE(entryOffset + 60, nameBytes.size.toUInt())
        nameBytes.copyInto(queryPacket, entryOffset + 104)

        val parsedEntries = SmbMessages.parseQueryDirectoryResponse(queryPacket)
        assertEquals(1, parsedEntries?.size)
        assertEquals("item.txt", parsedEntries?.get(0)?.name)

        // 3. MS-SRVS 3.1.4.8: Oversized or negative maxCount in NDR response must not throw OOM or NegativeSize
        val badRpcStub = ByteArray(24)
        badRpcStub.writeUIntLE(0, 1u) // Level = 1
        badRpcStub.writeUIntLE(4, 1u) // Switch = 1
        badRpcStub.writeUIntLE(8, 0x00020000u) // Container Ptr
        badRpcStub.writeUIntLE(12, 0x7FFFFFFFu) // Huge EntriesRead
        badRpcStub.writeUIntLE(16, 0x00020004u) // Buffer Ptr
        badRpcStub.writeUIntLE(20, 0xFFFFFFFFu) // Negative MaxCount (-1)
        assertTrue(DceRpcSrvSvc.parseNetrShareEnumResponse(badRpcStub).isEmpty())

        // 4. MS-SMB2 3.2.5.1.1.1: Compound encrypted packet with mismatched inner SessionId on 2nd message must fail
        val msg1 = SmbMessages.buildLogoffRequest(messageId = 1uL, sessionId = 0x1122uL)
        val msg2 = SmbMessages.buildLogoffRequest(messageId = 2uL, sessionId = 0x9999uL)
        // Set SERVER_TO_REDIR so buildCompoundRelatedPacket keeps msg2's explicit SessionId (0x9999uL)
        msg1.writeUIntLE(16, SmbHeader.SMB2_FLAGS_SERVER_TO_REDIR)
        msg2.writeUIntLE(16, SmbHeader.SMB2_FLAGS_SERVER_TO_REDIR)
        val compound = SmbMessages.buildCompoundRelatedPacket(listOf(msg1, msg2))
        val key = ByteArray(16) { (it + 1).toByte() }
        val encrypted = SmbTransformHeader.encryptPacket(
            plainSmbPacket = compound,
            sessionId = 0x1122uL,
            cipherId = SmbCipherId.AES_128_GCM,
            encryptionKey = key,
        )
        assertFailsWith<IllegalArgumentException> {
            SmbTransformHeader.decryptPacket(
                transformPacket = encrypted,
                cipherId = SmbCipherId.AES_128_GCM,
                decryptionKey = key,
                expectedSessionId = 0x1122uL,
            )
        }

        // 5. MS-SMB2 3.3.5.18: STATUS_NO_SUCH_FILE on initial QUERY_DIRECTORY must return null (0 matching entries)
        val noSuchFileQuery = ByteArray(SmbHeader.SIZE + 8)
        SmbHeader(
            status = NtStatus.STATUS_NO_SUCH_FILE,
            command = SmbCommand.QUERY_DIRECTORY,
            flags = SmbHeader.SMB2_FLAGS_SERVER_TO_REDIR,
            messageId = 2uL,
        ).encodeInto(noSuchFileQuery, 0)
        assertEquals(null, SmbMessages.parseQueryDirectoryResponse(noSuchFileQuery))

        // 6. parseReadResponse must cap returned payload at maxLength
        val oversizedRead = ByteArray(SmbHeader.SIZE + 16 + 32)
        SmbHeader(
            status = NtStatus.STATUS_SUCCESS,
            command = SmbCommand.READ,
            flags = SmbHeader.SMB2_FLAGS_SERVER_TO_REDIR,
            messageId = 3uL,
        ).encodeInto(oversizedRead, 0)
        oversizedRead.writeUShortLE(SmbHeader.SIZE, 17u)
        oversizedRead[SmbHeader.SIZE + 2] = (SmbHeader.SIZE + 16).toByte()
        oversizedRead.writeUIntLE(SmbHeader.SIZE + 4, 32u)
        assertEquals(10, SmbMessages.parseReadResponse(oversizedRead, maxLength = 10).size)

        // 7. SPNEGO-wrapped NTLMSSP Type 2 challenge with trailing ASN.1 fields must extract exact Type 2 length
        val rawType2 = ByteArray(56)
        "NTLMSSP\u0000".encodeToByteArray().copyInto(rawType2, 0)
        rawType2.writeUIntLE(8, 2u)
        rawType2.writeUIntLE(20, 0x62888215u)
        rawType2.writeUShortLE(40, 4u)
        rawType2.writeUShortLE(42, 4u)
        rawType2.writeUIntLE(44, 48u)
        val spnegoWrappedType2WithTrailingMic = ByteArray(4 + rawType2.size + 18).apply {
            this[0] = 0xA2.toByte()
            this[1] = (2 + rawType2.size).toByte()
            this[2] = 0x04.toByte() // OCTET STRING tag
            this[3] = rawType2.size.toByte() // Exact Type 2 length (56)
            rawType2.copyInto(this, 4)
            // Trailing [3] mechListMIC field (18 bytes)
            this[4 + rawType2.size] = 0xA3.toByte()
            this[5 + rawType2.size] = 16
        }
        val parsedChallenge = NtlmAuthenticator.parseType2Challenge(spnegoWrappedType2WithTrailingMic)
        assertEquals(rawType2.size, parsedChallenge.rawType2Message.size)

        // 8. MS-SMB2 2.2.4.1.2 / 3.2.5.2: SMB 3.1.1 NEGOTIATE response with unknown non-zero Cipher ID must fail
        fun buildSmb311NegRespWithCipher(cipherCode: UShort): ByteArray {
            val ctx1 = ByteArray(48)
            ctx1.writeUShortLE(0, 0x0001u)
            ctx1.writeUShortLE(2, 38u)
            ctx1.writeUShortLE(8, 1u)
            ctx1.writeUShortLE(10, 32u)
            ctx1.writeUShortLE(12, 0x0001u) // SHA-512
            val ctx2 = ByteArray(14)
            ctx2.writeUShortLE(0, 0x0002u)
            ctx2.writeUShortLE(2, 4u)
            ctx2.writeUShortLE(8, 1u)
            ctx2.writeUShortLE(10, cipherCode)
            val ctxOffset = 128
            val pkt = ByteArray(ctxOffset + ctx1.size + ctx2.size)
            SmbHeader(
                command = SmbCommand.NEGOTIATE,
                flags = SmbHeader.SMB2_FLAGS_SERVER_TO_REDIR,
                messageId = 0uL,
            ).encodeInto(pkt, 0)
            val b = SmbHeader.SIZE
            pkt.writeUShortLE(b, 65u)
            pkt.writeUShortLE(b + 4, SmbDialect.SMB_3_1_1.code)
            pkt.writeUShortLE(b + 6, 2u)
            pkt.writeUIntLE(b + 60, ctxOffset.toUInt())
            ctx1.copyInto(pkt, ctxOffset)
            ctx2.copyInto(pkt, ctxOffset + ctx1.size)
            return pkt
        }
        val unknownCipherEx = assertFailsWith<SmbException> {
            SmbMessages.parseNegotiateResponse(buildSmb311NegRespWithCipher(0x9999u))
        }
        assertEquals(NtStatus.STATUS_INVALID_NETWORK_RESPONSE, unknownCipherEx.ntStatus)
        val noCipherResp = SmbMessages.parseNegotiateResponse(buildSmb311NegRespWithCipher(0x0000u))
        assertEquals(null, noCipherResp.negotiatedCipher)
    }

    @Test
    fun testDialectDowngradeAndEncryptionStrippingRejected() = runTest {
        val creds = SmbCredentials(username = "alice", password = "Password123!", domain = "WORKGROUP")

        // 1. MS-SMB2 3.2.5.2: Server returning a dialect not in SmbConfig.dialects must be rejected
        val downgradeTransport = object : SmbPacketTransport {
            private var lastMsgId: ULong = 0uL
            override suspend fun sendPacket(packet: ByteArray) {
                lastMsgId = SmbHeader.decode(packet).messageId
            }
            override suspend fun receivePacket(): ByteArray {
                val resp = ByteArray(SmbHeader.SIZE + 64)
                SmbHeader(
                    command = SmbCommand.NEGOTIATE,
                    flags = SmbHeader.SMB2_FLAGS_SERVER_TO_REDIR,
                    messageId = lastMsgId,
                ).encodeInto(resp, 0)
                resp.writeUShortLE(SmbHeader.SIZE, 65u)
                resp.writeUShortLE(SmbHeader.SIZE + 4, SmbDialect.SMB_2_0_2.code)
                return resp
            }
            override fun close() {}
        }
        val downgradeClient = SmbClient(
            host = "127.0.0.1",
            port = 445,
            config = SmbConfig(dialects = listOf(SmbDialect.SMB_3_1_1)),
            transport = downgradeTransport,
        )
        val downgradeEx = assertFailsWith<SmbException> {
            downgradeClient.initializeSession(creds)
        }
        assertEquals(NtStatus.STATUS_INVALID_NETWORK_RESPONSE, downgradeEx.ntStatus)

        // 2. MS-SMB2 3.2.5.1.1.2: Unencrypted response on an encrypted SMB3 session must be rejected
        val baseTransport = MockSmb3ServerTransport(expectedCredentials = creds, encryptShare = true)
        var stripEncryptionOnNextResponse = false
        val strippingTransport = object : SmbPacketTransport {
            private var lastInnerPlain: ByteArray? = null
            override suspend fun sendPacket(packet: ByteArray) {
                if (stripEncryptionOnNextResponse && SmbTransformHeader.isTransformPacket(packet)) {
                    val reqMsgId = 3uL // First post-SESSION_SETUP command (TREE_CONNECT)
                    val fakePlainResp = ByteArray(SmbHeader.SIZE + 16)
                    SmbHeader.withTreeId(
                        command = SmbCommand.TREE_CONNECT,
                        messageId = reqMsgId,
                        treeId = 1u,
                        sessionId = 0x1000200030004000uL,
                        flags = SmbHeader.SMB2_FLAGS_SERVER_TO_REDIR,
                    ).encodeInto(fakePlainResp, 0)
                    fakePlainResp.writeUShortLE(SmbHeader.SIZE, 16u)
                    lastInnerPlain = fakePlainResp
                    return
                }
                baseTransport.sendPacket(packet)
            }
            override suspend fun receivePacket(): ByteArray {
                lastInnerPlain?.let {
                    lastInnerPlain = null
                    return it
                }
                return baseTransport.receivePacket()
            }
            override fun close() = baseTransport.close()
        }

        val encClient = SmbClient("127.0.0.1", 445, SmbConfig(encryptionPolicy = SmbEncryptionPolicy.REQUIRED), strippingTransport)
        encClient.initializeSession(creds)
        stripEncryptionOnNextResponse = true
        val stripEx = assertFailsWith<SmbException> {
            encClient.connectShare("PublicDocs")
        }
        assertEquals(NtStatus.STATUS_ACCESS_DENIED, stripEx.ntStatus)
        encClient.close()
    }

    @Test
    fun testSmb202AndSmb302DialectsCcmAndAnonymousGuestSessions() = runTest {
        val creds = SmbCredentials("alice", "SecretPassword123!", "WORKGROUP")

        // 1. SMB 2.0.2 with HMAC-SHA256 signing, CreditCharge=0, and NTLMv2 Timestamp + MsvAvFlags MIC calculation
        val smb202Transport = MockSmb3ServerTransport(
            expectedCredentials = creds,
            dialect = SmbDialect.SMB_2_0_2,
            encryptShare = false,
            includeTimestampInChallenge = true,
        )
        val smb202Client = SmbClient(
            host = "192.168.1.10",
            port = 445,
            config = SmbConfig(
                dialects = listOf(SmbDialect.SMB_2_0_2),
                encryptionPolicy = SmbEncryptionPolicy.DISABLED,
                alwaysSign = true,
                verifyServerSignatures = true,
            ),
            transport = smb202Transport,
        )
        smb202Client.initializeSession(creds)
        assertEquals(SmbDialect.SMB_2_0_2, smb202Client.negotiatedDialect)
        assertEquals(null, smb202Client.negotiatedCipher)
        assertFalse(smb202Client.isSessionEncrypted)

        val smb202Share = smb202Client.connectShare("PublicDocs")
        smb202Share.writeText("notes/smb202.txt", "SMB 2.0.2 HMAC-SHA256 Signed!")
        assertEquals("SMB 2.0.2 HMAC-SHA256 Signed!", smb202Share.readText("notes/smb202.txt"))

        // Signature stripping / corruption detection on SMB 2.0.2 (Compound stat and single-command openFile)
        smb202Transport.stripServerSignatureOnNextResponse = true
        val missingSigEx = assertFailsWith<SmbException> {
            smb202Share.stat("notes/smb202.txt")
        }
        assertEquals(NtStatus.STATUS_ACCESS_DENIED, missingSigEx.ntStatus)

        smb202Transport.corruptServerSignatureOnNextResponse = true
        val badSigEx = assertFailsWith<SmbException> {
            smb202Share.stat("notes/smb202.txt")
        }
        assertEquals(NtStatus.STATUS_ACCESS_DENIED, badSigEx.ntStatus)

        smb202Transport.stripServerSignatureOnNextResponse = true
        val singleMissingSigEx = assertFailsWith<SmbException> {
            smb202Share.openFile("notes/smb202.txt")
        }
        assertEquals(NtStatus.STATUS_ACCESS_DENIED, singleMissingSigEx.ntStatus)

        smb202Transport.corruptServerSignatureOnNextResponse = true
        val singleBadSigEx = assertFailsWith<SmbException> {
            smb202Share.openFile("notes/smb202.txt")
        }
        assertEquals(NtStatus.STATUS_ACCESS_DENIED, singleBadSigEx.ntStatus)

        smb202Share.closeSuspend()
        smb202Client.closeSuspend()

        // 1b. SMB 3.1.1 default signing policy (alwaysSign = false, serverSigningRequired = false):
        //     Only TREE_CONNECT is signed by the client; READ/WRITE omit unnecessary CMAC computation
        val selectiveSignTransport = MockSmb3ServerTransport(
            expectedCredentials = creds,
            dialect = SmbDialect.SMB_3_1_1,
            encryptShare = false,
        )
        val selectiveSignClient = SmbClient(
            host = "192.168.1.10",
            port = 445,
            config = SmbConfig(
                encryptionPolicy = SmbEncryptionPolicy.DISABLED,
                alwaysSign = false,
                verifyServerSignatures = true,
            ),
            transport = selectiveSignTransport,
        )
        selectiveSignClient.initializeSession(creds)
        val selectiveShare = selectiveSignClient.connectShare("PublicDocs")
        selectiveShare.writeText("notes/selective.txt", "Selective TREE_CONNECT signing")
        assertEquals("Selective TREE_CONNECT signing", selectiveShare.readText("notes/selective.txt"))
        assertEquals(listOf(SmbCommand.TREE_CONNECT), selectiveSignTransport.signedRequestCommands)
        selectiveShare.closeSuspend()
        selectiveSignClient.closeSuspend()

        // 2. SMB 3.0.2 with AES-128-CCM Transform Header encryption and SP800-108 SMB 3.0/3.0.2 KDF labels
        val smb302Transport = MockSmb3ServerTransport(
            expectedCredentials = creds,
            dialect = SmbDialect.SMB_3_0_2,
            cipherId = SmbCipherId.AES_128_CCM,
            encryptShare = true,
        )
        val smb302Client = SmbClient(
            host = "192.168.1.10",
            port = 445,
            config = SmbConfig(
                dialects = listOf(SmbDialect.SMB_3_0_2),
                ciphers = listOf(SmbCipherId.AES_128_CCM),
                encryptionPolicy = SmbEncryptionPolicy.REQUIRED,
            ),
            transport = smb302Transport,
        )
        smb302Client.initializeSession(creds)
        assertEquals(SmbDialect.SMB_3_0_2, smb302Client.negotiatedDialect)
        assertEquals(SmbCipherId.AES_128_CCM, smb302Client.negotiatedCipher)
        assertTrue(smb302Client.isSessionEncrypted)

        val smb302Share = smb302Client.connectShare("PublicDocs")
        smb302Share.writeText("notes/smb302.txt", "SMB 3.0.2 AES-128-CCM Encrypted!")
        assertEquals("SMB 3.0.2 AES-128-CCM Encrypted!", smb302Share.readText("notes/smb302.txt"))
        smb302Share.closeSuspend()
        smb302Client.closeSuspend()
        assertTrue(smb302Transport.encryptedPacketsCount >= 4)

        // 3. Anonymous 1-step login & Guest 2-step login (and REQUIRED encryption rejection on anonymous)
        val anonImmediateTransport = MockSmb3ServerTransport(
            expectedCredentials = SmbCredentials.Anonymous,
            encryptShare = false,
            immediateAnonymousSuccess = true,
        )
        val anonClient = SmbClient(
            host = "192.168.1.10",
            port = 445,
            config = SmbConfig(encryptionPolicy = SmbEncryptionPolicy.NEGOTIATE),
            transport = anonImmediateTransport,
        )
        anonClient.initializeSession(SmbCredentials.Anonymous)
        val anonShare = anonClient.connectShare("PublicDocs")
        anonShare.writeText("notes/anon.txt", "Anonymous 1-step")
        assertEquals("Anonymous 1-step", anonShare.readText("notes/anon.txt"))
        anonShare.closeSuspend()
        anonClient.closeSuspend()

        val anonRequiredEx = assertFailsWith<SmbException> {
            val c = SmbClient(
                host = "192.168.1.10",
                port = 445,
                config = SmbConfig(encryptionPolicy = SmbEncryptionPolicy.REQUIRED),
                transport = MockSmb3ServerTransport(
                    expectedCredentials = SmbCredentials.Anonymous,
                    encryptShare = false,
                    immediateAnonymousSuccess = true,
                ),
            )
            c.initializeSession(SmbCredentials.Anonymous)
        }
        assertEquals(NtStatus.STATUS_NOT_SUPPORTED, anonRequiredEx.ntStatus)

        // 2-step Anonymous & Guest session flag
        val guestTransport = MockSmb3ServerTransport(
            expectedCredentials = SmbCredentials.Anonymous,
            encryptShare = false,
            returnGuestSessionFlag = true,
        )
        val guestClient = SmbClient(
            host = "192.168.1.10",
            port = 445,
            config = SmbConfig(encryptionPolicy = SmbEncryptionPolicy.NEGOTIATE, alwaysSign = true),
            transport = guestTransport,
        )
        guestClient.initializeSession(SmbCredentials.Anonymous)
        val guestShare = guestClient.connectShare("PublicDocs")
        guestShare.writeText("notes/guest.txt", "Guest 2-step")
        assertEquals("Guest 2-step", guestShare.readText("notes/guest.txt"))
        guestShare.closeSuspend()
        guestClient.closeSuspend()
    }

    @Test
    fun testAsyncInterimPendingAndMultiFragmentDceRpcAndPipeOperations() = runTest {
        val creds = SmbCredentials("alice", "SecretPassword123!", "WORKGROUP")
        val mockTransport = MockSmb3ServerTransport(
            expectedCredentials = creds,
            encryptShare = false,
            injectPendingAndNotifications = true,
            multiFragmentRpcResponse = true,
        )
        val client = SmbClient("192.168.1.10", 445, SmbConfig(encryptionPolicy = SmbEncryptionPolicy.DISABLED), mockTransport)
        client.initializeSession(creds)

        // 1. Multi-fragment DCE/RPC response (2 PDUs) with hidden & varied share types
        val visibleShares = client.listShares(includeHidden = false)
        assertEquals(3, visibleShares.size)
        val allShares = client.listShares(includeHidden = true)
        assertEquals(5, allShares.size)
        assertEquals(SmbShareType.DISKTREE, allShares[0].type)
        assertEquals(SmbShareType.PRINTQ, allShares[1].type)
        assertEquals(SmbShareType.DEVICE, allShares[2].type)
        assertEquals(SmbShareType.IPC, allShares[3].type)
        assertTrue(allShares[3].isSpecialOrHidden)
        assertEquals(SmbShareType.UNKNOWN, allShares[4].type)
        assertTrue(allShares[4].isSpecialOrHidden)

        // 2. Direct IPC$ SmbPipeShare & SmbNamedPipe write / read / close lifecycle
        val ipc = client.connectIpcShare()
        assertFalse(ipc.isClosed)
        val pipe = ipc.openPipe("\\pipe\\wkssvc")
        assertEquals("wkssvc", pipe.pipeName)
        assertFalse(pipe.isClosed)
        assertEquals(0, pipe.write(ByteArray(0)))
        val written = pipe.write("RPC_PING".encodeToByteArray())
        assertEquals(8, written)
        assertEquals(0, pipe.read(0).size)
        val pipeRead = pipe.read(64)
        assertEquals("RPC_PING", pipeRead.decodeToString())
        pipe.close()
        assertTrue(pipe.isClosed)
        assertFailsWith<SmbException> {
            pipe.write("AFTER_CLOSE".encodeToByteArray())
        }
        ipc.close()
        assertTrue(ipc.isClosed)
        assertFailsWith<SmbException> {
            ipc.openPipe("srvsvc")
        }

        // 3. Compound request with injected interim STATUS_PENDING, unsolicited OPLOCK_BREAK, and stale MessageId
        val share = client.connectShare("PublicDocs")
        share.writeText("notes/async.txt", "Async pending handled!")
        assertTrue(share.exists("notes/async.txt"))
        assertEquals("Async pending handled!", share.readText("notes/async.txt"))
        share.closeSuspend()
        client.closeSuspend()
    }

    @Test
    fun testRandomAccessFileAllPrimitivesModesAndBuffering() = runTest {
        val creds = SmbCredentials("alice", "SecretPassword123!", "WORKGROUP")
        val mockTransport = MockSmb3ServerTransport(creds, encryptShare = false)
        val client = SmbClient("192.168.1.10", 445, SmbConfig(encryptionPolicy = SmbEncryptionPolicy.DISABLED), mockTransport)
        client.initializeSession(creds)
        val share = client.connectShare("PublicDocs")

        assertFailsWith<IllegalArgumentException> {
            SmbRandomAccessMode.fromModeString("invalid")
        }
        assertEquals(SmbRandomAccessMode.READ_WRITE_SYNC, SmbRandomAccessMode.fromModeString("rws"))
        assertEquals(SmbRandomAccessMode.READ_WRITE_DSYNC, SmbRandomAccessMode.fromModeString("rwd"))

        // Open using SmbRandomAccessMode enum overload ("rws")
        share.openRandomAccessFile("data/primitives.bin", SmbRandomAccessMode.READ_WRITE_SYNC, bufferSize = 8).use { raf ->
            raf.writeBoolean(true)
            raf.writeBoolean(false)
            raf.writeShort(0x1234)
            raf.writeShort(0xFF80)
            raf.write(0xAB)
            raf.write(ByteArray(0), 0, 0)
            raf.flush()

            assertEquals(7L, raf.length)
            assertFalse(raf.metadata.isDirectory)

            raf.seek(0L)
            assertTrue(raf.readBoolean())
            assertFalse(raf.readBoolean())
            assertEquals(0x1234.toShort(), raf.readShort())
            assertEquals(0xFF80, raf.readUnsignedShort())
            assertEquals(0xAB, raf.readUnsignedByte())
            assertEquals(-1, raf.read())
            assertFailsWith<SmbEndOfFileException> {
                raf.readUnsignedByte()
            }

            // skipBytes and readBytes
            raf.seek(0L)
            assertEquals(0, raf.skipBytes(0))
            assertEquals(0, raf.skipBytes(-5))
            assertEquals(2, raf.skipBytes(2))
            assertEquals(2L, raf.position)
            assertEquals(0, raf.readBytes(0).size)
            val twoBytes = raf.readBytes(2)
            assertContentEquals(byteArrayOf(0x12, 0x34), twoBytes)
            // Requesting 10 bytes when only 3 remain
            val tailBytes = raf.readBytes(10)
            assertEquals(3, tailBytes.size)
            assertEquals(0, raf.skipBytes(5))
            assertEquals(0, raf.readBytes(4).size)
        }

        // Buffered read-ahead & cache invalidation on write + toRandomAccessFile wrapper
        share.writeBytes("data/buffered.bin", ByteArray(24) { (it + 1).toByte() })
        val rawFile = share.openFile("data/buffered.bin", desiredAccess = SmbAccessMask.WRITE_DEFAULT)
        rawFile.toRandomAccessFile(path = "data/buffered.bin", mode = SmbRandomAccessMode.READ_WRITE_DSYNC, bufferSize = 8).use { bRaf ->
            // Fill 8-byte buffer at offset 0..7 and hit fast path
            assertEquals(1, bRaf.read())
            assertEquals(2, bRaf.read())
            val smallSlice = ByteArray(4)
            assertEquals(4, bRaf.read(smallSlice))
            assertContentEquals(byteArrayOf(3, 4, 5, 6), smallSlice)

            // Cross buffer boundary: 2 bytes left in buffer (7, 8) + 10 bytes >= bufferSize (direct zero-copy read)
            val crossLarge = ByteArray(12)
            assertEquals(12, bRaf.read(crossLarge))
            assertContentEquals(ByteArray(12) { (it + 7).toByte() }, crossLarge)

            // Cross buffer boundary with small remainder (< bufferSize): refill buffer path
            bRaf.seek(0L)
            assertEquals(1, bRaf.read()) // populates buffer 0..7
            bRaf.seek(6L)
            val crossSmall = ByteArray(5) // 2 bytes from buffer (7, 8) + 3 bytes refilled (9, 10, 11)
            assertEquals(5, bRaf.read(crossSmall))
            assertContentEquals(byteArrayOf(7, 8, 9, 10, 11), crossSmall)

            // Write invalidates buffer so subsequent read sees updated byte
            bRaf.seek(8L)
            bRaf.writeByte(0x77)
            bRaf.seek(8L)
            assertEquals(0x77, bRaf.readUnsignedByte())
        }

        share.closeSuspend()
        client.closeSuspend()
    }

    @Test
    fun testAsyncPipeliningOutOfOrderResponsesAndCreditFlowControl() = runTest {
        val creds = SmbCredentials("alice", "SecretPassword123!", "WORKGROUP")
        val backend = MockSmb3ServerTransport(creds, encryptShare = true)

        // 1. Out-of-order pipelining transport: holds 4 concurrent READ requests until ALL 4 arrive on the wire,
        //    proving requests are pipelined without waiting for prior responses, then flushes responses in reverse order (4 -> 3 -> 2 -> 1).
        val barrierMutex = Mutex()
        var holdReads = false
        val heldResponses = ArrayList<ByteArray>(4)
        val outOfOrderChannel = Channel<ByteArray>(Channel.UNLIMITED)
        val allFourSent = CompletableDeferred<Unit>()

        val pipeliningTransport = object : SmbPacketTransport {
            override suspend fun sendPacket(packet: ByteArray) {
                barrierMutex.withLock {
                    backend.sendPacket(packet)
                    val produced = ArrayList<ByteArray>()
                    while (backend.hasPendingResponses()) {
                        produced.add(backend.receivePacket())
                    }
                    if (holdReads) {
                        heldResponses.addAll(produced)
                        if (heldResponses.size == 4) {
                            for (resp in heldResponses.asReversed()) {
                                outOfOrderChannel.trySend(resp)
                            }
                            heldResponses.clear()
                            allFourSent.complete(Unit)
                        }
                    } else {
                        for (resp in produced) {
                            outOfOrderChannel.trySend(resp)
                        }
                    }
                }
            }

            override suspend fun receivePacket(): ByteArray = outOfOrderChannel.receive()

            override fun close() {
                outOfOrderChannel.close()
                backend.close()
            }
        }

        withContext(Dispatchers.Default) {
            val client = SmbClient(
                host = "192.168.1.10",
                port = 445,
                config = SmbConfig(encryptionPolicy = SmbEncryptionPolicy.REQUIRED),
                transport = pipeliningTransport,
                readerDispatcher = Dispatchers.IO,
            )
            client.initializeSession(creds)
            val share = client.connectShare("PublicDocs")

            val payload = ByteArray(4096) { idx -> ((idx * 29 + 3) and 0xFF).toByte() }
            share.writeBytes("data/pipelined.bin", payload)
            val openFile = share.openFile("data/pipelined.bin")

            barrierMutex.withLock {
                holdReads = true
            }
            val readJobs = (0 until 4).map { chunkIdx ->
                async {
                    openFile.read(chunkIdx * 1024L, 1024)
                }
            }
            allFourSent.await()
            val results = readJobs.awaitAll()
            barrierMutex.withLock {
                holdReads = false
            }

            for (chunkIdx in 0 until 4) {
                assertContentEquals(
                    payload.copyOfRange(chunkIdx * 1024, (chunkIdx + 1) * 1024),
                    results[chunkIdx],
                )
            }

            openFile.closeSuspend()
            share.closeSuspend()
            client.closeSuspend()
        }

        // 2. Credit flow control: server grants only 1 credit per response, throttling 6 concurrent compound/single requests cleanly in FIFO order
        val stingyBackend = MockSmb3ServerTransport(creds, encryptShare = false, creditsGrantedPerResponse = 1u)
        withContext(Dispatchers.Default) {
            val client = SmbClient(
                host = "192.168.1.10",
                port = 445,
                config = SmbConfig(encryptionPolicy = SmbEncryptionPolicy.DISABLED),
                transport = stingyBackend,
                readerDispatcher = Dispatchers.IO,
            )
            client.initializeSession(creds)
            val share = client.connectShare("PublicDocs")
            for (i in 0 until 6) {
                share.writeText("notes/c_$i.txt", "Credit-$i")
            }
            val results = (0 until 6).map { i ->
                async {
                    share.readText("notes/c_$i.txt")
                }
            }.awaitAll()
            for (i in 0 until 6) {
                assertEquals("Credit-$i", results[i])
            }
            // Server refuses >1 credit even on ECHO: a 2-credit compound stat() must fail fast with STATUS_INSUFFICIENT_RESOURCES rather than deadlocking
            val capEx = assertFailsWith<SmbException> {
                share.stat("notes/c_0.txt")
            }
            assertEquals(NtStatus.STATUS_INSUFFICIENT_RESOURCES, capEx.ntStatus)
            share.closeSuspend()
            client.closeSuspend()
        }

        // 3. Automatic SMB2 ECHO credit replenishment when idle with 1 credit and concurrent multi-credit compound requests ([W1=2, W2=3]) arrive
        val echoReplenishBackend = MockSmb3ServerTransport(
            expectedCredentials = creds,
            encryptShare = false,
            creditsGrantedPerResponse = 1u,
            echoCreditsGranted = 3u,
        )
        withContext(Dispatchers.Default) {
            val client = SmbClient(
                host = "192.168.1.10",
                port = 445,
                config = SmbConfig(encryptionPolicy = SmbEncryptionPolicy.DISABLED),
                transport = echoReplenishBackend,
                readerDispatcher = Dispatchers.IO,
            )
            client.initializeSession(creds)
            val share = client.connectShare("PublicDocs")
            share.writeText("notes/to_delete.txt", "temp")
            // Concurrent 2-credit stat() and 3-credit deleteFile() when availableCredits == 1;
            // first ECHO grants 3 credits (waking W1 and leaving 1 credit == creditsBefore), second ECHO wakes W2
            val w1 = async { share.exists("notes/missing.txt") }
            val w2 = async { share.deleteFile("notes/to_delete.txt") }
            assertFalse(w1.await())
            w2.await()
            assertFalse(share.exists("notes/to_delete.txt"))
            share.closeSuspend()
            client.closeSuspend()
        }

        // 4. Request timeout surfaces as SmbException(STATUS_IO_TIMEOUT) instead of CancellationException
        val blackholeBackend = MockSmb3ServerTransport(creds, encryptShare = false)
        var dropNextSend = false
        val timeoutTransport = object : SmbPacketTransport {
            override suspend fun sendPacket(packet: ByteArray) {
                if (!dropNextSend) {
                    blackholeBackend.sendPacket(packet)
                }
            }
            override suspend fun receivePacket(): ByteArray = blackholeBackend.receivePacket()
            override fun close() = blackholeBackend.close()
        }
        assertFailsWith<IllegalArgumentException> {
            SmbConfig(connectTimeout = 0.seconds)
        }
        assertFailsWith<IllegalArgumentException> {
            SmbConfig(requestTimeout = (-1).seconds)
        }
        withContext(Dispatchers.Default) {
            val client = SmbClient(
                host = "192.168.1.10",
                port = 445,
                config = SmbConfig(
                    encryptionPolicy = SmbEncryptionPolicy.DISABLED,
                    requestTimeout = 80.milliseconds,
                ),
                transport = timeoutTransport,
                readerDispatcher = Dispatchers.IO,
            )
            client.initializeSession(creds)
            dropNextSend = true
            val timeoutEx = assertFailsWith<SmbException> {
                client.connectShare("PublicDocs")
            }
            assertEquals(NtStatus.STATUS_IO_TIMEOUT, timeoutEx.ntStatus)
            assertTrue(client.isClosed)
        }
    }

    @Test
    fun testCoroutineCancellationAndRandomAccessCallerJobAbort() = runTest {
        val creds = SmbCredentials("alice", "SecretPassword123!", "WORKGROUP")
        val backend = MockSmb3ServerTransport(creds, encryptShare = true)

        val gateMutex = Mutex()
        var holdResponses = false
        val heldResponses = ArrayList<ByteArray>()
        val wireChannel = Channel<ByteArray>(Channel.UNLIMITED)
        var inFlightSentSignal = CompletableDeferred<Unit>()

        val gatedTransport = object : SmbPacketTransport {
            override suspend fun sendPacket(packet: ByteArray) {
                gateMutex.withLock {
                    backend.sendPacket(packet)
                    val produced = ArrayList<ByteArray>()
                    while (backend.hasPendingResponses()) {
                        produced.add(backend.receivePacket())
                    }
                    if (holdResponses) {
                        heldResponses.addAll(produced)
                        inFlightSentSignal.complete(Unit)
                    } else {
                        for (resp in produced) {
                            wireChannel.trySend(resp)
                        }
                    }
                }
            }

            override suspend fun receivePacket(): ByteArray = wireChannel.receive()

            override fun close() {
                wireChannel.close()
                backend.close()
            }
        }

        suspend fun releaseHeldResponses() {
            gateMutex.withLock {
                holdResponses = false
                for (resp in heldResponses) {
                    wireChannel.trySend(resp)
                }
                heldResponses.clear()
            }
        }

        withContext(Dispatchers.Default) {
            val client = SmbClient(
                host = "192.168.1.10",
                port = 445,
                config = SmbConfig(encryptionPolicy = SmbEncryptionPolicy.REQUIRED),
                transport = gatedTransport,
                readerDispatcher = Dispatchers.IO.limitedParallelism(2),
            )
            client.initializeSession(creds)
            val share = client.connectShare("PublicDocs")
            share.writeBytes("data/comic.cbz", ByteArray(8192) { (it and 0xFF).toByte() })
            assertEquals(0, backend.openHandleCount())

            // 1. Cancel an in-flight openFile (SMB2 CREATE): connection must stay healthy and leaked FileId must be auto-closed
            gateMutex.withLock {
                holdResponses = true
                inFlightSentSignal = CompletableDeferred()
            }
            val openJob = launch {
                share.openFile("data/comic.cbz").closeSuspend()
            }
            inFlightSentSignal.await()
            openJob.cancelAndJoin()
            assertFalse(client.isClosed, "Cancelling a single caller must not close the shared SmbClient")

            releaseHeldResponses()
            kotlinx.coroutines.withTimeout(1_000L) {
                while (backend.openHandleCount() != 0) {
                    kotlinx.coroutines.delay(5L)
                }
            }
            assertTrue(share.exists("data/comic.cbz"))
            assertEquals(0, backend.openHandleCount(), "Orphaned CREATE handle from cancelled openFile must be closed")

            // 1b. Cancel an in-flight [CREATE, SET_INFO, CLOSE] compound where CREATE succeeds, SET_INFO fails, and trailing CLOSE fails:
            //     cleanupOrphanedCompoundResponses must still close the leaked FileId
            backend.failTrailingCloseOnSetInfoError = true
            gateMutex.withLock {
                holdResponses = true
                inFlightSentSignal = CompletableDeferred()
            }
            val delNonEmptyJob = async {
                runCatching { share.deleteDirectory("data") }
            }
            inFlightSentSignal.await()
            delNonEmptyJob.cancelAndJoin()
            releaseHeldResponses()
            kotlinx.coroutines.withTimeout(1_000L) {
                while (backend.openHandleCount() != 0) {
                    kotlinx.coroutines.delay(5L)
                }
            }
            backend.failTrailingCloseOnSetInfoError = false
            assertEquals(0, backend.openHandleCount(), "Orphaned CREATE handle from cancelled compound with failed CLOSE must be closed")

            // 2. Cancel an active coroutine whose OWN Job (currentCoroutineContext()[Job]) is set on raf.callerJob
            //    while blocked inside raf.read() -> runBlocking (verifying immediate Cancelling-state interruption)
            val raf = share.openRandomAccessFile("data/comic.cbz", "r")

            gateMutex.withLock {
                holdResponses = true
                inFlightSentSignal = CompletableDeferred()
            }
            var capturedReadError: Throwable? = null
            val activeThumbnailCoroutine = launch(Dispatchers.IO.limitedParallelism(1)) {
                raf.callerJob = kotlinx.coroutines.currentCoroutineContext()[Job]
                try {
                    val buf = ByteArray(1024)
                    raf.read(buf, 0, buf.size)
                } catch (t: Throwable) {
                    capturedReadError = t
                    throw t
                } finally {
                    raf.callerJob = null
                }
            }
            inFlightSentSignal.await()
            kotlinx.coroutines.withTimeout(1_000L) {
                activeThumbnailCoroutine.cancelAndJoin()
            }

            assertTrue(
                capturedReadError is CancellationException,
                "Expected CancellationException from raf.read on active coroutine Cancelling, got $capturedReadError",
            )
            assertFalse(client.isClosed, "Cancelling raf.callerJob must not close the shared SmbClient")

            releaseHeldResponses()
            // Closing the cancelled SmbRandomAccessFile must still send SMB2 CLOSE (cancellable = false)
            raf.close()
            assertEquals(0, backend.openHandleCount(), "raf.close() must close the SMB file handle even after callerJob cancellation")

            // Shared SmbClient & SmbShare remain healthy for subsequent visible thumbnails
            assertEquals(8192L, share.stat("data/comic.cbz").size)
            share.closeSuspend()
            client.closeSuspend()

            // 3. Cancelling a head-of-line multi-credit waiter must immediately wake subsequent 1-credit waiters
            val stingyWakeBackend = MockSmb3ServerTransport(
                expectedCredentials = creds,
                encryptShare = false,
                creditsGrantedPerResponse = 1u,
                echoCreditsGranted = 2u,
            )
            val wakeChannel = Channel<ByteArray>(Channel.UNLIMITED)
            val wakeLock = Mutex()
            var holdEchoResp = false
            val heldEchoResps = ArrayList<ByteArray>()
            val echoSentSignal = CompletableDeferred<Unit>()
            val wakeTransport = object : SmbPacketTransport {
                override suspend fun sendPacket(packet: ByteArray) {
                    wakeLock.withLock {
                        val cmd = SmbHeader.decode(packet).command
                        stingyWakeBackend.sendPacket(packet)
                        val produced = ArrayList<ByteArray>()
                        while (stingyWakeBackend.hasPendingResponses()) {
                            produced.add(stingyWakeBackend.receivePacket())
                        }
                        if (holdEchoResp && cmd == SmbCommand.ECHO) {
                            heldEchoResps.addAll(produced)
                            echoSentSignal.complete(Unit)
                        } else {
                            for (r in produced) wakeChannel.trySend(r)
                        }
                    }
                }
                override suspend fun receivePacket(): ByteArray = wakeChannel.receive()
                override fun close() {
                    wakeChannel.close()
                    stingyWakeBackend.close()
                }
            }
            val wClient = SmbClient(
                host = "192.168.1.10",
                port = 445,
                config = SmbConfig(encryptionPolicy = SmbEncryptionPolicy.DISABLED),
                transport = wakeTransport,
                readerDispatcher = Dispatchers.IO.limitedParallelism(2),
            )
            wClient.initializeSession(creds)
            val wShare = wClient.connectShare("PublicDocs")
            val wFile = wShare.openFile(
                path = "notes/wake.txt",
                desiredAccess = SmbAccessMask.WRITE_DEFAULT,
                createDisposition = SmbCreateDisposition.FILE_OVERWRITE_IF,
            )
            stingyWakeBackend.creditsGrantedPerResponse = 2u
            wFile.write(0L, "wake".encodeToByteArray())
            stingyWakeBackend.creditsGrantedPerResponse = 1u
            // availableCredits is now exactly 2.
            // headWaiter needs 3 credits -> triggers ECHO (which consumes 1 credit, leaving availableCredits == 1 while ECHO response is held).
            // tailWaiter needs 1 credit -> queues behind headWaiter.
            // Cancelling headWaiter must immediately wake tailWaiter using the remaining 1 credit even while ECHO is still held!
            wakeLock.withLock { holdEchoResp = true }
            val headWaiter = async { runCatching { wShare.deleteFile("notes/missing_3cred.txt") } }
            echoSentSignal.await()
            val tailWaiter = async { wFile.read(0L, 4).decodeToString() }
            kotlinx.coroutines.delay(15L) // Ensure tailWaiter is queued behind headWaiter
            headWaiter.cancelAndJoin()
            assertEquals("wake", kotlinx.coroutines.withTimeout(1_000L) { tailWaiter.await() })
            wakeLock.withLock {
                holdEchoResp = false
                for (r in heldEchoResps) wakeChannel.trySend(r)
                heldEchoResps.clear()
            }
            wFile.closeSuspend()
            wShare.closeSuspend()
            wClient.closeSuspend()

            // 4. Cancelling initializeSession mid-handshake aborts immediately instead of hanging for requestTimeout (30s)
            val stalledHandshakeSent = CompletableDeferred<Unit>()
            val stalledHandshakeTransport = object : SmbPacketTransport {
                override suspend fun sendPacket(packet: ByteArray) {
                    stalledHandshakeSent.complete(Unit)
                }
                override suspend fun receivePacket(): ByteArray {
                    kotlinx.coroutines.awaitCancellation()
                }
                override fun close() {}
            }
            val hClient = SmbClient(
                host = "192.168.1.10",
                port = 445,
                config = SmbConfig(requestTimeout = 30.seconds),
                transport = stalledHandshakeTransport,
            )
            var handshakeErr: Throwable? = null
            val hJob = launch {
                try {
                    hClient.initializeSession(creds)
                } catch (t: Throwable) {
                    handshakeErr = t
                    throw t
                }
            }
            stalledHandshakeSent.await()
            kotlinx.coroutines.withTimeout(1_000L) {
                hJob.cancelAndJoin()
            }
            assertTrue(handshakeErr is CancellationException, "Expected CancellationException on cancelled handshake, got $handshakeErr")
            assertTrue(hClient.isClosed, "Cancelled handshake must close the half-initialized SmbClient")
        }
    }

    @Test
    fun testLargeChunkedIoAndMultiBatchDirectoryAndProtocolModels() = runTest {
        val creds = SmbCredentials("alice", "SecretPassword123!", "WORKGROUP")
        val mockTransport = MockSmb3ServerTransport(
            expectedCredentials = creds,
            encryptShare = false,
            maxReadWriteSize = 4096u,
            multiBatchDirectoryQuery = true,
        )
        val client = SmbClient("192.168.1.10", 445, SmbConfig(encryptionPolicy = SmbEncryptionPolicy.DISABLED), mockTransport)
        client.initializeSession(creds)
        assertEquals(4096, client.maxReadSize)
        assertEquals(4096, client.maxWriteSize)
        assertEquals(4096, client.maxTransactSize)

        val share = client.connectShare("PublicDocs")

        // 1. Write & read 70KB (> 64KB segment buffer and > 4KB SMB MaxWriteSize/MaxReadSize) with closeFileOnClose = false
        val largePayload = ByteArray(70_000) { idx -> ((idx * 13 + 7) and 0xFF).toByte() }
        val file = share.openFile(
            path = "streams/large.bin",
            desiredAccess = SmbAccessMask.WRITE_DEFAULT,
            createDisposition = SmbCreateDisposition.FILE_OVERWRITE_IF,
        )
        file.asSink(startOffset = 0L, closeFileOnClose = false).use { sink ->
            sink.write(largePayload)
            sink.flush()
        }
        assertFalse(file.isClosed)
        assertEquals(70_000L, file.size)

        val readBack = file.asSource(startOffset = 0L, closeFileOnClose = false).use { source ->
            source.readByteArray()
        }
        assertFalse(file.isClosed)
        assertContentEquals(largePayload, readBack)

        // Direct chunked file.read(offset, length) > maxChunk
        val directRead = file.read(0L, 10_000)
        assertContentEquals(largePayload.copyOfRange(0, 10_000), directRead)
        assertEquals(0, file.read(0L, 0).size)
        assertEquals(0, file.readInto(0L, ByteArray(4), 0, 0))
        assertEquals(0, file.write(0L, ByteArray(0)))

        // Shared lock without failImmediately
        file.lock(offset = 0L, length = 100L, exclusive = false, failImmediately = false)
        file.unlock(offset = 0L, length = 100L)
        file.close()
        assertTrue(file.isClosed)

        // 2. appendBytes, writeBytes(overwrite = false), openSink(overwrite = false), deleteDirectory, deleteRecursively on single file
        share.writeBytes("notes/new_only.txt", "Part1".encodeToByteArray(), overwrite = false)
        val fileCollisionEx = assertFailsWith<SmbException> {
            share.writeBytes("notes/new_only.txt", "Duplicate".encodeToByteArray(), overwrite = false)
        }
        assertEquals(NtStatus.STATUS_OBJECT_NAME_COLLISION, fileCollisionEx.ntStatus)
        share.appendBytes("notes/new_only.txt", "-Part2".encodeToByteArray())
        assertEquals("Part1-Part2", share.readText("notes/new_only.txt"))
        share.deleteRecursively("notes/new_only.txt")
        assertFalse(share.exists("notes/new_only.txt"))
        // deleteRecursively on non-existent path returns cleanly
        share.deleteRecursively("notes/does_not_exist.txt")

        share.openSink("notes/sink_create.txt", append = false, overwrite = false).use { sink ->
            sink.writeString("Created via Sink")
        }
        val sinkCollisionEx = assertFailsWith<SmbException> {
            share.openSink("notes/sink_create.txt", append = false, overwrite = false)
        }
        assertEquals(NtStatus.STATUS_OBJECT_NAME_COLLISION, sinkCollisionEx.ntStatus)
        assertEquals("Created via Sink", share.readText("notes/sink_create.txt"))

        share.createDirectory("empty_dir")
        val dirCollisionEx = assertFailsWith<SmbException> {
            share.createDirectory("empty_dir")
        }
        assertEquals(NtStatus.STATUS_OBJECT_NAME_COLLISION, dirCollisionEx.ntStatus)
        share.deleteDirectory("empty_dir")
        assertFalse(share.exists("empty_dir"))

        // 3. Multi-batch directory listing (1 entry per QUERY_DIRECTORY response before STATUS_NO_MORE_FILES)
        share.writeText("notes/second_batch.txt", "Second batch entry")
        val entries = share.listDirectory("notes")
        assertEquals(2, entries.size)
        assertEquals(setOf("sink_create.txt", "second_batch.txt"), entries.map { it.name }.toSet())
        val firstEntry = entries.first()
        assertFalse(firstEntry.isDirectory)
        assertFalse(firstEntry.isReadOnly)
        assertFalse(firstEntry.isHidden)

        // 4. ByteUtils FILETIME round-trip & NtStatus.nameOf coverage
        assertEquals(0L, filetimeToEpochMillis(0uL))
        assertEquals(0L, filetimeToEpochMillis(100uL))
        assertEquals(0uL, epochMillisToFiletime(0L))
        val nowMillis = 1700000000000L
        assertEquals(nowMillis, filetimeToEpochMillis(epochMillisToFiletime(nowMillis)))

        val knownStatuses = listOf(
            NtStatus.STATUS_SUCCESS,
            NtStatus.STATUS_PENDING,
            NtStatus.STATUS_BUFFER_OVERFLOW,
            NtStatus.STATUS_NO_MORE_FILES,
            NtStatus.STATUS_INVALID_PARAMETER,
            NtStatus.STATUS_NO_SUCH_FILE,
            NtStatus.STATUS_END_OF_FILE,
            NtStatus.STATUS_MORE_PROCESSING_REQUIRED,
            NtStatus.STATUS_ACCESS_DENIED,
            NtStatus.STATUS_OBJECT_NAME_INVALID,
            NtStatus.STATUS_OBJECT_NAME_NOT_FOUND,
            NtStatus.STATUS_OBJECT_NAME_COLLISION,
            NtStatus.STATUS_OBJECT_PATH_NOT_FOUND,
            NtStatus.STATUS_SHARING_VIOLATION,
            NtStatus.STATUS_FILE_LOCK_CONFLICT,
            NtStatus.STATUS_LOCK_NOT_GRANTED,
            NtStatus.STATUS_LOGON_FAILURE,
            NtStatus.STATUS_INVALID_NETWORK_RESPONSE,
            NtStatus.STATUS_BAD_NETWORK_NAME,
            NtStatus.STATUS_NOT_A_DIRECTORY,
            NtStatus.STATUS_FILE_IS_A_DIRECTORY,
            NtStatus.STATUS_DIRECTORY_NOT_EMPTY,
            0xDEAD_BEEFu,
        )
        for (st in knownStatuses) {
            assertTrue(NtStatus.nameOf(st).isNotEmpty())
        }

        share.closeSuspend()
        client.closeSuspend()
    }

    @Test
    fun testLoopbackTcpTransportAndSmbClientConnect() = runTest {
        val creds = SmbCredentials("alice", "SecretPassword123!", "WORKGROUP")
        val mockBackend = MockSmb3ServerTransport(creds, encryptShare = true)

        withContext(Dispatchers.IO) {
            // 1. Valid Direct TCP session over loopback socket
            val selector = SelectorManager(Dispatchers.IO)
            val serverSocket = aSocket(selector).tcp().bind("127.0.0.1", 0)
            val port = (serverSocket.localAddress as InetSocketAddress).port

            val serverJob = launch {
                val clientSocket = try {
                    serverSocket.accept()
                } catch (_: Throwable) {
                    return@launch
                }
                try {
                    val readCh = clientSocket.openReadChannel()
                    val writeCh = clientSocket.openWriteChannel(autoFlush = false)
                    val prefix = ByteArray(4)
                    while (true) {
                        readCh.readFully(prefix, 0, 4)
                        val len = ((prefix[1].toInt() and 0xFF) shl 16) or
                            ((prefix[2].toInt() and 0xFF) shl 8) or
                            (prefix[3].toInt() and 0xFF)
                        val req = ByteArray(len)
                        readCh.readFully(req, 0, len)
                        mockBackend.sendPacket(req)
                        while (mockBackend.hasPendingResponses()) {
                            val resp = mockBackend.receivePacket()
                            val outPrefix = byteArrayOf(
                                0,
                                ((resp.size ushr 16) and 0xFF).toByte(),
                                ((resp.size ushr 8) and 0xFF).toByte(),
                                (resp.size and 0xFF).toByte(),
                            )
                            writeCh.writeFully(outPrefix, 0, 4)
                            writeCh.writeFully(resp, 0, resp.size)
                            writeCh.flush()
                        }
                    }
                } catch (_: Throwable) {
                } finally {
                    runCatching { clientSocket.close() }
                }
            }

            var client: SmbClient? = null
            try {
                val connected = SmbClient.connect(
                    host = "127.0.0.1",
                    port = port,
                    credentials = creds,
                    config = SmbConfig(encryptionPolicy = SmbEncryptionPolicy.REQUIRED),
                )
                client = connected
                assertEquals(SmbDialect.SMB_3_1_1, connected.negotiatedDialect)
                val share = connected.connectShare("PublicDocs")
                share.writeText("notes/tcp.txt", "Over real TCP loopback!")
                assertEquals("Over real TCP loopback!", share.readText("notes/tcp.txt"))
                share.closeSuspend()
            } finally {
                runCatching { client?.closeSuspend() }
                serverJob.cancel()
                runCatching { serverSocket.close() }
                runCatching { selector.close() }
            }

            // 2. Malformed Direct TCP stream header & undersized frame length guards + SmbClient.connect rollback
            for (badFrame in listOf(
                byteArrayOf(0x01, 0x00, 0x00, 0x40), // Non-zero first byte
                byteArrayOf(0x00, 0x00, 0x00, 0x10), // Frame length (16) < SmbHeader.SIZE (64)
            )) {
                val badSelector = SelectorManager(Dispatchers.IO)
                val badServer = aSocket(badSelector).tcp().bind("127.0.0.1", 0)
                val badPort = (badServer.localAddress as InetSocketAddress).port
                val badJob = launch {
                    val sock = try {
                        badServer.accept()
                    } catch (_: Throwable) {
                        return@launch
                    }
                    try {
                        val r = sock.openReadChannel()
                        val w = sock.openWriteChannel(autoFlush = false)
                        val hdr = ByteArray(4)
                        r.readFully(hdr, 0, 4)
                        val reqLen = ((hdr[1].toInt() and 0xFF) shl 16) or
                            ((hdr[2].toInt() and 0xFF) shl 8) or
                            (hdr[3].toInt() and 0xFF)
                        if (reqLen > 0) {
                            r.readFully(ByteArray(reqLen), 0, reqLen)
                        }
                        w.writeFully(badFrame, 0, badFrame.size)
                        w.flush()
                    } catch (_: Throwable) {
                    } finally {
                        runCatching { sock.close() }
                    }
                }
                try {
                    assertFailsWith<IllegalStateException> {
                        SmbClient.connect(
                            host = "127.0.0.1",
                            port = badPort,
                            credentials = creds,
                        )
                    }
                } finally {
                    badJob.cancel()
                    runCatching { badServer.close() }
                    runCatching { badSelector.close() }
                }

                // 9. Verify deprecated Long-based SmbConfig constructors and properties
                @Suppress("DEPRECATION")
                val cfgConnectOnly = SmbConfig(connectTimeoutMillis = 5_000L)
                assertEquals(5_000L, cfgConnectOnly.connectTimeout.inWholeMilliseconds)
                assertEquals(30_000L, cfgConnectOnly.requestTimeout.inWholeMilliseconds)
                @Suppress("DEPRECATION")
                assertEquals(5_000L, cfgConnectOnly.connectTimeoutMillis)

                @Suppress("DEPRECATION")
                val cfgRequestOnly = SmbConfig(requestTimeoutMillis = 15_000L)
                assertEquals(10_000L, cfgRequestOnly.connectTimeout.inWholeMilliseconds)
                assertEquals(15_000L, cfgRequestOnly.requestTimeout.inWholeMilliseconds)
                @Suppress("DEPRECATION")
                assertEquals(15_000L, cfgRequestOnly.requestTimeoutMillis)

                @Suppress("DEPRECATION")
                val cfgBoth = SmbConfig(connectTimeoutMillis = 4_000L, requestTimeoutMillis = 12_000L)
                assertEquals(4_000L, cfgBoth.connectTimeout.inWholeMilliseconds)
                assertEquals(12_000L, cfgBoth.requestTimeout.inWholeMilliseconds)
            }
        }
    }

    /**
     * In-memory mock SMB2/SMB3 server transport for end-to-end testing.
     */
    @OptIn(ExperimentalCoroutinesApi::class)
    private class MockSmb3ServerTransport(
        private val expectedCredentials: SmbCredentials,
        private val dialect: SmbDialect = SmbDialect.SMB_3_1_1,
        private val cipherId: SmbCipherId = SmbCipherId.AES_128_GCM,
        private val encryptShare: Boolean = true,
        private val omitRelatedErrorResponses: Boolean = false,
        private val maxReadWriteSize: UInt = 65536u,
        private val immediateAnonymousSuccess: Boolean = false,
        private val returnGuestSessionFlag: Boolean = false,
        private val includeTimestampInChallenge: Boolean = false,
        private val injectPendingAndNotifications: Boolean = false,
        private val multiFragmentRpcResponse: Boolean = false,
        private val multiBatchDirectoryQuery: Boolean = false,
        var creditsGrantedPerResponse: UShort = 31u,
        private val echoCreditsGranted: UShort = creditsGrantedPerResponse,
    ) : SmbPacketTransport {

        private val serverMutex = Mutex()
        private val responseChannel = Channel<ByteArray>(Channel.UNLIMITED)
        private var preauthHash = ByteArray(64)
        private val serverChallenge = ByteArray(8) { (0x11 * (it + 1)).toByte() }
        private var serverSigningKey: ByteArray? = null
        private var serverEncryptionKey: ByteArray? = null // ServerOutKey (SMBS2CCipherKey)
        private var serverDecryptionKey: ByteArray? = null // ServerInKey (SMBC2SCipherKey)
        private val sessionId: ULong = 0x1000200030004000uL

        private val files = mutableMapOf<String, ByteArray>()
        private val directories = mutableSetOf("", "notes", "data", "streams")
        private val openHandles = mutableMapOf<ULong, String>()
        private val pendingPipeReads = mutableMapOf<ULong, ByteArray>()
        private val dirQueryCounts = mutableMapOf<ULong, Int>()
        private var nextHandleId: ULong = 100uL
        private var lastSeenMessageId: Long = -1L

        var splitRpcTransceiveResponse: Boolean = false
        var stripServerSignatureOnNextResponse: Boolean = false
        var corruptServerSignatureOnNextResponse: Boolean = false
        var failTrailingCloseOnSetInfoError: Boolean = false
        var encryptedPacketsCount: Int = 0
            private set
        var readRequestsCount: Int = 0
            private set
        val signedRequestCommands = mutableListOf<SmbCommand>()

        fun hasPendingResponses(): Boolean = !responseChannel.isEmpty

        suspend fun openHandleCount(): Int = serverMutex.withLock { openHandles.size }

        override suspend fun sendPacket(packet: ByteArray) = serverMutex.withLock {
            val wasEncrypted = SmbTransformHeader.isTransformPacket(packet)
            val plainPacket = if (wasEncrypted) {
                encryptedPacketsCount++
                SmbTransformHeader.decryptPacket(packet, cipherId, serverDecryptionKey!!)
            } else {
                packet
            }

            val reqParts = SmbMessages.splitCompoundPacket(plainPacket)
            var lastCompoundHandleId: ULong = 0uL
            var compoundFailedStatus: UInt = NtStatus.STATUS_SUCCESS
            val respParts = mutableListOf<ByteArray>()

            for ((partIndex, rawPart) in reqParts.withIndex()) {
                val reqHeader = SmbHeader.decode(rawPart)
                if (!wasEncrypted && reqHeader.isSigned) {
                    signedRequestCommands.add(reqHeader.command)
                }
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
                        resp.writeUShortLE(14, creditsGrantedPerResponse)
                        preauthHash = updateHash(preauthHash, resp)
                        resp
                    }
                    SmbCommand.SESSION_SETUP -> {
                        preauthHash = updateHash(preauthHash, plainReq)
                        val secBufOffset = plainReq.readUShortLE(SmbHeader.SIZE + 12).toInt()
                        val secBufLen = plainReq.readUShortLE(SmbHeader.SIZE + 14).toInt()
                        val secBlob = plainReq.copyOfRange(secBufOffset, secBufOffset + secBufLen)

                        if (reqHeader.sessionId == 0uL) {
                            if (immediateAnonymousSuccess) {
                                buildSessionSetupSuccess(reqHeader.messageId)
                            } else {
                                val resp = buildSessionSetupChallenge(reqHeader.messageId)
                                resp.writeUShortLE(14, creditsGrantedPerResponse)
                                preauthHash = updateHash(preauthHash, resp)
                                resp
                            }
                        } else {
                            if (!expectedCredentials.isAnonymous && !returnGuestSessionFlag) {
                                deriveSessionKeysFromType3(secBlob)
                            }
                            buildSessionSetupSuccess(reqHeader.messageId)
                        }
                    }
                    SmbCommand.TREE_CONNECT -> buildTreeConnectResponse(reqHeader)
                    SmbCommand.TREE_DISCONNECT, SmbCommand.LOGOFF, SmbCommand.ECHO -> buildSimpleResponse(reqHeader, 4)
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
                            dirQueryCounts.remove(vId)
                        }
                        buildSimpleResponse(reqHeader, if (reqHeader.command == SmbCommand.CLOSE) 60 else 4)
                    }
                    SmbCommand.WRITE -> handleWrite(reqHeader, plainReq)
                    SmbCommand.READ -> handleRead(reqHeader, plainReq)
                    SmbCommand.QUERY_DIRECTORY -> handleQueryDirectory(reqHeader, plainReq)
                    SmbCommand.LOCK -> buildSimpleResponse(reqHeader, 4)
                    SmbCommand.SET_INFO -> {
                        val resp = handleSetInfo(reqHeader, plainReq)
                        val respHdr = SmbHeader.decode(resp)
                        if (failTrailingCloseOnSetInfoError && respHdr.status != NtStatus.STATUS_SUCCESS) {
                            compoundFailedStatus = respHdr.status
                        }
                        resp
                    }
                    SmbCommand.IOCTL -> handleIoctl(reqHeader, plainReq)
                    else -> buildSimpleResponse(reqHeader, 4, NtStatus.STATUS_NOT_SUPPORTED)
                }
                respParts.add(singleResp)
            }

            if (injectPendingAndNotifications && reqParts.first().let { SmbHeader.decode(it).command } !in listOf(SmbCommand.NEGOTIATE, SmbCommand.SESSION_SETUP)) {
                val firstMsgId = SmbHeader.decode(reqParts.first()).messageId
                // 1. Unsolicited OPLOCK_BREAK notification (MessageId = ULong.MAX_VALUE)
                val unsolicited = ByteArray(SmbHeader.SIZE + 24)
                SmbHeader(
                    command = SmbCommand.OPLOCK_BREAK,
                    creditRequestResponse = 0u,
                    flags = SmbHeader.SMB2_FLAGS_SERVER_TO_REDIR,
                    messageId = ULong.MAX_VALUE,
                ).encodeInto(unsolicited, 0)
                responseChannel.trySend(unsolicited)

                // 2. Interim STATUS_PENDING async response
                val pending = ByteArray(SmbHeader.SIZE + 8)
                SmbHeader(
                    status = NtStatus.STATUS_PENDING,
                    command = SmbHeader.decode(reqParts.first()).command,
                    creditRequestResponse = 0u,
                    flags = SmbHeader.SMB2_FLAGS_SERVER_TO_REDIR or SmbHeader.SMB2_FLAGS_ASYNC_COMMAND,
                    messageId = firstMsgId,
                    asyncIdOrTreeId = 0xCAFE_BABEuL,
                    sessionId = sessionId,
                ).encodeInto(pending, 0)
                responseChannel.trySend(pending)

                // 3. Stale response with older MessageId (0)
                if (firstMsgId > 1uL) {
                    val stale = ByteArray(SmbHeader.SIZE + 4)
                    SmbHeader(
                        command = SmbCommand.ECHO,
                        creditRequestResponse = 0u,
                        flags = SmbHeader.SMB2_FLAGS_SERVER_TO_REDIR,
                        messageId = 0uL,
                        sessionId = sessionId,
                    ).encodeInto(stale, 0)
                    responseChannel.trySend(stale)
                }
            }

            for (respPart in respParts) {
                val cmd = SmbHeader.decode(respPart).command
                respPart.writeUShortLE(
                    14,
                    if (cmd == SmbCommand.ECHO) echoCreditsGranted else creditsGrantedPerResponse,
                )
            }
            val signEach: ((ByteArray) -> Unit)? = if (!wasEncrypted && serverSigningKey != null) {
                { slice ->
                    val hdr = SmbHeader.decode(slice)
                    if (hdr.command != SmbCommand.NEGOTIATE &&
                        !(hdr.command == SmbCommand.SESSION_SETUP && hdr.status != NtStatus.STATUS_SUCCESS)
                    ) {
                        if (stripServerSignatureOnNextResponse) {
                            stripServerSignatureOnNextResponse = false
                        } else {
                            SmbHeader.signPacket(slice, dialect, serverSigningKey!!)
                            if (corruptServerSignatureOnNextResponse) {
                                corruptServerSignatureOnNextResponse = false
                                slice[48] = (slice[48].toInt() xor 0xFF).toByte()
                            }
                        }
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
                    cipherId = cipherId,
                    encryptionKey = serverEncryptionKey!!
                )
            } else {
                plainResp
            }
            responseChannel.trySend(wireResp)
            Unit
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

        override suspend fun receivePacket(): ByteArray = responseChannel.receive()

        override fun close() {
            responseChannel.close()
        }

        private fun updateHash(h: ByteArray, p: ByteArray): ByteArray {
            val combined = ByteArray(h.size + p.size)
            h.copyInto(combined, 0)
            p.copyInto(combined, h.size)
            return Sha512.digest(combined)
        }

        private fun buildNegotiateResponse(messageId: ULong): ByteArray {
            if (dialect != SmbDialect.SMB_3_1_1) {
                val packet = ByteArray(SmbHeader.SIZE + 64)
                SmbHeader(
                    command = SmbCommand.NEGOTIATE,
                    flags = SmbHeader.SMB2_FLAGS_SERVER_TO_REDIR,
                    messageId = messageId,
                ).encodeInto(packet, 0)
                val b = SmbHeader.SIZE
                packet.writeUShortLE(b, 65u)
                packet.writeUShortLE(b + 2, 0x0001u)
                packet.writeUShortLE(b + 4, dialect.code)
                val caps = if (dialect.isSmb3 && encryptShare) {
                    SmbMessages.SMB2_GLOBAL_CAP_LARGE_MTU or SmbMessages.SMB2_GLOBAL_CAP_ENCRYPTION
                } else {
                    0u
                }
                packet.writeUIntLE(b + 24, caps)
                packet.writeUIntLE(b + 28, maxReadWriteSize)
                packet.writeUIntLE(b + 32, maxReadWriteSize)
                packet.writeUIntLE(b + 36, maxReadWriteSize)
                return packet
            }

            // Context 1: SMB2_PREAUTH_INTEGRITY_CAPABILITIES (0x0001), HashAlgorithmCount=1, SaltLength=32, HashAlgorithms[0]=SHA-512 (0x0001)
            // Header(8) + Data(6 + 32 = 38) = 46 bytes, padded to 8-byte alignment = 48 bytes
            val ctx1 = ByteArray(48)
            ctx1.writeUShortLE(0, 0x0001u) // Type = SMB2_PREAUTH_INTEGRITY_CAPABILITIES
            ctx1.writeUShortLE(2, 38u) // DataLength = 38
            ctx1.writeUShortLE(8, 1u) // HashAlgorithmCount = 1
            ctx1.writeUShortLE(10, 32u) // SaltLength = 32
            ctx1.writeUShortLE(12, 0x0001u) // SHA-512

            // Context 2: SMB2_ENCRYPTION_CAPABILITIES (0x0002), CipherCount=1
            val ctx2 = ByteArray(14)
            ctx2.writeUShortLE(0, 0x0002u) // Type = SMB2_ENCRYPTION_CAPABILITIES
            ctx2.writeUShortLE(2, 6u) // DataLength = 6
            ctx2.writeUShortLE(8, 1u) // CipherCount = 1
            ctx2.writeUShortLE(10, cipherId.code)
            ctx2.writeUShortLE(12, 0u) // Padding

            val ctxOffset = 64 + 64 // 128 (8-byte aligned)
            val packet = ByteArray(ctxOffset + ctx1.size + ctx2.size)
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
            packet.writeUShortLE(b + 6, 2u) // NegotiateContextCount = 2
            packet.writeUIntLE(b + 24, SmbMessages.SMB2_GLOBAL_CAP_LARGE_MTU or SmbMessages.SMB2_GLOBAL_CAP_ENCRYPTION)
            packet.writeUIntLE(b + 28, maxReadWriteSize)
            packet.writeUIntLE(b + 32, maxReadWriteSize)
            packet.writeUIntLE(b + 36, maxReadWriteSize)
            packet.writeUShortLE(b + 56, 128u) // SecurityBufferOffset
            packet.writeUShortLE(b + 58, 0u) // SecurityBufferLength
            packet.writeUIntLE(b + 60, ctxOffset.toUInt())

            ctx1.copyInto(packet, ctxOffset)
            ctx2.copyInto(packet, ctxOffset + ctx1.size)
            return packet
        }

        private fun buildSessionSetupChallenge(messageId: ULong): ByteArray {
            val targetInfo = if (includeTimestampInChallenge) {
                // MSV_AV_FLAGS (id=6, len=4, val=0) + MSV_AV_TIMESTAMP (id=7, len=8, val=133485408000000000) + MSV_AV_EOL (id=0, len=0)
                ByteArray(8 + 12 + 4).apply {
                    writeUShortLE(0, 6u)
                    writeUShortLE(2, 4u)
                    writeUIntLE(4, 0u)
                    writeUShortLE(8, 7u)
                    writeUShortLE(10, 8u)
                    writeULongLE(12, 133485408000000000uL)
                }
            } else {
                ByteArray(4) // MSV_AV_EOL
            }
            val type2 = ByteArray(48 + targetInfo.size)
            "NTLMSSP\u0000".encodeToByteArray().copyInto(type2, 0)
            type2.writeUIntLE(8, 2u)
            val flags = 0x62888215u
            type2.writeUIntLE(20, flags)
            serverChallenge.copyInto(type2, 24)
            type2.writeUShortLE(40, targetInfo.size.toUShort())
            type2.writeUShortLE(42, targetInfo.size.toUShort())
            type2.writeUIntLE(44, 48u)
            targetInfo.copyInto(type2, 48)

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

            if (dialect.isSmb3) {
                val derived = Smb3Kdf.deriveKeys(
                    dialect = dialect,
                    sessionKey = exportedSessionKey,
                    preauthIntegrityHash = if (dialect == SmbDialect.SMB_3_1_1) preauthHash else null,
                )
                serverSigningKey = derived.signingKey
                serverDecryptionKey = derived.encryptionKey
                serverEncryptionKey = derived.decryptionKey
            } else {
                serverSigningKey = exportedSessionKey.copyOf(16)
            }
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
            val sessFlags: UShort = when {
                returnGuestSessionFlag -> SmbMessages.SMB2_SESSION_FLAG_IS_GUEST
                encryptShare && dialect.isSmb3 -> SmbMessages.SMB2_SESSION_FLAG_ENCRYPT_DATA
                else -> 0u
            }
            packet.writeUShortLE(b + 2, sessFlags)
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
            packet.writeUIntLE(b + 4, if (encryptShare && dialect.isSmb3) SmbMessages.SMB2_SHAREFLAG_ENCRYPT_DATA else 0u)
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
            val isPipe = path == "srvsvc" || path == "wkssvc"

            // disposition 1 = FILE_OPEN, 2 = FILE_CREATE
            if (disposition == 1u && path.isNotEmpty() && !isPipe && !isKnownDir && !isKnownFile) {
                return buildSimpleResponse(reqHeader, 8, NtStatus.STATUS_OBJECT_NAME_NOT_FOUND)
            }
            if (disposition == 2u && path.isNotEmpty() && (isKnownDir || isKnownFile)) {
                return buildSimpleResponse(reqHeader, 8, NtStatus.STATUS_OBJECT_NAME_COLLISION)
            }
            if ((disposition == 0u || disposition >= 2u) && path.isNotEmpty()) {
                if (isDirCreate) {
                    directories.add(path)
                } else if (disposition == 0u || disposition == 4u || disposition == 5u || !isKnownFile) {
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

            if (path == "wkssvc") {
                pendingPipeReads[handleId] = plainReq.copyOfRange(dataOff, dataOff + dataLen)
            } else {
                val existing = files[path] ?: ByteArray(0)
                val newBuf = ByteArray(maxOf(existing.size, fileOff + dataLen))
                existing.copyInto(newBuf, 0)
                plainReq.copyInto(newBuf, fileOff, dataOff, dataOff + dataLen)
                files[path] = newBuf
            }

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
            readRequestsCount++
            val b = SmbHeader.SIZE
            val reqLen = plainReq.readUIntLE(b + 4).toInt()
            val fileOff = plainReq.readULongLE(b + 8).toInt()
            val handleId = plainReq.readULongLE(b + 24)
            val pendingPipe = pendingPipeReads.remove(handleId)
            val slice = if (pendingPipe != null) {
                if (pendingPipe.size <= reqLen) {
                    pendingPipe
                } else {
                    pendingPipeReads[handleId] = pendingPipe.copyOfRange(reqLen, pendingPipe.size)
                    pendingPipe.copyOfRange(0, reqLen)
                }
            } else {
                val path = openHandles[handleId] ?: ""
                val content = files[path] ?: ByteArray(0)
                val avail = (content.size - fileOff).coerceAtLeast(0).coerceAtMost(reqLen)
                if (avail > 0) content.copyOfRange(fileOff, fileOff + avail) else ByteArray(0)
            }

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
            val count = dirQueryCounts.getOrElse(handleId) { 0 }
            dirQueryCounts[handleId] = count + 1
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
                val emptyStatus = if (count == 0) NtStatus.STATUS_NO_SUCH_FILE else NtStatus.STATUS_NO_MORE_FILES
                return buildSimpleResponse(reqHeader, 8, emptyStatus)
            }

            val batchEntries = if (multiBatchDirectoryQuery) {
                if (count >= directEntries.size) {
                    return buildSimpleResponse(reqHeader, 8, NtStatus.STATUS_NO_MORE_FILES)
                }
                listOf(directEntries[count])
            } else {
                if (count >= 1) {
                    return buildSimpleResponse(reqHeader, 8, NtStatus.STATUS_NO_MORE_FILES)
                }
                directEntries
            }

            val encodedEntries = batchEntries.mapIndexed { idx, item ->
                val nameBytes = item.name.encodeToUtf16LE()
                val rawLen = 104 + nameBytes.size
                val isLast = idx == batchEntries.lastIndex
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
                    if (directories.remove(path)) {
                        directories.add(newPath)
                    } else {
                        val data = files.remove(path) ?: ByteArray(0)
                        files[newPath] = data
                    }
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
            val handleId = plainReq.readULongLE(b + 8)
            val inOff = plainReq.readUIntLE(b + 24).toInt()
            val inLen = plainReq.readUIntLE(b + 28).toInt()
            val rpcIn = plainReq.copyOfRange(inOff, inOff + inLen)
            val ptype = rpcIn[2].toInt()

            if (ptype == 11) {
                // Bind_ack (PTYPE = 12)
                val bindAck = ByteArray(24).apply {
                    this[0] = 5
                    this[1] = 0
                    this[2] = 12
                    this[3] = 0x03
                    writeUShortLE(8, 24u)
                }
                return buildIoctlResponsePacket(reqHeader, bindAck, NtStatus.STATUS_SUCCESS)
            }

            val shareSpecs = if (multiFragmentRpcResponse) {
                listOf(
                    Triple("PublicDocs\u0000", 0u, "Shared Documents\u0000"),
                    Triple("Printer1\u0000", 1u, "Office Printer\u0000"),
                    Triple("ComPort\u0000", 2u, "Serial Device\u0000"),
                    Triple("IPC$\u0000", 0x80000003u, "Remote IPC\u0000"),
                    Triple("Custom$\u0000", 99u, "Vendor Special\u0000"),
                )
            } else {
                listOf(Triple("PublicDocs\u0000", 0u, "Shared Documents\u0000"))
            }

            val stubBytes = buildNetrShareEnumStub(shareSpecs)

            val (outPayload, ioctlStatus) = when {
                multiFragmentRpcResponse -> {
                    val splitAt = stubBytes.size / 2
                    val stub1 = stubBytes.copyOfRange(0, splitAt)
                    val stub2 = stubBytes.copyOfRange(splitAt, stubBytes.size)
                    val pdu1 = ByteArray(24 + stub1.size).apply {
                        this[0] = 5
                        this[2] = 2
                        this[3] = 0x01 // PFC_FIRST_FRAG only
                        writeUShortLE(8, this.size.toUShort())
                        stub1.copyInto(this, 24)
                    }
                    val pdu2 = ByteArray(24 + stub2.size).apply {
                        this[0] = 5
                        this[2] = 2
                        this[3] = 0x02 // PFC_LAST_FRAG
                        writeUShortLE(8, this.size.toUShort())
                        stub2.copyInto(this, 24)
                    }
                    pendingPipeReads[handleId] = pdu2
                    pdu1 to NtStatus.STATUS_SUCCESS
                }
                splitRpcTransceiveResponse -> {
                    val pdu = ByteArray(24 + stubBytes.size).apply {
                        this[0] = 5
                        this[2] = 2
                        this[3] = 0x03
                        writeUShortLE(8, this.size.toUShort())
                        stubBytes.copyInto(this, 24)
                    }
                    pendingPipeReads[handleId] = pdu.copyOfRange(40, pdu.size)
                    pdu.copyOfRange(0, 40) to NtStatus.STATUS_BUFFER_OVERFLOW
                }
                else -> {
                    val pdu = ByteArray(24 + stubBytes.size).apply {
                        this[0] = 5
                        this[2] = 2
                        this[3] = 0x03
                        writeUShortLE(8, this.size.toUShort())
                        stubBytes.copyInto(this, 24)
                    }
                    pdu to NtStatus.STATUS_SUCCESS
                }
            }

            return buildIoctlResponsePacket(reqHeader, outPayload, ioctlStatus)
        }

        private fun buildNetrShareEnumStub(shares: List<Triple<String, UInt, String>>): ByteArray {
            val count = shares.size
            val stringsBytes = shares.flatMap { (name, _, rem) -> listOf(name, rem) }.sumOf { s ->
                val bLen = s.encodeToUtf16LE().size
                val pad = (4 - (bLen % 4)) % 4
                12 + bLen + pad
            }
            val stub = ByteArray(24 + count * 12 + stringsBytes + 12)
            var pos = 0
            stub.writeUIntLE(pos, 1u); pos += 4 // Level = 1
            stub.writeUIntLE(pos, 1u); pos += 4 // Switch = 1
            stub.writeUIntLE(pos, 0x00020000u); pos += 4 // Container Ptr
            stub.writeUIntLE(pos, count.toUInt()); pos += 4 // EntriesRead
            stub.writeUIntLE(pos, 0x00020004u); pos += 4 // Buffer Ptr
            stub.writeUIntLE(pos, count.toUInt()); pos += 4 // MaxCount

            var refId = 0x00020008u
            for ((_, type, _) in shares) {
                stub.writeUIntLE(pos, refId); refId += 4u; pos += 4
                stub.writeUIntLE(pos, type); pos += 4
                stub.writeUIntLE(pos, refId); refId += 4u; pos += 4
            }

            fun writeNdrString(strWithNull: String) {
                val utf16 = strWithNull.encodeToUtf16LE()
                val pad = (4 - (utf16.size % 4)) % 4
                stub.writeUIntLE(pos, strWithNull.length.toUInt()); pos += 4
                stub.writeUIntLE(pos, 0u); pos += 4
                stub.writeUIntLE(pos, strWithNull.length.toUInt()); pos += 4
                utf16.copyInto(stub, pos); pos += utf16.size + pad
            }

            for ((name, _, rem) in shares) {
                writeNdrString(name)
                writeNdrString(rem)
            }
            return stub
        }

        private fun buildIoctlResponsePacket(reqHeader: SmbHeader, outPayload: ByteArray, ioctlStatus: UInt): ByteArray {
            val b = SmbHeader.SIZE
            val outOffset = SmbHeader.SIZE + 48
            val packet = ByteArray(outOffset + outPayload.size)
            val header = SmbHeader.withTreeId(
                command = SmbCommand.IOCTL,
                messageId = reqHeader.messageId,
                treeId = reqHeader.treeId,
                sessionId = sessionId,
                flags = SmbHeader.SMB2_FLAGS_SERVER_TO_REDIR,
            ).copy(status = ioctlStatus)
            header.encodeInto(packet, 0)
            packet.writeUShortLE(b, 49u)
            packet.writeUIntLE(b + 32, outOffset.toUInt())
            packet.writeUIntLE(b + 36, outPayload.size.toUInt())
            outPayload.copyInto(packet, outOffset)
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
