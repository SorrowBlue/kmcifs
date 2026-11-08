package com.sorrowblue.kmcifs.client.protocol

import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.Socket
import io.ktor.network.sockets.aSocket
import io.ktor.network.sockets.openReadChannel
import io.ktor.network.sockets.openWriteChannel
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.ByteWriteChannel
import io.ktor.utils.io.readFully
import io.ktor.utils.io.writeFully
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.withTimeout

/**
 * Direct TCP (ポート 445) 上で 4 バイトのストリーム長プレフィックス付き SMB パケットを送受信するトランスポート抽象。
 */
internal interface SmbPacketTransport {
    suspend fun sendPacket(packet: ByteArray)
    suspend fun receivePacket(): ByteArray
    fun close()
}

/**
 * `ktor-network` を用いたマルチプラットフォーム TCP ソケットトランスポート実装。
 */
internal class KtorTcpSmbTransport private constructor(
    private val selectorManager: SelectorManager,
    private val socket: Socket,
    private val readChannel: ByteReadChannel,
    private val writeChannel: ByteWriteChannel,
) : SmbPacketTransport {

    private val sendPrefix = ByteArray(4)
    private val receivePrefix = ByteArray(4)

    override suspend fun sendPacket(packet: ByteArray) {
        val len = packet.size
        sendPrefix[0] = 0x00 // Direct TCP Stream Protocol Header (0x00 + 24-bit big-endian length)
        sendPrefix[1] = ((len ushr 16) and 0xFF).toByte()
        sendPrefix[2] = ((len ushr 8) and 0xFF).toByte()
        sendPrefix[3] = (len and 0xFF).toByte()

        writeChannel.writeFully(sendPrefix, 0, 4)
        if (len > 0) {
            writeChannel.writeFully(packet, 0, len)
        }
        writeChannel.flush()
    }

    override suspend fun receivePacket(): ByteArray {
        readChannel.readFully(receivePrefix, 0, 4)
        val length = ((receivePrefix[1].toInt() and 0xFF) shl 16) or
            ((receivePrefix[2].toInt() and 0xFF) shl 8) or
            (receivePrefix[3].toInt() and 0xFF)
        val payload = ByteArray(length)
        if (length > 0) {
            readChannel.readFully(payload, 0, length)
        }
        return payload
    }

    override fun close() {
        runCatching { socket.close() }
        runCatching { selectorManager.close() }
    }

    companion object {
        suspend fun connect(host: String, port: Int, connectTimeoutMillis: Long): KtorTcpSmbTransport {
            val selectorManager = SelectorManager(Dispatchers.IO)
            return try {
                val socket = withTimeout(connectTimeoutMillis) {
                    aSocket(selectorManager).tcp().connect(host, port) {
                        noDelay = true
                    }
                }
                val readChannel = socket.openReadChannel()
                val writeChannel = socket.openWriteChannel(autoFlush = false)
                KtorTcpSmbTransport(selectorManager, socket, readChannel, writeChannel)
            } catch (e: Throwable) {
                runCatching { selectorManager.close() }
                throw e
            }
        }
    }
}
