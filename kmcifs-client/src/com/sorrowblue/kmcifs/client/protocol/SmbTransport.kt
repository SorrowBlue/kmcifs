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
 * Transport abstraction for sending and receiving SMB packets framed with a 4-byte stream length prefix over Direct TCP (port 445).
 */
internal interface SmbPacketTransport {
    suspend fun sendPacket(packet: ByteArray)
    suspend fun receivePacket(): ByteArray
    fun close()
}

/**
 * Multiplatform TCP socket transport implementation backed by `ktor-network`.
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
        check(receivePrefix[0].toInt() == 0) {
            "Invalid Direct TCP stream protocol header byte: 0x${(receivePrefix[0].toInt() and 0xFF).toString(16)}"
        }
        val length = ((receivePrefix[1].toInt() and 0xFF) shl 16) or
            ((receivePrefix[2].toInt() and 0xFF) shl 8) or
            (receivePrefix[3].toInt() and 0xFF)
        check(length >= SmbHeader.SIZE) {
            "Direct TCP frame length ($length) is smaller than minimum SMB2 header size (${SmbHeader.SIZE})"
        }
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
            var socket: Socket? = null
            return try {
                val connected = withTimeout(connectTimeoutMillis) {
                    aSocket(selectorManager).tcp().connect(host, port) {
                        noDelay = true
                    }
                }
                socket = connected
                val readChannel = connected.openReadChannel()
                val writeChannel = connected.openWriteChannel(autoFlush = false)
                KtorTcpSmbTransport(selectorManager, connected, readChannel, writeChannel)
            } catch (e: Throwable) {
                runCatching { socket?.close() }
                runCatching { selectorManager.close() }
                throw e
            }
        }
    }
}
