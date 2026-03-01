package com.example.starlightcamerabridge.adb

import android.content.Context
import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.IOException
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.concurrent.atomic.AtomicInteger
import android.util.Base64

/**
 * ADB 客户端
 * 提供与 ADB 服务器通信的功能，支持 Shell 命令执行。
 */
class AdbClient(context: Context) {
    private val appContext = context.applicationContext
    private val keyStore = AdbKeyStore(appContext)

    @Volatile
    private var socket: Socket? = null
    @Volatile
    private var packetIO: AdbPacketIO? = null
    @Volatile
    private var maxPayloadSize: Int = AdbConstants.DEFAULT_MAX_PAYLOAD
    private val localIdCounter = AtomicInteger(1)

    /**
     * 连接到 ADB 服务器。
     *
     * @param host ADB 服务器地址
     * @param port ADB 服务器端口
     * @return Unit
     */
    suspend fun connect(host: String, port: Int) = withContext(Dispatchers.IO) {
        if (socket?.isConnected == true) return@withContext
        val sock = Socket()
        sock.tcpNoDelay = true
        sock.keepAlive = true
        sock.connect(InetSocketAddress(host, port), CONNECT_TIMEOUT_MS)
        maxPayloadSize = AdbConstants.DEFAULT_MAX_PAYLOAD
        val io = AdbPacketIO(sock.getInputStream(), sock.getOutputStream())
        performHandshake(io)
        socket = sock
        packetIO = io
    }

    /**
     * 判断是否已连接到 ADB 服务器。
     *
     * @return 已连接返回 true，否则返回 false
     */
    fun isConnected(): Boolean = socket?.isConnected == true

    /**
     * 执行 Shell 命令。
     *
     * @param command 待执行的 Shell 命令
     * @return Shell 输出内容
     */
    suspend fun executeShellCommand(command: String): String = withContext(Dispatchers.IO) {
        val rootCommand = AdbRootShell.wrapIfEnabled(appContext, command)
        executeShellCommandOnce(rootCommand.raw, rootCommand.logSafe)
    }

    /**
     * 通过 ADB sync 协议将文件推送到远程设备。
     *
     * @param data 文件原始字节数据
     * @param remotePath 远程目标路径
     * @param mode POSIX 文件权限模式（默认 0755）
     * @param onProgress 进度回调 (已发送字节, 总字节)
     */
    suspend fun pushFile(
        data: ByteArray,
        remotePath: String,
        mode: Int = 493, // 0755
        onProgress: ((sent: Int, total: Int) -> Unit)? = null
    ): Unit = withContext(Dispatchers.IO) {
        val io = packetIO ?: throw IllegalStateException("ADB not connected")
        val localId = localIdCounter.getAndIncrement()

        // 1. 打开 sync: 流
        io.send(
            command = AdbConstants.COMMAND_OPEN,
            arg0 = localId,
            arg1 = 0,
            payload = "sync:\u0000".toByteArray(Charsets.UTF_8),
        )
        val remoteId = waitForOkay(io, localId)

        try {
            // 2. 发送 SEND 指令
            val pathMode = "$remotePath,$mode"
            val pathModeBytes = pathMode.toByteArray(Charsets.UTF_8)
            val sendCmd = ByteBuffer.allocate(8 + pathModeBytes.size).order(ByteOrder.LITTLE_ENDIAN)
            sendCmd.put(AdbConstants.SYNC_SEND.toByteArray())
            sendCmd.putInt(pathModeBytes.size)
            sendCmd.put(pathModeBytes)
            writeSyncPayload(io, localId, remoteId, sendCmd.array())

            // 3. 分块发送 DATA
            val chunkSize = (maxPayloadSize - 8).coerceIn(4088, 65536)
            var offset = 0
            while (offset < data.size) {
                val end = minOf(offset + chunkSize, data.size)
                val len = end - offset
                val dataCmd = ByteBuffer.allocate(8 + len).order(ByteOrder.LITTLE_ENDIAN)
                dataCmd.put(AdbConstants.SYNC_DATA.toByteArray())
                dataCmd.putInt(len)
                dataCmd.put(data, offset, len)
                writeSyncPayload(io, localId, remoteId, dataCmd.array())
                offset = end
                onProgress?.invoke(offset, data.size)
            }

            // 4. 发送 DONE
            val doneCmd = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN)
            doneCmd.put(AdbConstants.SYNC_DONE.toByteArray())
            doneCmd.putInt((System.currentTimeMillis() / 1000).toInt())
            writeSyncPayload(io, localId, remoteId, doneCmd.array())

            // 5. 读取 sync 应答
            readSyncResponse(io, localId, remoteId)
        } finally {
            // 6. 关闭 sync 流
            runCatching {
                io.send(command = AdbConstants.COMMAND_CLSE, arg0 = localId, arg1 = remoteId)
            }
        }
        Log.d(TAG, "pushFile done: $remotePath (${data.size} bytes)")
    }

    /**
     * 通过 shell + base64 方式推送文件（兼容不支持 sync 协议的设备）。
     *
     * 将文件分块 base64 编码后，逐块通过 shell 命令写入远程文件。
     *
     * @param data 文件原始字节数据
     * @param remotePath 远程目标路径
     * @param mode POSIX 文件权限模式（默认 0755）
     * @param onProgress 进度回调 (已发送字节, 总字节)
     */
    suspend fun pushFileViaShell(
        data: ByteArray,
        remotePath: String,
        mode: Int = 493,
        onProgress: ((sent: Int, total: Int) -> Unit)? = null
    ): Unit = withContext(Dispatchers.IO) {
        // 动态计算安全块大小，确保 shell OPEN payload 永不超过协商的 maxPayloadSize。
        // 预留固定命令开销和保护余量，剩余预算全部留给 base64 字符串。
        val cmdFixed = "shell:printf '%s' '' | base64 -d >> ".toByteArray(Charsets.UTF_8).size +
            remotePath.toByteArray(Charsets.UTF_8).size
        val payloadSafetyMargin = 512
        val payloadBudget = (maxPayloadSize - cmdFixed - payloadSafetyMargin).coerceAtLeast(4)
        // base64 长度必须是 4 的倍数；raw 长度按 4:3 反推，至少 3 字节避免死循环。
        val safeB64Chars = (payloadBudget / 4) * 4
        val rawChunkSize = ((safeB64Chars / 4) * 3).coerceAtLeast(3)

        var offset = 0
        var first = true
        while (offset < data.size) {
            val end = minOf(offset + rawChunkSize, data.size)
            val chunk = data.copyOfRange(offset, end)
            val b64 = Base64.encodeToString(chunk, Base64.NO_WRAP)

            val redirect = if (first) ">" else ">>"
            // 使用 printf 避免 echo 对转义字符的解读
            val cmd = "printf '%s' '$b64' | base64 -d $redirect $remotePath"
            executeShellCommand(cmd)

            offset = end
            first = false
            onProgress?.invoke(offset, data.size)
        }

        // 设置文件权限
        val octalMode = String.format("%o", mode)
        executeShellCommand("chmod $octalMode $remotePath")

        Log.d(TAG, "pushFileViaShell done: $remotePath (${data.size} bytes)")
    }

    /**
     * 关闭连接。
     *
     * @return Unit
     */
    fun close() {
        try {
            packetIO = null
            socket?.close()
        } catch (_: IOException) {
        } finally {
            socket = null
        }
    }

    // ========== Sync 辅助方法 ==========

    /**
     * 等待 ADB OKAY 应答并返回 remoteId。
     */
    private fun waitForOkay(io: AdbPacketIO, localId: Int): Int {
        while (true) {
            val msg = io.read()
            when (msg.command) {
                AdbConstants.COMMAND_OKAY -> {
                    if (msg.arg1 == localId) return msg.arg0
                }
                AdbConstants.COMMAND_CLSE -> {
                    if (msg.arg1 == localId || msg.arg1 == 0) {
                        throw IOException("Stream rejected by device")
                    }
                    // 忽略不属于当前流的 CLSE
                }
                AdbConstants.COMMAND_AUTH -> respondToAuth(io, msg, allowPublicKey = false)
                else -> { /* 跳过不相关的消息 */ }
            }
        }
    }

    /**
     * 通过 WRTE 发送 sync 子协议数据并等待传输层 OKAY。
     */
    private fun writeSyncPayload(io: AdbPacketIO, localId: Int, remoteId: Int, payload: ByteArray) {
        io.send(command = AdbConstants.COMMAND_WRTE, arg0 = localId, arg1 = remoteId, payload = payload)
        while (true) {
            val msg = io.read()
            when (msg.command) {
                AdbConstants.COMMAND_OKAY -> {
                    if (msg.arg1 == localId) return
                }
                AdbConstants.COMMAND_CLSE -> throw IOException("Sync stream closed unexpectedly")
                else -> { /* 跳过 */ }
            }
        }
    }

    /**
     * 读取 sync 子协议应答（OKAY 或 FAIL）。
     */
    private fun readSyncResponse(io: AdbPacketIO, localId: Int, remoteId: Int) {
        while (true) {
            val msg = io.read()
            when (msg.command) {
                AdbConstants.COMMAND_WRTE -> {
                    if (msg.arg1 == localId && msg.payload.size >= 4) {
                        // 发送传输层 OKAY 确认收到 WRTE
                        io.send(command = AdbConstants.COMMAND_OKAY, arg0 = localId, arg1 = remoteId)
                        val resp = String(msg.payload, 0, 4, Charsets.UTF_8)
                        if (resp == AdbConstants.SYNC_OKAY) return
                        if (resp == AdbConstants.SYNC_FAIL) {
                            val errLen = if (msg.payload.size >= 8) {
                                ByteBuffer.wrap(msg.payload, 4, 4).order(ByteOrder.LITTLE_ENDIAN).int
                            } else 0
                            val errMsg = if (errLen > 0 && msg.payload.size >= 8 + errLen) {
                                String(msg.payload, 8, errLen, Charsets.UTF_8)
                            } else "unknown error"
                            throw IOException("Sync FAIL: $errMsg")
                        }
                    }
                }
                AdbConstants.COMMAND_OKAY -> { /* 传输层确认，继续等 */ }
                AdbConstants.COMMAND_CLSE -> throw IOException("Sync stream closed before response")
                else -> { /* 跳过 */ }
            }
        }
    }

    private fun performHandshake(io: AdbPacketIO) {
        io.send(
            command = AdbConstants.COMMAND_CNXN,
            arg0 = AdbConstants.DEFAULT_VERSION,
            arg1 = AdbConstants.DEFAULT_MAX_PAYLOAD,
            payload = AdbConstants.DEFAULT_BANNER,
        )
        var publicKeySent = false
        while (true) {
            val message = io.read()
            when (message.command) {
                AdbConstants.COMMAND_AUTH -> {
                    val sentPub = respondToAuth(io, message, allowPublicKey = !publicKeySent)
                    if (sentPub) publicKeySent = true
                }
                AdbConstants.COMMAND_CNXN -> {
                    maxPayloadSize = message.arg1
                    return
                }
                else -> throw IOException("Unexpected command during handshake: ${message.command.toCommandString()}")
            }
        }
    }

    private fun executeShellCommandOnce(command: String, logSafe: String): String {
        val io = packetIO ?: throw IllegalStateException("ADB not connected")
        val localId = localIdCounter.getAndIncrement()
        val serviceString = "shell:$command "
        io.send(
            command = AdbConstants.COMMAND_OPEN,
            arg0 = localId,
            arg1 = 0,
            payload = serviceString.toByteArray(Charsets.UTF_8),
        )

        val output = StringBuilder()
        var closed = false
        while (!closed) {
            val message = io.read()
            when (message.command) {
                AdbConstants.COMMAND_OKAY -> {
                    if (message.arg1 != localId) continue
                }
                AdbConstants.COMMAND_WRTE -> {
                    if (message.arg1 != localId) continue
                    val text = String(message.payload, Charsets.UTF_8)
                    output.append(text)
                    io.send(
                        command = AdbConstants.COMMAND_OKAY,
                        arg0 = localId,
                        arg1 = message.arg0,
                    )
                }
                AdbConstants.COMMAND_CLSE -> {
                    if (message.arg1 != localId) continue
                    io.send(
                        command = AdbConstants.COMMAND_CLSE,
                        arg0 = localId,
                        arg1 = message.arg0,
                    )
                    closed = true
                }
                AdbConstants.COMMAND_AUTH -> respondToAuth(io, message, allowPublicKey = false)
                else -> {
                    Log.e(TAG, "adb_shell unexpected_command cmd=${message.command.toCommandString()}")
                    throw IOException("Unexpected command during shell exec: ${message.command.toCommandString()}")
                }
            }
        }
        Log.d(TAG, "adb_shell cmd=\"${logSafe.take(80)}\" bytes=${output.length}")
        return output.toString()
    }

    private fun respondToAuth(io: AdbPacketIO, message: AdbMessage, allowPublicKey: Boolean): Boolean {
        if (message.arg0 != AdbConstants.AUTH_TOKEN) return false
        val signature = keyStore.signToken(message.payload)
        io.send(
            command = AdbConstants.COMMAND_AUTH,
            arg0 = AdbConstants.AUTH_SIGNATURE,
            arg1 = 0,
            payload = signature,
        )
        if (allowPublicKey) {
            io.send(
                command = AdbConstants.COMMAND_AUTH,
                arg0 = AdbConstants.AUTH_RSAPUBLICKEY,
                arg1 = 0,
                payload = keyStore.publicKeyPayload(),
            )
            return true
        }
        return false
    }

    private companion object {
        private const val CONNECT_TIMEOUT_MS = 5_000
        private const val TAG = "AdbClient"
    }
}
