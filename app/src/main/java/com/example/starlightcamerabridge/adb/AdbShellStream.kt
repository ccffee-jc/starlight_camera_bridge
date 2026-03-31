package com.example.starlightcamerabridge.adb

import java.io.IOException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * ADB shell 长连接读取器，用于托管长生命周期命令。
 */
class AdbShellStream internal constructor(
    private val io: AdbPacketIO,
    private val client: AdbClient,
    private val localId: Int,
    remoteId: Int,
    private val initialChunks: List<String>,
) {
    @Volatile
    private var remoteId: Int = remoteId
    @Volatile
    private var closed: Boolean = false

    suspend fun readLoop(onChunk: (String) -> Unit) = withContext(Dispatchers.IO) {
        for (chunk in initialChunks) {
            if (chunk.isNotEmpty()) {
                onChunk(chunk)
            }
        }
        while (!closed) {
            val message = io.read()
            when (message.command) {
                AdbConstants.COMMAND_OKAY -> {
                    if (message.arg1 == localId && remoteId <= 0) {
                        remoteId = message.arg0
                    }
                }
                AdbConstants.COMMAND_WRTE -> {
                    if (message.arg1 != localId) continue
                    val text = String(message.payload, Charsets.UTF_8)
                    if (text.isNotEmpty()) {
                        onChunk(text)
                    }
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
                AdbConstants.COMMAND_AUTH -> client.respondToAuth(io, message, allowPublicKey = false)
                else -> throw IOException("Unexpected command during shell stream: ${message.command.toCommandString()}")
            }
        }
    }

    fun close() {
        if (closed) return
        closed = true
        val remote = remoteId
        if (remote > 0) {
            runCatching {
                io.send(
                    command = AdbConstants.COMMAND_CLSE,
                    arg0 = localId,
                    arg1 = remote,
                )
            }
        }
    }
}
