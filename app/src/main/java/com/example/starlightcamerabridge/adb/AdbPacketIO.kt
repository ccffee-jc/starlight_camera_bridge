package com.example.starlightcamerabridge.adb

import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder

internal class AdbPacketIO(
    private val input: InputStream,
    private val output: OutputStream
) {
    /**
     * 发送 ADB 协议包。
     *
     * @param command ADB 命令字
     * @param arg0 命令参数 0
     * @param arg1 命令参数 1
     * @param payload 数据载荷
     * @return Unit
     */
    fun send(command: Int, arg0: Int, arg1: Int, payload: ByteArray = ByteArray(0)) {
        val checksum = payload.byteSum()
        val header = ByteBuffer.allocate(24).order(ByteOrder.LITTLE_ENDIAN)
        header.putInt(command)
        header.putInt(arg0)
        header.putInt(arg1)
        header.putInt(payload.size)
        header.putInt(checksum)
        header.putInt(command.inv())
        output.write(header.array())
        if (payload.isNotEmpty()) {
            output.write(payload)
        }
        output.flush()
    }

    /**
     * 读取并解析 ADB 协议包。
     *
     * @return 解析后的 ADB 消息
     */
    fun read(): AdbMessage {
        val header = readFully(24)
        val headerBuffer = ByteBuffer.wrap(header).order(ByteOrder.LITTLE_ENDIAN)
        val command = headerBuffer.int
        val arg0 = headerBuffer.int
        val arg1 = headerBuffer.int
        val payloadLength = headerBuffer.int
        val checksum = headerBuffer.int
        val magic = headerBuffer.int
        val payload = if (payloadLength > 0) readFully(payloadLength) else ByteArray(0)
        if (payload.byteSum() != checksum) {
            throw IOException("Checksum mismatch for command=${command.toCommandString()}")
        }
        return AdbMessage(command, arg0, arg1, payloadLength, checksum, magic, payload)
    }

    private fun readFully(length: Int): ByteArray {
        val buffer = ByteArray(length)
        var offset = 0
        while (offset < length) {
            val read = input.read(buffer, offset, length - offset)
            if (read <= 0) throw IOException("Stream closed while reading")
            offset += read
        }
        return buffer
    }
}
