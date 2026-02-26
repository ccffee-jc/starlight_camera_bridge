package com.example.starlightcamerabridge.adb

import java.nio.ByteBuffer
import java.nio.ByteOrder

internal data class AdbMessage(
    val command: Int,
    val arg0: Int,
    val arg1: Int,
    val payloadLength: Int,
    val checksum: Int,
    val magic: Int,
    val payload: ByteArray
) {
    fun toByteArray(): ByteArray {
        val buffer = ByteBuffer.allocate(24).order(ByteOrder.LITTLE_ENDIAN)
        buffer.putInt(command)
        buffer.putInt(arg0)
        buffer.putInt(arg1)
        buffer.putInt(payloadLength)
        buffer.putInt(checksum)
        buffer.putInt(magic)
        return buffer.array()
    }

    companion object {
        fun fromByteArray(bytes: ByteArray): AdbMessage {
            val buffer = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
            val command = buffer.int
            val arg0 = buffer.int
            val arg1 = buffer.int
            val payloadLength = buffer.int
            val checksum = buffer.int
            val magic = buffer.int
            return AdbMessage(command, arg0, arg1, payloadLength, checksum, magic, ByteArray(0))
        }
    }
}

internal fun Int.toCommandString(): String {
    val bytes = ByteArray(4)
    bytes[0] = (this and 0xFF).toByte()
    bytes[1] = (this shr 8 and 0xFF).toByte()
    bytes[2] = (this shr 16 and 0xFF).toByte()
    bytes[3] = (this shr 24 and 0xFF).toByte()
    return String(bytes)
}

internal fun ByteArray.byteSum(): Int {
    var sum = 0
    for (b in this) {
        sum += if (b < 0) b + 0x100 else b.toInt()
    }
    return sum
}
