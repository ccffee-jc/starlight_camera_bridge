package com.example.starlightcamerabridge.adb

import org.junit.Assert.assertEquals
import org.junit.Test

class AdbRootShellTest {

    @Test
    fun `wrapCommandWithPassword returns raw when root disabled`() {
        val result = AdbRootShell.wrapCommandWithPassword("id", false, "secret")
        assertEquals("id", result.raw)
        assertEquals("id", result.logSafe)
    }

    @Test
    fun `wrapCommandWithPassword returns raw when password blank`() {
        val result = AdbRootShell.wrapCommandWithPassword("id", true, "")
        assertEquals("id", result.raw)
        assertEquals("id", result.logSafe)
    }

    @Test
    fun `wrapCommandWithPassword probes adb root then falls back to su`() {
        val result = AdbRootShell.wrapCommandWithPassword("echo 'hi'", true, "pw123")
        assertEquals(
            "if [ \"\$(id -u 2>/dev/null)\" = \"0\" ]; then sh -c 'echo '\''hi'\'''; else su -p 'pw123' 0 sh -c 'echo '\''hi'\'''; fi",
            result.raw
        )
        assertEquals(
            "if [ \"\$(id -u 2>/dev/null)\" = \"0\" ]; then sh -c 'echo '\''hi'\'''; else su -p '***' 0 sh -c 'echo '\''hi'\'''; fi",
            result.logSafe
        )
    }
}
