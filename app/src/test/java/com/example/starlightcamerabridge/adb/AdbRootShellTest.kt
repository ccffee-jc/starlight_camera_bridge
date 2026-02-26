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
    fun `wrapCommandWithPassword injects password and escapes quotes`() {
        val result = AdbRootShell.wrapCommandWithPassword("echo 'hi'", true, "pw123")
        assertEquals("su -p pw123 -c 'echo '\''hi'\'''", result.raw)
        assertEquals("su -p *** -c 'echo '\''hi'\'''", result.logSafe)
    }
}
