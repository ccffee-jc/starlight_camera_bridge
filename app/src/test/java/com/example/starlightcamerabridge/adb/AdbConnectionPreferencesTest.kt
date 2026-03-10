package com.example.starlightcamerabridge.adb

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AdbConnectionPreferencesTest {

    @Test
    fun `prefers device protected bridge connection values when available`() {
        assertEquals("192.168.1.10", AdbConnectionPreferences.resolveHost("192.168.1.10", "127.0.0.1"))
        assertEquals(5566, AdbConnectionPreferences.resolvePort(5566, 5557))
    }

    @Test
    fun `falls back to defaults for invalid bridge connection values`() {
        assertEquals(AdbConnectionPreferences.resolveHost(null, null), "127.0.0.1")
        assertEquals(5557, AdbConnectionPreferences.resolvePort(70000, null))
    }

    @Test
    fun `migrates bridge connection only when device protected missing`() {
        assertTrue(AdbConnectionPreferences.shouldMigrateLegacyValue(deviceProtectedHasValue = false, legacyHasValue = true))
        assertFalse(AdbConnectionPreferences.shouldMigrateLegacyValue(deviceProtectedHasValue = true, legacyHasValue = true))
    }
}
