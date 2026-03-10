package com.example.starlightcamerabridge.adb

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AdbRootPasswordPreferencesTest {

    @Test
    fun `prefers device protected root password when available`() {
        assertEquals("new_pwd", AdbRootPasswordPreferences.resolvePassword("new_pwd", "old_pwd"))
    }

    @Test
    fun `falls back to default root password when both stores empty`() {
        assertEquals("sgmw**HK_305", AdbRootPasswordPreferences.resolvePassword(null, null))
    }

    @Test
    fun `migrates root password only when device protected missing`() {
        assertTrue(AdbRootPasswordPreferences.shouldMigrateLegacyValue(deviceProtectedHasValue = false, legacyHasValue = true))
        assertFalse(AdbRootPasswordPreferences.shouldMigrateLegacyValue(deviceProtectedHasValue = true, legacyHasValue = true))
    }
}
