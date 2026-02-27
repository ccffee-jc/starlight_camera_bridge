package com.example.starlightcamerabridge

import org.junit.Assert.assertFalse
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class FridaDeployerPolicyTest {

    @Test
    fun shouldSkipDuplicateInjection_returnsTrueWhenInsideWindow() {
        val now = 2_000L
        val lastInject = now - 500L

        assertTrue(shouldSkipDuplicateInjection(lastInject, now))
    }

    @Test
    fun shouldSkipDuplicateInjection_returnsFalseWhenWindowExpired() {
        val now = DUPLICATE_INJECT_SKIP_WINDOW_MS + 2_000L
        val lastInject = 1_000L

        assertFalse(shouldSkipDuplicateInjection(lastInject, now))
    }

    @Test
    fun shouldRestartInnerAvmProcess_requiresPidUnchanged() {
        assertFalse(shouldRestartInnerAvmProcess(previousPid = null, currentPid = "123"))
        assertFalse(shouldRestartInnerAvmProcess(previousPid = "100", currentPid = null))
        assertFalse(shouldRestartInnerAvmProcess(previousPid = "100", currentPid = "200"))
        assertTrue(shouldRestartInnerAvmProcess(previousPid = "100", currentPid = "100"))
    }

    @Test
    fun decideDuplicateInjection_shouldForceWhenSocketMissingInsideWindow() {
        val decision = decideDuplicateInjection(
            lastInjectAtMs = 1_000L,
            nowMs = 10_000L,
            bridgeSocketReady = false,
            lastInjectPid = "200",
            currentPid = "200"
        )

        assertFalse(decision.shouldSkip)
        assertEquals("socket_missing", decision.reason)
    }

    @Test
    fun decideDuplicateInjection_shouldForceWhenPidChangedInsideWindow() {
        val decision = decideDuplicateInjection(
            lastInjectAtMs = 1_000L,
            nowMs = 10_000L,
            bridgeSocketReady = false,
            lastInjectPid = "100",
            currentPid = "200"
        )

        assertFalse(decision.shouldSkip)
        assertEquals("pid_changed", decision.reason)
    }

    @Test
    fun decideDuplicateInjection_shouldSkipOnlyWhenSocketReadyInsideWindow() {
        val decision = decideDuplicateInjection(
            lastInjectAtMs = 1_000L,
            nowMs = 10_000L,
            bridgeSocketReady = true,
            lastInjectPid = "100",
            currentPid = "100"
        )

        assertTrue(decision.shouldSkip)
        assertEquals("socket_ready", decision.reason)
    }
}
