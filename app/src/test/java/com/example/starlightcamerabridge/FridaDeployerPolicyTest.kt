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

    @Test
    fun parseProcessKillObservation_parsesMarkers() {
        val observation = parseProcessKillObservation(
            """
            __KILL_RC__:0
            __KILL_PID__:1234
            """.trimIndent()
        )

        assertEquals(0, observation.killExitCode)
        assertEquals("1234", observation.pidAfterKill)
        assertFalse(observation.passwordRejected)
        assertFalse(observation.markerMissing)
    }

    @Test
    fun parseProcessKillObservation_detectsPasswordFailureWhenMarkersMissing() {
        val observation = parseProcessKillObservation("The Password is incorrect")

        assertEquals(null, observation.killExitCode)
        assertEquals(null, observation.pidAfterKill)
        assertTrue(observation.passwordRejected)
        assertTrue(observation.markerMissing)
    }

    @Test
    fun diagnoseTargetProcessMissing_detectsPermissionIssue() {
        val diagnosis = diagnoseTargetProcessMissing(
            targetProcess = "avm3d_service",
            pidofOutput = "su: permission denied",
            exactProcessOutput = "",
            processSnapshot = ""
        )

        assertEquals("permission", diagnosis.reason)
    }

    @Test
    fun diagnoseTargetProcessMissing_detectsPidofMiss() {
        val diagnosis = diagnoseTargetProcessMissing(
            targetProcess = "avm3d_service",
            pidofOutput = "",
            exactProcessOutput = "root      3456  1  avm3d_service",
            processSnapshot = ""
        )

        assertEquals("pidof_miss", diagnosis.reason)
    }

    @Test
    fun diagnoseTargetProcessMissing_detectsNameMismatch() {
        val diagnosis = diagnoseTargetProcessMissing(
            targetProcess = "avm3d_service",
            pidofOutput = "",
            exactProcessOutput = "",
            processSnapshot = "u0_a123    3456  1000  com.desaysv.inneravmservice"
        )

        assertEquals("name_mismatch", diagnosis.reason)
    }

    @Test
    fun diagnoseTargetProcessMissing_defaultsToNotRunning() {
        val diagnosis = diagnoseTargetProcessMissing(
            targetProcess = "avm3d_service",
            pidofOutput = "",
            exactProcessOutput = "",
            processSnapshot = ""
        )

        assertEquals("not_running", diagnosis.reason)
    }

    @Test
    fun parsePidFromPsLine_extractsPidWhenExactProcessExists() {
        val output = """
            root      1234  100  avm3d_service
            u0_a100   2233  200  com.other.app
        """.trimIndent()

        assertEquals("1234", parsePidFromPsLine(output, "avm3d_service"))
    }

    @Test
    fun parseShellProbeResult_extractsExitCodeMarker() {
        val result = parseShellProbeResult(
            """
            line1
            line2
            __HA_RC__:7
            """.trimIndent()
        )

        assertEquals("line1\nline2", result.output)
        assertEquals(7, result.exitCode)
        assertFalse(result.markerMissing)
    }
}
