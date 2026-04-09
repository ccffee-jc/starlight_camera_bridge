package com.example.starlightcamerabridge

import org.junit.Assert.assertFalse
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
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
    fun normalizeBridgeInjectSource_shouldSanitizeAndFallback() {
        assertEquals("ui_action/aa_bb", normalizeBridgeInjectSource(" ui action/aa?bb "))

        val longRaw = "x".repeat(BRIDGE_INJECT_SOURCE_MAX_LEN + 5)
        assertEquals(BRIDGE_INJECT_SOURCE_MAX_LEN, normalizeBridgeInjectSource(longRaw).length)

        assertEquals("fallback", normalizeBridgeInjectSource("!!!", fallback = "fallback"))
    }

    @Test
    fun shouldRestartInnerAvmProcess_requiresPidUnchanged() {
        assertFalse(shouldRestartInnerAvmProcess(previousPid = null, currentPid = "123"))
        assertFalse(shouldRestartInnerAvmProcess(previousPid = "100", currentPid = null))
        assertFalse(shouldRestartInnerAvmProcess(previousPid = "100", currentPid = "200"))
        assertTrue(shouldRestartInnerAvmProcess(previousPid = "100", currentPid = "100"))
    }

    @Test
    fun buildInjectedProcessCleanupOrder_killsTargetBeforeFridaProcesses() {
        val order = buildInjectedProcessCleanupOrder("avm3d_service")

        assertEquals(listOf("avm3d_service", "frida-inject", "frida-server"), order.map { it.processName })
        assertEquals("目标进程 avm3d_service", order.first().displayName)
    }

    @Test
    fun buildManagedInjectSessionCleanupOrder_keepsServerOutOfSessionRecovery() {
        val order = buildManagedInjectSessionCleanupOrder("avm3d_service")

        assertEquals(listOf("avm3d_service", "frida-inject"), order.map { it.processName })
    }

    @Test
    fun shouldReuseBundledFridaBinary_requiresMatchingBundleVersion() {
        assertTrue(
            shouldReuseBundledFridaBinary(
                remoteExists = true,
                remoteBundleVersion = BUNDLED_FRIDA_BINARY_VERSION
            )
        )
        assertFalse(
            shouldReuseBundledFridaBinary(
                remoteExists = true,
                remoteBundleVersion = "17.4.0-android-arm64"
            )
        )
        assertFalse(
            shouldReuseBundledFridaBinary(
                remoteExists = false,
                remoteBundleVersion = BUNDLED_FRIDA_BINARY_VERSION
            )
        )
    }

    @Test
    fun decideInjectEntry_skipsReadySocketOnlyWhenNotStrict() {
        val decision = decideInjectEntry(
            strictRestart = false,
            bridgeReady = true
        )

        assertTrue(decision.shouldSkipBecauseSocketReady)
        assertFalse(decision.shouldBypassDuplicateWindow)
    }

    @Test
    fun decideInjectEntry_bypassesShortCircuitWhenStrictRestartEnabled() {
        val decision = decideInjectEntry(
            strictRestart = true,
            bridgeReady = true
        )

        assertFalse(decision.shouldSkipBecauseSocketReady)
        assertTrue(decision.shouldBypassDuplicateWindow)
    }

    @Test
    fun decideDuplicateInjection_shouldForceWhenSocketMissingInsideWindow() {
        val decision = decideDuplicateInjection(
            lastInjectAtMs = 1_000L,
            nowMs = 10_000L,
            bridgeSocketReady = false,
            bridgeProtocolReady = false,
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
            bridgeProtocolReady = false,
            lastInjectPid = "100",
            currentPid = "200"
        )

        assertFalse(decision.shouldSkip)
        assertEquals("pid_changed", decision.reason)
    }

    @Test
    fun decideDuplicateInjection_shouldSkipOnlyWhenBridgeReadyInsideWindow() {
        val decision = decideDuplicateInjection(
            lastInjectAtMs = 1_000L,
            nowMs = 10_000L,
            bridgeSocketReady = true,
            bridgeProtocolReady = true,
            lastInjectPid = "100",
            currentPid = "100"
        )

        assertTrue(decision.shouldSkip)
        assertEquals("bridge_ready", decision.reason)
    }

    @Test
    fun decideDuplicateInjection_shouldForceWhenProtocolNotReadyInsideWindow() {
        val decision = decideDuplicateInjection(
            lastInjectAtMs = 1_000L,
            nowMs = 10_000L,
            bridgeSocketReady = true,
            bridgeProtocolReady = false,
            lastInjectPid = "100",
            currentPid = "100"
        )

        assertFalse(decision.shouldSkip)
        assertEquals("proto_not_ready", decision.reason)
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

    @Test
    fun parseBridgeReadinessState_extractsProtocolReady() {
        val state = parseBridgeReadinessState(
            """
            __BRIDGE_SOCKET__:1
            __BRIDGE_PROTO__:1
            """.trimIndent()
        )

        assertTrue(state.socketReady)
        assertTrue(state.protocolReady)
        assertTrue(state.ready)
    }

    @Test
    fun parseBridgeReadinessState_extractsSocketAndProtocolFlags() {
        val state = parseBridgeReadinessState(
            """
            __BRIDGE_SOCKET__:1
            __BRIDGE_PROTO__:0
            """.trimIndent()
        )

        assertTrue(state.socketReady)
        assertFalse(state.protocolReady)
        assertFalse(state.ready)
    }

    @Test
    fun assessFridaInjectResult_allowsPositiveLogWithoutExitMarker() {
        val result = assessFridaInjectResult(
            rawOutput = "[?] shell channel closed early",
            injectLog = """
                [?] memfd NF ready
                [?] stealth_camera_v3 loaded. Waiting for camera activation...
            """.trimIndent()
        )

        assertNull(result.exitCode)
        assertTrue(result.markerMissing)
        assertTrue(result.positiveSignalDetected)
        assertFalse(result.fatalSignalDetected)
        assertTrue(result.canProceedToActivation)
    }

    @Test
    fun parseManagedFridaLaunchObservation_parsesBackgroundMarkers() {
        val observation = parseManagedFridaLaunchObservation(
            """
            __BG_PID__:12345
            __BG_ALIVE__:1
            """.trimIndent()
        )

        assertEquals("12345", observation.backgroundPid)
        assertTrue(observation.processAlive)
        assertFalse(observation.markerMissing)
    }

    @Test
    fun extractLatestLogWindow_returnsContentAfterLastMarker() {
        val marker = "==== frida-inject start ts=2 pid=200 mode=managed ===="
        val window = extractLatestLogWindow(
            logText = """
                ==== frida-inject start ts=1 pid=100 mode=managed ====
                old
                $marker
                new
                lines
            """.trimIndent(),
            startMarker = marker
        )

        assertEquals("$marker\nnew\nlines", window)
    }

    @Test
    fun collectProtectedProcessFridaResidues_parsesDistinctEntries() {
        val residues = collectProtectedProcessFridaResidues(
            """
            zygote_secondary:21488:maps
            zygote_secondary:21488:threads
            zygote_secondary:21488:threads
            system_server:16341:maps
            """.trimIndent()
        )

        assertEquals(3, residues.size)
        assertEquals("zygote_secondary", residues[0].processName)
        assertEquals("21488", residues[0].pid)
        assertEquals("maps", residues[0].evidence)
        assertEquals("threads", residues[1].evidence)
        assertEquals("system_server", residues[2].processName)
    }

    @Test
    fun collectProtectedProcessFridaResidues_ignoresShellSyntaxNoise() {
        val residues = collectProtectedProcessFridaResidues(
            """
            /system/bin/sh: syntax error: unexpected '('
            system_server:16341:maps
            zygote_secondary:syntax error:threads
            random_process:123:maps
            """.trimIndent()
        )

        assertEquals(1, residues.size)
        assertEquals("system_server", residues[0].processName)
        assertEquals("16341", residues[0].pid)
        assertEquals("maps", residues[0].evidence)
    }

    @Test
    fun assessFridaInjectResult_rejectsFatalInjectLog() {
        val result = assessFridaInjectResult(
            rawOutput = "__RC:1",
            injectLog = "Failed to inject: permission denied"
        )

        assertEquals(1, result.exitCode)
        assertFalse(result.markerMissing)
        assertFalse(result.positiveSignalDetected)
        assertTrue(result.fatalSignalDetected)
        assertFalse(result.canProceedToActivation)
    }

    @Test
    fun normalizeBridgeTargetFps_shouldClampAndFallback() {
        assertEquals(DEFAULT_BRIDGE_TARGET_FPS, normalizeBridgeTargetFps(Double.NaN), 0.0)
        assertEquals(5.0, normalizeBridgeTargetFps(1.0), 0.0)
        assertEquals(30.0, normalizeBridgeTargetFps(60.0), 0.0)
        assertEquals(12.5, normalizeBridgeTargetFps(12.5), 0.0)
    }

    @Test
    fun computeBridgeFrameIntervalMs_shouldUseCeiling() {
        assertEquals(100, computeBridgeFrameIntervalMs(10.0))
        assertEquals(42, computeBridgeFrameIntervalMs(24.0))
        assertEquals(67, computeBridgeFrameIntervalMs(15.0))
    }

    @Test
    fun renderHookScriptTemplate_shouldReplaceTargetFpsAndInterval() {
        val rendered = renderHookScriptTemplate(
            """
            var targetFps = __TARGET_FPS__, minIntervalMs = __MIN_INTERVAL_MS__;
            var backgroundBypassCopy = __BACKGROUND_BYPASS_COPY__;
            var backgroundBypassRender = __BACKGROUND_BYPASS_RENDER__;
            var backgroundForceRenderLoop = __BACKGROUND_FORCE_RENDER_LOOP__;
            var recoverFrameCount = __RECOVER_FRAME_COUNT__;
            """.trimIndent(),
            HookScriptRuntimeConfig(
                targetFps = 12.5,
                backgroundBypassCopy = true,
                backgroundBypassRender = false,
                backgroundForceRenderLoop = true,
                recoverFrameCount = 5
            )
        )

        assertEquals(
            """
            var targetFps = 12.5, minIntervalMs = 80;
            var backgroundBypassCopy = true;
            var backgroundBypassRender = false;
            var backgroundForceRenderLoop = true;
            var recoverFrameCount = 5;
            """.trimIndent(),
            rendered
        )
    }

    @Test
    fun renderHookScriptTemplate_shouldFailWhenPlaceholderMissing() {
        try {
            renderHookScriptTemplate(
                "var targetFps = __TARGET_FPS__;",
                HookScriptRuntimeConfig(targetFps = 10.0)
            )
            fail("expected placeholder validation failure")
        } catch (expected: IllegalArgumentException) {
            assertTrue(expected.message?.contains("__MIN_INTERVAL_MS__") == true)
        }
    }

    @Test
    fun renderHookScriptTemplate_shouldClampRecoverFrameCountToZero() {
        val rendered = renderHookScriptTemplate(
            """
            __TARGET_FPS__
            __MIN_INTERVAL_MS__
            __BACKGROUND_BYPASS_COPY__
            __BACKGROUND_BYPASS_RENDER__
            __BACKGROUND_FORCE_RENDER_LOOP__
            __RECOVER_FRAME_COUNT__
            """.trimIndent(),
            HookScriptRuntimeConfig(
                targetFps = 10.0,
                recoverFrameCount = -3
            )
        )

        assertTrue(rendered.endsWith("0"))
    }
}
