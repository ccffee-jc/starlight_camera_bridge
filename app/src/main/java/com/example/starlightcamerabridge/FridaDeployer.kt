package com.example.starlightcamerabridge

import android.content.Context
import android.util.Log
import com.example.starlightcamerabridge.adb.AdbClient
import com.example.starlightcamerabridge.adb.AdbRootShell
import com.example.starlightcamerabridge.adb.AdbShellStream
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.tukaani.xz.XZInputStream
import java.io.File
import java.io.IOException
import java.text.DecimalFormat
import java.text.DecimalFormatSymbols
import java.util.Locale
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.math.ceil

/**
 * 重复注入跳过窗口（毫秒）。
 * 距离上次成功注入在此窗口内的新注入请求将被直接跳过。
 */
internal const val DUPLICATE_INJECT_SKIP_WINDOW_MS = 60000L
internal const val DEFAULT_BRIDGE_TARGET_FPS = 15.0
internal const val BUNDLED_FRIDA_BINARY_VERSION =
    "frida-server-17.6.2_frida-inject-17.4.0_android-arm64_disable-preload"
private const val MIN_BRIDGE_TARGET_FPS = 5.0
private const val MAX_BRIDGE_TARGET_FPS = 30.0
private const val HOOK_SCRIPT_TARGET_FPS_PLACEHOLDER = "__TARGET_FPS__"
private const val HOOK_SCRIPT_MIN_INTERVAL_MS_PLACEHOLDER = "__MIN_INTERVAL_MS__"
private const val HOOK_SCRIPT_BACKGROUND_BYPASS_COPY_PLACEHOLDER = "__BACKGROUND_BYPASS_COPY__"
private const val HOOK_SCRIPT_BACKGROUND_BYPASS_RENDER_PLACEHOLDER = "__BACKGROUND_BYPASS_RENDER__"
private const val HOOK_SCRIPT_BACKGROUND_FORCE_RENDER_LOOP_PLACEHOLDER = "__BACKGROUND_FORCE_RENDER_LOOP__"
private const val HOOK_SCRIPT_RECOVER_FRAME_COUNT_PLACEHOLDER = "__RECOVER_FRAME_COUNT__"
private const val DEFAULT_BACKGROUND_RECOVER_FRAME_COUNT = 3

internal data class HookScriptRuntimeConfig(
    val targetFps: Double,
    val backgroundBypassCopy: Boolean = true,
    val backgroundBypassRender: Boolean = true,
    val backgroundForceRenderLoop: Boolean = false,
    val recoverFrameCount: Int = DEFAULT_BACKGROUND_RECOVER_FRAME_COUNT
)

private val HOOK_TARGET_FPS_FORMAT = DecimalFormat(
    "0.##",
    DecimalFormatSymbols(Locale.US)
)

internal fun normalizeBridgeTargetFps(targetFps: Double): Double {
    if (!targetFps.isFinite()) return DEFAULT_BRIDGE_TARGET_FPS
    return targetFps.coerceIn(MIN_BRIDGE_TARGET_FPS, MAX_BRIDGE_TARGET_FPS)
}

internal fun computeBridgeFrameIntervalMs(targetFps: Double): Int {
    val normalizedTargetFps = normalizeBridgeTargetFps(targetFps)
    return maxOf(ceil(1000.0 / normalizedTargetFps).toInt(), 1)
}

internal fun formatBridgeTargetFps(targetFps: Double): String {
    return HOOK_TARGET_FPS_FORMAT.format(normalizeBridgeTargetFps(targetFps))
}

internal fun renderHookScriptTemplate(template: String, targetFps: Double): String {
    return renderHookScriptTemplate(
        template = template,
        config = HookScriptRuntimeConfig(targetFps = targetFps)
    )
}

internal fun renderHookScriptTemplate(template: String, config: HookScriptRuntimeConfig): String {
    require(template.contains(HOOK_SCRIPT_TARGET_FPS_PLACEHOLDER)) {
        "hook 脚本模板缺少 $HOOK_SCRIPT_TARGET_FPS_PLACEHOLDER"
    }
    require(template.contains(HOOK_SCRIPT_MIN_INTERVAL_MS_PLACEHOLDER)) {
        "hook 脚本模板缺少 $HOOK_SCRIPT_MIN_INTERVAL_MS_PLACEHOLDER"
    }
    require(template.contains(HOOK_SCRIPT_BACKGROUND_BYPASS_COPY_PLACEHOLDER)) {
        "hook 脚本模板缺少 $HOOK_SCRIPT_BACKGROUND_BYPASS_COPY_PLACEHOLDER"
    }
    require(template.contains(HOOK_SCRIPT_BACKGROUND_BYPASS_RENDER_PLACEHOLDER)) {
        "hook 脚本模板缺少 $HOOK_SCRIPT_BACKGROUND_BYPASS_RENDER_PLACEHOLDER"
    }
    require(template.contains(HOOK_SCRIPT_BACKGROUND_FORCE_RENDER_LOOP_PLACEHOLDER)) {
        "hook 脚本模板缺少 $HOOK_SCRIPT_BACKGROUND_FORCE_RENDER_LOOP_PLACEHOLDER"
    }
    require(template.contains(HOOK_SCRIPT_RECOVER_FRAME_COUNT_PLACEHOLDER)) {
        "hook 脚本模板缺少 $HOOK_SCRIPT_RECOVER_FRAME_COUNT_PLACEHOLDER"
    }
    val normalizedTargetFps = normalizeBridgeTargetFps(config.targetFps)
    val normalizedRecoverFrameCount = config.recoverFrameCount.coerceAtLeast(0)
    val rendered = template
        .replace(HOOK_SCRIPT_TARGET_FPS_PLACEHOLDER, formatBridgeTargetFps(normalizedTargetFps))
        .replace(
            HOOK_SCRIPT_MIN_INTERVAL_MS_PLACEHOLDER,
            computeBridgeFrameIntervalMs(normalizedTargetFps).toString()
        )
        .replace(HOOK_SCRIPT_BACKGROUND_BYPASS_COPY_PLACEHOLDER, config.backgroundBypassCopy.toString())
        .replace(HOOK_SCRIPT_BACKGROUND_BYPASS_RENDER_PLACEHOLDER, config.backgroundBypassRender.toString())
        .replace(
            HOOK_SCRIPT_BACKGROUND_FORCE_RENDER_LOOP_PLACEHOLDER,
            config.backgroundForceRenderLoop.toString()
        )
        .replace(HOOK_SCRIPT_RECOVER_FRAME_COUNT_PLACEHOLDER, normalizedRecoverFrameCount.toString())
    check(!rendered.contains(HOOK_SCRIPT_TARGET_FPS_PLACEHOLDER)) {
        "hook 脚本模板中的 $HOOK_SCRIPT_TARGET_FPS_PLACEHOLDER 未替换完成"
    }
    check(!rendered.contains(HOOK_SCRIPT_MIN_INTERVAL_MS_PLACEHOLDER)) {
        "hook 脚本模板中的 $HOOK_SCRIPT_MIN_INTERVAL_MS_PLACEHOLDER 未替换完成"
    }
    check(!rendered.contains(HOOK_SCRIPT_BACKGROUND_BYPASS_COPY_PLACEHOLDER)) {
        "hook 脚本模板中的 $HOOK_SCRIPT_BACKGROUND_BYPASS_COPY_PLACEHOLDER 未替换完成"
    }
    check(!rendered.contains(HOOK_SCRIPT_BACKGROUND_BYPASS_RENDER_PLACEHOLDER)) {
        "hook 脚本模板中的 $HOOK_SCRIPT_BACKGROUND_BYPASS_RENDER_PLACEHOLDER 未替换完成"
    }
    check(!rendered.contains(HOOK_SCRIPT_BACKGROUND_FORCE_RENDER_LOOP_PLACEHOLDER)) {
        "hook 脚本模板中的 $HOOK_SCRIPT_BACKGROUND_FORCE_RENDER_LOOP_PLACEHOLDER 未替换完成"
    }
    check(!rendered.contains(HOOK_SCRIPT_RECOVER_FRAME_COUNT_PLACEHOLDER)) {
        "hook 脚本模板中的 $HOOK_SCRIPT_RECOVER_FRAME_COUNT_PLACEHOLDER 未替换完成"
    }
    return rendered
}

/**
 * 判断是否应跳过本次重复注入。
 *
 * @param lastInjectAtMs 上次注入时间戳（毫秒），0 表示无记录
 * @param nowMs 当前时间戳（毫秒）
 * @return true = 应跳过
 */
internal fun shouldSkipDuplicateInjection(lastInjectAtMs: Long, nowMs: Long): Boolean {
    if (lastInjectAtMs <= 0) return false
    val elapsed = (nowMs - lastInjectAtMs).coerceAtLeast(0)
    return elapsed < DUPLICATE_INJECT_SKIP_WINDOW_MS
}

internal data class DuplicateInjectDecision(
    val shouldSkip: Boolean,
    val reason: String
)

internal data class BridgeReadinessState(
    val socketReady: Boolean,
    val streamReady: Boolean
) {
    val ready: Boolean
        get() = socketReady && streamReady
}

internal data class InjectEntryDecision(
    val shouldSkipBecauseSocketReady: Boolean,
    val shouldBypassDuplicateWindow: Boolean
)

internal fun decideInjectEntry(
    strictRestart: Boolean,
    bridgeReady: Boolean
): InjectEntryDecision {
    if (bridgeReady && !strictRestart) {
        return InjectEntryDecision(
            shouldSkipBecauseSocketReady = true,
            shouldBypassDuplicateWindow = false
        )
    }
    return InjectEntryDecision(
        shouldSkipBecauseSocketReady = false,
        shouldBypassDuplicateWindow = strictRestart
    )
}

internal fun decideDuplicateInjection(
    lastInjectAtMs: Long,
    nowMs: Long,
    bridgeSocketReady: Boolean,
    bridgeStreamReady: Boolean,
    lastInjectPid: String?,
    currentPid: String
): DuplicateInjectDecision {
    if (!shouldSkipDuplicateInjection(lastInjectAtMs, nowMs)) {
        return DuplicateInjectDecision(
            shouldSkip = false,
            reason = "outside_window"
        )
    }
    if (bridgeSocketReady && bridgeStreamReady) {
        return DuplicateInjectDecision(
            shouldSkip = true,
            reason = "bridge_ready"
        )
    }
    if (bridgeSocketReady) {
        return DuplicateInjectDecision(
            shouldSkip = false,
            reason = "stream_not_ready"
        )
    }
    val lastPid = lastInjectPid?.trim().orEmpty()
    if (lastPid.isNotEmpty() && lastPid != currentPid) {
        return DuplicateInjectDecision(
            shouldSkip = false,
            reason = "pid_changed"
        )
    }
    return DuplicateInjectDecision(
        shouldSkip = false,
        reason = "socket_missing"
    )
}

internal fun parseBridgeReadinessState(rawOutput: String): BridgeReadinessState {
    var socketReady = false
    var streamReady = false
    rawOutput.lineSequence().forEach { rawLine ->
        val line = rawLine.trim()
        when {
            line.startsWith("__BRIDGE_SOCKET__:") ->
                socketReady = line.removePrefix("__BRIDGE_SOCKET__:").trim() == "1"
            line.startsWith("__BRIDGE_STREAM__:") ->
                streamReady = line.removePrefix("__BRIDGE_STREAM__:").trim() == "1"
        }
    }
    return BridgeReadinessState(
        socketReady = socketReady,
        streamReady = streamReady
    )
}

/**
 * 判断 innerAvmService 是否需要被重启。
 *
 * @param previousPid 重启前的 PID
 * @param currentPid 当前 PID
 * @return true = PID 未变化，需要主动重启
 */
internal fun shouldRestartInnerAvmProcess(previousPid: String?, currentPid: String?): Boolean {
    if (previousPid.isNullOrBlank()) return false
    if (currentPid.isNullOrBlank()) return false
    return previousPid == currentPid
}

internal data class CleanupTarget(
    val processName: String,
    val displayName: String
)

internal fun buildManagedInjectSessionCleanupOrder(targetProcess: String): List<CleanupTarget> {
    return listOf(
        CleanupTarget(
            processName = targetProcess,
            displayName = "目标进程 $targetProcess"
        ),
        CleanupTarget(
            processName = "frida-inject",
            displayName = "frida-inject"
        )
    )
}

internal fun buildInjectedProcessCleanupOrder(targetProcess: String): List<CleanupTarget> {
    return buildManagedInjectSessionCleanupOrder(targetProcess) + CleanupTarget(
        processName = "frida-server",
        displayName = "frida-server"
    )
}

internal fun shouldReuseBundledFridaBinary(
    remoteExists: Boolean,
    remoteBundleVersion: String?,
    localBundleVersion: String = BUNDLED_FRIDA_BINARY_VERSION
): Boolean {
    if (!remoteExists) return false
    return remoteBundleVersion?.trim() == localBundleVersion
}

internal data class ProcessKillObservation(
    val killExitCode: Int?,
    val pidAfterKill: String?,
    val passwordRejected: Boolean,
    val markerMissing: Boolean
)

internal fun parseProcessKillObservation(rawOutput: String): ProcessKillObservation {
    val rcPrefix = "__KILL_RC__:"
    val pidPrefix = "__KILL_PID__:"
    val lines = rawOutput.lineSequence().map { it.trim() }.toList()
    val rcRaw = lines.firstOrNull { it.startsWith(rcPrefix) }?.removePrefix(rcPrefix)?.trim()
    val pidRaw = lines.firstOrNull { it.startsWith(pidPrefix) }?.removePrefix(pidPrefix)?.trim()
    return ProcessKillObservation(
        killExitCode = rcRaw?.toIntOrNull(),
        pidAfterKill = pidRaw?.takeIf { it.isNotEmpty() },
        passwordRejected = rawOutput.contains("The Password is incorrect", ignoreCase = true),
        markerMissing = rcRaw == null || pidRaw == null
    )
}

internal data class TargetProcessMissingDiagnosis(
    val reason: String
)

internal data class TargetPidLookup(
    val pid: String?,
    val source: String
)

internal data class ShellProbeResult(
    val output: String,
    val exitCode: Int?,
    val markerMissing: Boolean
)

internal data class FridaInjectAssessment(
    val exitCode: Int?,
    val markerMissing: Boolean,
    val positiveSignalDetected: Boolean,
    val fatalSignalDetected: Boolean,
    val canProceedToActivation: Boolean
)

internal data class ManagedFridaLaunchObservation(
    val backgroundPid: String?,
    val processAlive: Boolean,
    val markerMissing: Boolean
)

internal data class ProtectedProcessFridaResidue(
    val processName: String,
    val pid: String,
    val evidence: String
)

internal fun parseShellProbeResult(rawOutput: String, marker: String = "__HA_RC__:"): ShellProbeResult {
    val lines = rawOutput.lineSequence().toList()
    val markerLine = lines.lastOrNull { it.trim().startsWith(marker) }
    if (markerLine == null) {
        return ShellProbeResult(
            output = rawOutput.trim(),
            exitCode = null,
            markerMissing = true
        )
    }
    val exitCode = markerLine.trim().removePrefix(marker).trim().toIntOrNull()
    val outputLines = lines.dropLast(1)
    return ShellProbeResult(
        output = outputLines.joinToString("\n").trim(),
        exitCode = exitCode,
        markerMissing = false
    )
}

internal fun assessFridaInjectResult(
    rawOutput: String,
    injectLog: String,
    marker: String = "__RC:"
): FridaInjectAssessment {
    val probe = parseShellProbeResult(rawOutput, marker = marker)
    val positiveKeywords = listOf(
        "memfd NF ready",
        "stealth_camera_v3 loaded",
        "Waiting for camera activation",
        "switch_avm hooked",
        "setAppState + stop hooked"
    )
    val fatalKeywords = listOf(
        "not found",
        "No such file",
        "Permission denied",
        "Exec format error",
        "unable to connect",
        "failed to inject",
        "failed to attach",
        "failed to spawn",
        "process not found"
    )
    val positiveSignalDetected = positiveKeywords.any { injectLog.contains(it, ignoreCase = true) }
    val fatalSignalDetected = fatalKeywords.any { injectLog.contains(it, ignoreCase = true) }
    val canProceedToActivation = when {
        probe.exitCode == 0 && !fatalSignalDetected -> true
        probe.markerMissing && positiveSignalDetected && !fatalSignalDetected -> true
        else -> false
    }
    return FridaInjectAssessment(
        exitCode = probe.exitCode,
        markerMissing = probe.markerMissing,
        positiveSignalDetected = positiveSignalDetected,
        fatalSignalDetected = fatalSignalDetected,
        canProceedToActivation = canProceedToActivation
    )
}

internal fun parseManagedFridaLaunchObservation(
    rawOutput: String,
    pidMarker: String = "__BG_PID__:",
    aliveMarker: String = "__BG_ALIVE__:"
): ManagedFridaLaunchObservation {
    val lines = rawOutput.lineSequence().map { it.trim() }.toList()
    val pidRaw = lines.firstOrNull { it.startsWith(pidMarker) }?.removePrefix(pidMarker)?.trim()
    val aliveRaw = lines.firstOrNull { it.startsWith(aliveMarker) }?.removePrefix(aliveMarker)?.trim()
    return ManagedFridaLaunchObservation(
        backgroundPid = pidRaw?.takeIf { it.isNotEmpty() },
        processAlive = aliveRaw == "1",
        markerMissing = pidRaw == null || aliveRaw == null
    )
}

internal fun extractLatestLogWindow(logText: String, startMarker: String): String {
    val markerIndex = logText.lastIndexOf(startMarker)
    if (markerIndex < 0) return logText.trim()
    return logText.substring(markerIndex).trim()
}

internal fun collectProtectedProcessFridaResidues(rawOutput: String): List<ProtectedProcessFridaResidue> {
    val protectedProcessNames = setOf(
        "system_server",
        "zygote",
        "zygote64",
        "zygote_secondary"
    )
    return rawOutput
        .lineSequence()
        .map { it.trim() }
        .filter { it.isNotEmpty() }
        .mapNotNull { line ->
            val parts = line.split(':', limit = 3)
            if (parts.size != 3) return@mapNotNull null
            val processName = parts[0].trim()
            val pid = parts[1].trim()
            val evidence = parts[2].trim()
            if (processName.isEmpty() || pid.isEmpty() || evidence.isEmpty()) return@mapNotNull null
            if (processName !in protectedProcessNames) return@mapNotNull null
            if (!pid.all { it.isDigit() }) return@mapNotNull null
            ProtectedProcessFridaResidue(
                processName = processName,
                pid = pid,
                evidence = evidence
            )
        }
        .distinctBy { "${it.processName}:${it.pid}:${it.evidence}" }
        .toList()
}

internal fun parsePidFromPsLine(psOutput: String, processName: String): String? {
    if (psOutput.isBlank()) return null
    val nameRegex = Regex("(^|\\s)${Regex.escape(processName)}(\\s|$)")
    val pidRegex = Regex("\\b\\d+\\b")
    for (line in psOutput.lineSequence()) {
        val trimmed = line.trim()
        if (trimmed.isEmpty()) continue
        if (!nameRegex.containsMatchIn(trimmed)) continue
        val pid = pidRegex.find(trimmed)?.value
        if (!pid.isNullOrBlank()) return pid
    }
    return null
}

internal fun diagnoseTargetProcessMissing(
    targetProcess: String,
    pidofOutput: String,
    exactProcessOutput: String,
    processSnapshot: String
): TargetProcessMissingDiagnosis {
    val lowerPidof = pidofOutput.lowercase()
    val lowerExact = exactProcessOutput.lowercase()
    val lowerSnapshot = processSnapshot.lowercase()
    val merged = "$lowerPidof\n$lowerExact\n$lowerSnapshot"

    val permissionKeywords = listOf(
        "permission denied",
        "operation not permitted",
        "not permitted",
        "the password is incorrect",
        "authentication failure",
        "su:",
        "access denied"
    )
    if (permissionKeywords.any { merged.contains(it) }) {
        return TargetProcessMissingDiagnosis(reason = "permission")
    }

    if (lowerExact.contains(targetProcess.lowercase())) {
        return TargetProcessMissingDiagnosis(reason = "pidof_miss")
    }

    val hasTargetName = lowerSnapshot.contains(targetProcess.lowercase())
    val hasRelatedName = listOf("avm3d", "inneravm", "desaysv").any { lowerSnapshot.contains(it) }
    if (!hasTargetName && hasRelatedName) {
        return TargetProcessMissingDiagnosis(reason = "name_mismatch")
    }

    return TargetProcessMissingDiagnosis(reason = "not_running")
}

/**
 * Frida 部署与注入管理器。
 *
 * 负责：
 * - 从 APK assets 解压 frida 可执行文件和 hook 脚本
 * - 通过 ADB 推送到目标设备
 * - 启动 frida-server / 执行 frida-inject 注入脚本
 * - 管理注入后的 bridge socket 就绪检测和 AVM 激活
 * - 还原注入状态以恢复目标程序
 */
class FridaDeployer(private val appContext: Context) {

    // ========== 常量 ==========

    private companion object {
        const val TAG = "FridaDeployer"

        // assets 中的文件名
        const val ASSET_FRIDA_SERVER_XZ = "frida/frida-server.xz"
        const val ASSET_FRIDA_INJECT_XZ = "frida/frida-inject.xz"
        const val ASSET_HOOK_SCRIPT = "frida/stealth_camera_v3.js"
        const val LOCAL_STAGE_DIR = "frida_stage"
        const val LOCAL_STAGE_FRIDA_SERVER = "frida-server"
        const val LOCAL_STAGE_FRIDA_INJECT = "frida-inject"
        const val LOCAL_STAGE_HOOK_SCRIPT = "stealth_camera_v3.js"

        // 目标设备上的路径
        const val REMOTE_TMP = "/data/local/tmp"
        const val REMOTE_FRIDA_SERVER = "$REMOTE_TMP/frida-server"
        const val REMOTE_FRIDA_INJECT = "$REMOTE_TMP/frida-inject"
        const val REMOTE_HOOK_SCRIPT = "$REMOTE_TMP/stealth_camera_v3.js"
        const val REMOTE_FRIDA_SERVER_LOG = "$REMOTE_TMP/frida_server.log"
        const val REMOTE_FRIDA_INJECT_LOG = "$REMOTE_TMP/frida_inject.log"
        const val REMOTE_BRIDGE_SOCKET = "$REMOTE_TMP/starlight_bridge.sock"
        const val REMOTE_STREAM_READY_MARKER = "$REMOTE_TMP/starlight_bridge_stream_ready"
        const val REMOTE_LAST_INJECT_MARKER = "$REMOTE_TMP/starlight_bridge_last_inject_ms"
        const val REMOTE_INJECTING_MARKER = "$REMOTE_TMP/starlight_bridge_injecting"
        /** 远端部署版本标记文件，内容为推送时的 APK versionCode */
        const val REMOTE_DEPLOY_VERSION = "$REMOTE_TMP/starlight_bridge_deploy.version"
        /** 远端 Frida 二进制 bundle 标记，避免同版 APK 下资产升级被跳过 */
        const val REMOTE_FRIDA_BUNDLE_VERSION = "$REMOTE_TMP/starlight_bridge_frida_bundle.version"

        // 目标进程
        const val TARGET_PROCESS = "avm3d_service"
        const val INNER_AVM_PROCESS = "com.desaysv.inneravmservice"

        // 360 Activity 唤起（用于触发相机/视频流激活）
        const val AVM_ACTIVITY_COMPONENT = "com.desaysv.inneravmservice/.InnerAvmActivity"
        const val AVM_ACTIVITY_START_CMD = "am start -n $AVM_ACTIVITY_COMPONENT"
        const val AVM_ACTIVITY_STABILIZE_DELAY_MS = 800L

        // AVM 收口广播
        const val AVM_CONTROL_ACTION = "com.desaysv.action.control_inner_avm"
        const val AVM_CONTROL_KEY = "key_control_inner_avm"
        const val AVM_CONTROL_EXIT_VALUE = "exit_inner_avm"
        const val AVM_EXIT_BROADCAST_CMD =
            "am broadcast -a $AVM_CONTROL_ACTION --es $AVM_CONTROL_KEY $AVM_CONTROL_EXIT_VALUE"

        // innerAvmService 重绑等待参数
        const val INNER_AVM_REBIND_POLL_MS = 300L
        const val INNER_AVM_REBIND_WAIT_TIMEOUT_MS = 8000L

        // 注入前重启 innerAvmService 等待参数
        const val INNER_AVM_PREINJECT_RESTART_POLL_MS = 200L
        const val INNER_AVM_PREINJECT_RESTART_TIMEOUT_MS = 3000L
        const val INNER_AVM_FORCE_STOP_POLL_MS = 200L
        const val INNER_AVM_FORCE_STOP_TIMEOUT_MS = 2000L

        // bridge socket 就绪等待参数
        const val BRIDGE_READY_WAIT_POLL_MS = 200L
        const val BRIDGE_READY_WAIT_TIMEOUT_MS = 1500L
        const val BRIDGE_READY_WAIT_RETRY_TIMEOUT_MS = 2500L
        const val BRIDGE_READY_WAKE_RETRY_COUNT = 2

        // 重注入等待参数
        const val REINJECT_RESTART_WAIT_TIMEOUT_MS = 8000L
        const val REINJECT_RESTART_POLL_MS = 200L

        // 推送文件后 MD5 校验最大重试次数
        const val MAX_PUSH_VERIFY_RETRIES = 3

        // 目标进程轮询等待参数
        const val TARGET_PID_WAIT_POLL_MS = 200L
        const val TARGET_PID_WAIT_TIMEOUT_MS = 5000L
        const val TARGET_PID_WAKE_RETRY_TIMEOUT_MS = 3000L
        const val FRIDA_MANAGED_INJECT_STARTUP_DELAY_MS = 1000L
        const val FRIDA_MANAGED_INJECT_READY_TIMEOUT_MS = 5000L
        const val FRIDA_MANAGED_INJECT_READY_POLL_MS = 250L
        const val BACKGROUND_BYPASS_COPY_ENABLED = true
        const val BACKGROUND_BYPASS_RENDER_ENABLED = true
        const val BACKGROUND_FORCE_RENDER_LOOP = false
        const val BACKGROUND_RECOVER_FRAME_COUNT = DEFAULT_BACKGROUND_RECOVER_FRAME_COUNT
        val PROTECTED_PROCESS_NAMES = listOf(
            "system_server",
            "zygote",
            "zygote64",
            "zygote_secondary"
        )

        // 全局注入互斥，覆盖 UI/广播等多入口并发触发
        val injectOperationRunning = AtomicBoolean(false)
    }

    /**
     * 日志回调类型。
     */
    fun interface LogCallback {
        fun onLog(message: String)
    }

    // ========== 解压 ==========

    /**
     * 获取本地预处理目录（应用私有目录）。
     */
    private suspend fun ensureLocalStageDir(): File = withContext(Dispatchers.IO) {
        val dir = File(appContext.filesDir, LOCAL_STAGE_DIR)
        if (!dir.exists() && !dir.mkdirs()) {
            throw IOException("无法创建本地预处理目录: ${dir.absolutePath}")
        }
        dir
    }

    /**
     * 从 assets 读取 .xz 文件并解压到应用本地文件。
     */
    private suspend fun decompressXzAssetToFile(assetPath: String, outputFile: File) = withContext(Dispatchers.IO) {
        outputFile.parentFile?.mkdirs()
        appContext.assets.open(assetPath).use { raw ->
            XZInputStream(raw).use { xz ->
                outputFile.outputStream().use { out ->
                    val buffer = ByteArray(64 * 1024)
                    while (true) {
                        val n = xz.read(buffer)
                        if (n < 0) break
                        out.write(buffer, 0, n)
                    }
                }
            }
        }
    }

    /**
     * 从 assets 读取原始文件并写入应用本地文件。
     */
    private suspend fun copyAssetToFile(assetPath: String, outputFile: File) = withContext(Dispatchers.IO) {
        outputFile.parentFile?.mkdirs()
        appContext.assets.open(assetPath).use { input ->
            outputFile.outputStream().use { out ->
                input.copyTo(out)
            }
        }
    }

    private suspend fun renderHookScriptToFile(
        assetPath: String,
        outputFile: File,
        targetFps: Double
    ) = withContext(Dispatchers.IO) {
        outputFile.parentFile?.mkdirs()
        val template = appContext.assets.open(assetPath).bufferedReader(Charsets.UTF_8).use { it.readText() }
        val rendered = renderHookScriptTemplate(
            template = template,
            config = HookScriptRuntimeConfig(
                targetFps = targetFps,
                backgroundBypassCopy = BACKGROUND_BYPASS_COPY_ENABLED,
                backgroundBypassRender = BACKGROUND_BYPASS_RENDER_ENABLED,
                backgroundForceRenderLoop = BACKGROUND_FORCE_RENDER_LOOP,
                recoverFrameCount = BACKGROUND_RECOVER_FRAME_COUNT
            )
        )
        outputFile.writeText(rendered, Charsets.UTF_8)
    }

    // ========== 部署检测 ==========

    /**
     * 检测远程文件是否已存在。
     */
    private suspend fun remoteFileExists(client: AdbClient, path: String): Boolean {
        val out = client.executeShellCommand("ls $path 2>/dev/null && echo YES || echo NO").trim()
        return out.contains("YES")
    }

    /**
     * 检测远程文件是否具有可执行权限。
     */
    private suspend fun remoteFileExecutable(client: AdbClient, path: String): Boolean {
        val out = client.executeShellCommand("test -x $path && echo YES || echo NO").trim()
        return out.contains("YES")
    }

    /**
     * 计算文件的 MD5 十六进制字符串（小写）。
     */
    private suspend fun computeFileMd5(file: File): String = withContext(Dispatchers.IO) {
        val digest = java.security.MessageDigest.getInstance("MD5")
        file.inputStream().use { input ->
            val buffer = ByteArray(8 * 1024)
            while (true) {
                val n = input.read(buffer)
                if (n < 0) break
                if (n > 0) digest.update(buffer, 0, n)
            }
        }
        digest.digest().joinToString("") { "%02x".format(it) }
    }

    private fun shellQuote(path: String): String {
        return "'" + path.replace("'", "'\\''") + "'"
    }

    /**
     * 获取远程文件的 MD5 值。
     *
     * @return MD5 十六进制字符串（32 位小写），文件不存在或命令不可用时返回 null
     */
    private suspend fun remoteFileMd5(client: AdbClient, path: String): String? {
        val commands = listOf(
            "md5sum $path 2>/dev/null",
            "toybox md5sum $path 2>/dev/null",
            "busybox md5sum $path 2>/dev/null"
        )
        for (command in commands) {
            val out = client.executeShellCommand(command).trim()
            // md5sum 输出格式：<hash>  <filename>
            val hash = out.split("\\s+".toRegex()).firstOrNull()
            if (hash != null && hash.length == 32 && hash.all { c -> c in '0'..'9' || c in 'a'..'f' }) {
                return hash
            }
        }
        return null
    }

    /**
     * 使用 adb shell cp 将应用本地文件复制到远端，并循环重试直到 MD5 一致。
     *
     * @param localFile  应用本地已就绪文件
     * @param remotePath 远端目标路径
     * @param mode       文件权限（八进制整数，如 493 = 0755）
     * @param localMd5   本地预计算的 MD5
     * @param label      用于日志的显示名称
     */
    private suspend fun copyLocalAndVerify(
        client: AdbClient,
        localFile: File,
        remotePath: String,
        mode: Int,
        localMd5: String,
        label: String,
        log: LogCallback
    ) {
        val localPathQuoted = shellQuote(localFile.absolutePath)
        val remotePathQuoted = shellQuote(remotePath)
        val octalMode = String.format("%o", mode)
        for (attempt in 1..MAX_PUSH_VERIFY_RETRIES) {
            if (attempt > 1) log.onLog("  🔄 第 ${attempt} 次复制 $label...")
            client.executeShellCommand(
                "cp $localPathQuoted $remotePathQuoted 2>/dev/null " +
                    "|| toybox cp $localPathQuoted $remotePathQuoted 2>/dev/null " +
                    "|| busybox cp $localPathQuoted $remotePathQuoted 2>/dev/null"
            )
            client.executeShellCommand("chmod $octalMode $remotePathQuoted 2>/dev/null || true")
            val verifyMd5 = remoteFileMd5(client, remotePath)
            if (verifyMd5 == null) {
                log.onLog("  ⚠️ 设备不支持 md5sum，跳过 MD5 校验（已完成推送）")
                return
            }
            if (verifyMd5 == localMd5) {
                log.onLog("  ✅ $label 复制完成，MD5 校验通过")
                return
            }
            if (attempt < MAX_PUSH_VERIFY_RETRIES) {
                log.onLog("  ⚠️ $label MD5 校验失败（第 ${attempt} 次），重新复制...")
            }
        }
        throw IOException("$label MD5 校验失败，已重试 $MAX_PUSH_VERIFY_RETRIES 次（cp 复制）")
    }

    /**
     * 检测 frida-server 是否正在运行。
     */
    private suspend fun isFridaServerRunning(client: AdbClient): Boolean {
        val out = client.executeShellCommand(
            "ps -A 2>/dev/null | grep -F 'frida-server' | grep -v grep || true"
        ).trim()
        return parsePidFromPsLine(out, "frida-server") != null
    }

    private suspend fun waitForFridaServerRunning(
        client: AdbClient,
        timeoutMs: Long = 3_000L,
        pollMs: Long = 200L
    ): Boolean {
        val startAt = System.currentTimeMillis()
        while (true) {
            if (isFridaServerRunning(client)) return true
            val elapsed = (System.currentTimeMillis() - startAt).coerceAtLeast(0)
            if (elapsed >= timeoutMs) return false
            delay(pollMs)
        }
    }

    private suspend fun waitForFridaServerStopped(
        client: AdbClient,
        timeoutMs: Long = 3_000L,
        pollMs: Long = 200L
    ): Boolean {
        val startAt = System.currentTimeMillis()
        while (true) {
            if (!isFridaServerRunning(client)) return true
            val elapsed = (System.currentTimeMillis() - startAt).coerceAtLeast(0)
            if (elapsed >= timeoutMs) return false
            delay(pollMs)
        }
    }

    private suspend fun readRemoteLogTail(
        client: AdbClient,
        path: String,
        maxBytes: Int = 32768
    ): String {
        return client.executeShellCommand("tail -c $maxBytes $path 2>/dev/null").trim()
    }

    private fun appendTruncated(builder: StringBuilder, chunk: String, maxChars: Int = 8192) {
        if (chunk.isEmpty()) return
        builder.append(chunk)
        if (builder.length > maxChars) {
            builder.delete(0, builder.length - maxChars)
        }
    }

    private suspend fun readInjectLogWindow(
        client: AdbClient,
        startMarker: String,
        maxBytes: Int = 131072
    ): String {
        val fullLog = readRemoteLogTail(client, REMOTE_FRIDA_INJECT_LOG, maxBytes = maxBytes)
        return extractLatestLogWindow(fullLog, startMarker)
    }

    private suspend fun detectProtectedProcessFridaResidues(client: AdbClient): List<ProtectedProcessFridaResidue> {
        val processNames = PROTECTED_PROCESS_NAMES.joinToString(" ")
        val output = client.executeShellCommand(
            "for name in $processNames; do " +
                "for pid in \$(pidof \$name 2>/dev/null); do " +
                "if grep -aq frida-agent /proc/\$pid/maps 2>/dev/null; then echo \$name:\$pid:maps; fi; " +
                "if cat /proc/\$pid/task/*/comm 2>/dev/null | grep -qx gum-js-loop; then echo \$name:\$pid:threads; " +
                "elif cat /proc/\$pid/task/*/comm 2>/dev/null | grep -qx gmain; then echo \$name:\$pid:threads; " +
                "elif cat /proc/\$pid/task/*/comm 2>/dev/null | grep -qx gdbus; then echo \$name:\$pid:threads; fi; " +
                "done; " +
                "done"
        ).trim()
        return collectProtectedProcessFridaResidues(output)
    }

    private suspend fun ensureNoProtectedProcessFridaResidues(
        client: AdbClient,
        log: LogCallback,
        stageLabel: String
    ): Boolean {
        val residues = detectProtectedProcessFridaResidues(client)
        if (residues.isEmpty()) return true
        log.onLog("❌ $stageLabel：检测到受保护系统进程含有 Frida 残留，已中止注入以避免卡死/重启")
        residues.forEach { residue ->
            log.onLog(
                "  • ${residue.processName} (PID=${residue.pid}) 命中 ${residue.evidence} 证据"
            )
        }
        log.onLog("  ℹ️ 请先人工恢复到干净状态（建议重启设备）后再继续注入")
        return false
    }

    private suspend fun startManagedFridaInjectSession(
        client: AdbClient,
        targetPid: String,
        log: LogCallback
    ): String? {
        if (isFridaInjectRunning(client)) {
            log.onLog("❌ 启动新会话前仍检测到 frida-inject 存活，拒绝直接覆盖旧会话")
            return null
        }

        val startMarker = "==== frida-inject start ts=${System.currentTimeMillis()} pid=$targetPid mode=managed ===="
        val launchOutput = client.executeShellCommand(
            "echo $startMarker >> $REMOTE_FRIDA_INJECT_LOG; " +
                "$REMOTE_FRIDA_INJECT -p $targetPid -s $REMOTE_HOOK_SCRIPT >> $REMOTE_FRIDA_INJECT_LOG 2>&1 & " +
                "bg=\$!; echo __BG_PID__:\$bg; " +
                "sleep 1; if kill -0 \$bg 2>/dev/null; then echo __BG_ALIVE__:1; else echo __BG_ALIVE__:0; fi"
        )
        delay(FRIDA_MANAGED_INJECT_STARTUP_DELAY_MS)

        val launchObservation = parseManagedFridaLaunchObservation(launchOutput)
        if (launchObservation.markerMissing) {
            log.onLog("⚠️ frida-inject 后台启动标记缺失，将继续结合日志判定会话是否已建立")
        } else if (!launchObservation.processAlive) {
            log.onLog(
                "⚠️ frida-inject 后台会话启动后未存活（PID=${launchObservation.backgroundPid ?: "unknown"}）"
            )
        } else {
            log.onLog("✅ frida-inject 后台会话已启动 (PID=${launchObservation.backgroundPid})")
        }
        return startMarker
    }

    private suspend fun waitForManagedFridaInjectReady(
        client: AdbClient,
        log: LogCallback,
        startMarker: String
    ): Pair<Boolean, String> {
        val deadlineAt = System.currentTimeMillis() + FRIDA_MANAGED_INJECT_READY_TIMEOUT_MS
        var latestLogWindow: String
        while (System.currentTimeMillis() < deadlineAt) {
            latestLogWindow = readInjectLogWindow(client, startMarker)
            val injectAssessment = assessFridaInjectResult(
                rawOutput = "__RC:0",
                injectLog = latestLogWindow
            )
            if (injectAssessment.fatalSignalDetected) {
                return false to latestLogWindow
            }
            if (!ensureNoProtectedProcessFridaResidues(client, log, "注入后安全检查")) {
                return false to latestLogWindow
            }
            val injectRunning = isFridaInjectRunning(client)
            if (injectAssessment.positiveSignalDetected && injectRunning) {
                return true to latestLogWindow
            }
            delay(FRIDA_MANAGED_INJECT_READY_POLL_MS)
        }
        latestLogWindow = readInjectLogWindow(client, startMarker)
        return false to latestLogWindow
    }

    /**
     * 获取目标进程 PID。
     *
     * @return PID，未找到返回 null
     */
    private suspend fun findTargetPid(client: AdbClient): String? {
        return findTargetPidWithSource(client).pid
    }

    private suspend fun findTargetPidWithSource(client: AdbClient): TargetPidLookup {
        val pidofOutput = client.executeShellCommand("pidof $TARGET_PROCESS 2>/dev/null").trim()
        val pidFromPidof = pidofOutput.split("\\s+".toRegex()).firstOrNull { it.isNotEmpty() }
        if (!pidFromPidof.isNullOrBlank()) {
            return TargetPidLookup(pid = pidFromPidof, source = "pidof")
        }
        val psOutput = client.executeShellCommand(
            "ps -A 2>/dev/null | grep -F $TARGET_PROCESS 2>/dev/null || true"
        ).trim()
        val pidFromPs = parsePidFromPsLine(psOutput, TARGET_PROCESS)
        if (!pidFromPs.isNullOrBlank()) {
            return TargetPidLookup(pid = pidFromPs, source = "ps_fallback")
        }
        return TargetPidLookup(pid = null, source = "none")
    }

    private suspend fun waitForTargetPid(
        client: AdbClient,
        timeoutMs: Long,
        pollMs: Long = TARGET_PID_WAIT_POLL_MS
    ): TargetPidLookup? {
        val start = System.currentTimeMillis()
        while (true) {
            val lookup = findTargetPidWithSource(client)
            if (!lookup.pid.isNullOrBlank()) return lookup
            val elapsed = (System.currentTimeMillis() - start).coerceAtLeast(0)
            if (elapsed >= timeoutMs) return null
            delay(pollMs)
        }
    }

    private suspend fun findTargetPidWithRecovery(
        client: AdbClient,
        log: LogCallback,
        stageLabel: String,
        allowWakeUp: Boolean
    ): TargetPidLookup? {
        val immediate = findTargetPidWithSource(client)
        if (!immediate.pid.isNullOrBlank()) return immediate

        log.onLog("⏳ $stageLabel：等待 $TARGET_PROCESS 拉起（最多 ${TARGET_PID_WAIT_TIMEOUT_MS / 1000}s）...")
        val waited = waitForTargetPid(client, timeoutMs = TARGET_PID_WAIT_TIMEOUT_MS)
        if (waited != null) {
            log.onLog("✅ $stageLabel：轮询后捕获到目标 PID=${waited.pid}")
            return waited
        }

        if (!allowWakeUp) return null

        log.onLog("⚠️ $stageLabel：轮询超时，尝试唤起 360 Activity 再次等待")
        val wakeOutput = client.executeShellCommand("$AVM_ACTIVITY_START_CMD 2>&1").trim()
        if (wakeOutput.isNotBlank()) {
            log.onLog("📋 Activity 唤起输出:\n${truncateForUi(wakeOutput, 500)}")
        }
        delay(AVM_ACTIVITY_STABILIZE_DELAY_MS)

        val retried = waitForTargetPid(client, timeoutMs = TARGET_PID_WAKE_RETRY_TIMEOUT_MS)
        if (retried != null) {
            log.onLog("✅ $stageLabel：Activity 唤起后捕获到目标 PID=${retried.pid}")
        }
        return retried
    }

    private suspend fun runShellProbe(client: AdbClient, command: String): Pair<AdbRootShell.RootCommand, ShellProbeResult> {
        val marker = "__HA_RC__:"
        val wrapped = AdbRootShell.wrapIfEnabled(appContext, command)
        val raw = client.executeShellCommand("$command; echo $marker\$?")
        return wrapped to parseShellProbeResult(raw, marker = marker)
    }

    private suspend fun explainMissingTargetProcess(
        client: AdbClient,
        log: LogCallback
    ) {
        val (pidofCommand, pidofProbe) = runShellProbe(client, "pidof $TARGET_PROCESS 2>&1")
        val (exactPsCommand, exactPsProbe) = runShellProbe(
            client,
            "ps -A 2>&1 | grep -F $TARGET_PROCESS || true"
        )
        val (snapshotCommand, snapshotProbe) = runShellProbe(
            client,
            "ps -A 2>&1 | grep -F avm3d || true; " +
                "ps -A 2>&1 | grep -F inneravm || true; " +
                "ps -A 2>&1 | grep -F desaysv || true"
        )
        val pidFromPsFallback = parsePidFromPsLine(exactPsProbe.output, TARGET_PROCESS)
        log.onLog("🔧 诊断命令 pidof: ${truncateForUi(pidofCommand.logSafe, 260)}")
        log.onLog("🔧 诊断命令 ps精确: ${truncateForUi(exactPsCommand.logSafe, 260)}")
        log.onLog("🔧 诊断命令 ps快照: ${truncateForUi(snapshotCommand.logSafe, 260)}")
        log.onLog(
            "📎 命令返回码: pidof=${pidofProbe.exitCode ?: "N/A"}, " +
                "ps精确=${exactPsProbe.exitCode ?: "N/A"}, ps快照=${snapshotProbe.exitCode ?: "N/A"}"
        )
        if (pidofProbe.markerMissing || exactPsProbe.markerMissing || snapshotProbe.markerMissing) {
            log.onLog("⚠️ 诊断命令返回码标记缺失，可能存在 shell 包装或命令链路异常")
        }

        val diagnosis = diagnoseTargetProcessMissing(
            targetProcess = TARGET_PROCESS,
            pidofOutput = pidofProbe.output,
            exactProcessOutput = exactPsProbe.output,
            processSnapshot = snapshotProbe.output
        )

        when (diagnosis.reason) {
            "permission" -> {
                log.onLog("🔍 判定：更可能是权限问题（su/提权失败或命令被拒绝）")
            }
            "pidof_miss" -> {
                log.onLog(
                    "🔍 判定：pidof 未命中，但 ps 能看到 $TARGET_PROCESS，" +
                        "更可能是工具差异或当前权限上下文导致 pidof 失效"
                )
            }
            "name_mismatch" -> {
                log.onLog("🔍 判定：更可能是进程名称不匹配（设备上的实际名称与 $TARGET_PROCESS 不一致）")
            }
            else -> {
                log.onLog("🔍 判定：目标进程当前未启动（未发现相关 AVM 进程）")
            }
        }

        if (pidofProbe.output.isNotBlank()) {
            log.onLog("📋 pidof 输出:\n${truncateForUi(pidofProbe.output)}")
        }
        if (exactPsProbe.output.isNotBlank()) {
            log.onLog("📋 ps 精确匹配输出:\n${truncateForUi(exactPsProbe.output)}")
        }
        if (!pidFromPsFallback.isNullOrBlank()) {
            log.onLog("📌 ps 回退可解析到 PID=$pidFromPsFallback（可用于进一步排查 pidof 兼容性）")
        }
        if (snapshotProbe.output.isNotBlank()) {
            log.onLog("📋 相关进程快照:\n${truncateForUi(snapshotProbe.output)}")
        }
    }

    private fun truncateForUi(text: String, maxChars: Int = 1200): String {
        val normalized = text.trim()
        if (normalized.length <= maxChars) return normalized
        return normalized.take(maxChars) + "\n...（输出已截断）"
    }

    /**
     * 获取 innerAvmService 进程 PID。
     *
     * @return PID，未找到返回 null
     */
    private suspend fun findInnerAvmPid(client: AdbClient): String? {
        val out = client.executeShellCommand("pidof $INNER_AVM_PROCESS 2>/dev/null").trim()
        return out.split("\\s+".toRegex()).firstOrNull { it.isNotEmpty() }
    }

    /**
     * 检测 frida-inject 是否正在运行。
     */
    private suspend fun isFridaInjectRunning(client: AdbClient): Boolean {
        val out = client.executeShellCommand("pidof frida-inject 2>/dev/null").trim()
        return out.isNotEmpty()
    }

    /**
     * 读取 bridge 当前就绪状态。
     * 同时检查公共 socket 是否存在且可监听，以及脚本侧 stream_ready marker 是否已写入。
     */
    private suspend fun readBridgeReadinessState(client: AdbClient): BridgeReadinessState {
        val raw = client.executeShellCommand(
            "if [ -S $REMOTE_BRIDGE_SOCKET ] && grep -F \" $REMOTE_BRIDGE_SOCKET\" /proc/net/unix >/dev/null 2>&1; " +
                "then echo __BRIDGE_SOCKET__:1; else echo __BRIDGE_SOCKET__:0; fi; " +
                "if [ -f $REMOTE_STREAM_READY_MARKER ]; then echo __BRIDGE_STREAM__:1; " +
                "else echo __BRIDGE_STREAM__:0; fi"
        ).trim()
        return parseBridgeReadinessState(raw)
    }

    // ========== 进程管理 ==========

    /**
     * 重复注入前先杀目标进程，等待系统保活拉起新 PID。
     *
     * @param client ADB 客户端
     * @param oldPid 当前目标进程 PID
     * @param log 日志回调
     * @return 重启后的新 PID，失败返回 null
     */
    private suspend fun restartTargetProcessForReinject(
        client: AdbClient,
        oldPid: String,
        log: LogCallback,
        reasonLabel: String = "重复注入"
    ): String? {
        log.onLog("🔁 $reasonLabel：先重启目标进程 $TARGET_PROCESS (PID=$oldPid)")
        client.executeShellCommand("kill -9 $oldPid 2>/dev/null || true")

        log.onLog("⏳ 等待目标进程拉起（最多 ${REINJECT_RESTART_WAIT_TIMEOUT_MS / 1000}s）...")
        val deadlineAt = System.currentTimeMillis() + REINJECT_RESTART_WAIT_TIMEOUT_MS
        while (System.currentTimeMillis() < deadlineAt) {
            val current = findTargetPid(client)
            if (!current.isNullOrBlank() && current != oldPid) {
                return current
            }
            delay(REINJECT_RESTART_POLL_MS)
        }
        log.onLog("⚠️ 目标进程重启等待超时，仍未拿到新 PID")
        return null
    }

    private suspend fun killProcessByName(
        client: AdbClient,
        processName: String,
        displayName: String,
        log: LogCallback
    ) {
        val pids = client.executeShellCommand("pidof $processName 2>/dev/null").trim()
        if (pids.isEmpty()) {
            log.onLog("  ℹ️ $displayName 未运行")
            return
        }
        client.executeShellCommand("kill -9 $pids 2>/dev/null || true")
        log.onLog("  ✅ 已杀死 $displayName (PID=$pids)")
    }

    private suspend fun clearRuntimeStateWithoutRemovingFiles(
        client: AdbClient,
        log: LogCallback
    ) {
        client.executeShellCommand(
            "rm -f $REMOTE_BRIDGE_SOCKET $REMOTE_STREAM_READY_MARKER " +
                "$REMOTE_LAST_INJECT_MARKER $REMOTE_INJECTING_MARKER 2>/dev/null || true"
        )
        FridaInjectTimestampPreferences.clear(appContext)
        log.onLog("  🧹 已清理 bridge socket 与注入标记（保留二进制/脚本/日志）")
    }

    private suspend fun ensureNoActiveManagedInjectSession(
        client: AdbClient,
        currentPid: String,
        log: LogCallback
    ): String? {
        if (!isFridaInjectRunning(client)) return currentPid
        log.onLog("⚠️ 检测到旧 frida-inject 托管会话，先按安全顺序清理旧状态")
        for (target in buildManagedInjectSessionCleanupOrder(TARGET_PROCESS)) {
            killProcessByName(client, target.processName, target.displayName, log)
        }
        clearRuntimeStateWithoutRemovingFiles(client, log)
        val restartedPid = restartTargetProcessForReinject(
            client = client,
            oldPid = currentPid,
            log = log,
            reasonLabel = "旧托管会话清理"
        )
        if (restartedPid.isNullOrBlank()) {
            log.onLog("❌ 旧托管会话清理后未等到目标进程恢复")
            return null
        }
        log.onLog("✅ 已清理旧托管会话，新目标 PID=$restartedPid")
        return restartedPid
    }

    private suspend fun prepareStrictReinject(
        client: AdbClient,
        currentPid: String,
        log: LogCallback
    ): String? {
        log.onLog("🔒 严格重启重注入：清理目标进程与 Frida 运行态，但保留部署文件")
        for (target in buildInjectedProcessCleanupOrder(TARGET_PROCESS)) {
            killProcessByName(client, target.processName, target.displayName, log)
        }
        clearRuntimeStateWithoutRemovingFiles(client, log)
        val restartedPid = restartTargetProcessForReinject(
            client = client,
            oldPid = currentPid,
            log = log,
            reasonLabel = "严格重启重注入"
        )
        if (restartedPid.isNullOrBlank()) {
            log.onLog("❌ 严格重启后未等到 $TARGET_PROCESS 被系统重新拉起")
            return null
        }
        log.onLog("✅ 严格重启后目标进程已重新拉起，新 PID=$restartedPid")
        return restartedPid
    }

    private suspend fun cleanupAfterManagedInjectFailure(
        client: AdbClient,
        log: LogCallback,
        reasonLabel: String
    ) {
        log.onLog("🧹 $reasonLabel：按安全顺序回收未完成的托管注入会话")
        for (target in buildManagedInjectSessionCleanupOrder(TARGET_PROCESS)) {
            killProcessByName(client, target.processName, target.displayName, log)
        }
        clearRuntimeStateWithoutRemovingFiles(client, log)
        val residues = detectProtectedProcessFridaResidues(client)
        if (residues.isNotEmpty()) {
            log.onLog("⚠️ 回收后仍检测到系统进程存在 Frida 残留，建议重启设备后再继续联调")
            residues.forEach { residue ->
                log.onLog("  • ${residue.processName} (PID=${residue.pid}) 命中 ${residue.evidence} 证据")
            }
        }
    }

    /**
     * 目标进程重启后，确保 innerAvmService 也完成重绑。
     *
     * 如果 innerAvmService 的 PID 未变化（说明仍为旧连接），则主动 kill 并等待系统拉起新进程。
     */
    private suspend fun ensureInnerAvmReboundAfterTargetRestart(
        client: AdbClient,
        innerPidBeforeRestart: String?,
        log: LogCallback
    ) {
        if (innerPidBeforeRestart.isNullOrBlank()) {
            log.onLog("ℹ️ 重启前 inneravmservice 未运行，后续通过 Activity 冷启动")
            return
        }

        val currentInnerPid = findInnerAvmPid(client)

        if (!shouldRestartInnerAvmProcess(innerPidBeforeRestart, currentInnerPid)) {
            if (currentInnerPid.isNullOrBlank()) {
                log.onLog("ℹ️ inneravmservice 当前未运行，将在拉起 Activity 时启动")
            } else {
                log.onLog("✅ inneravmservice 已更新 PID=$currentInnerPid")
            }
            return
        }

        // PID 未变化，需要主动重启
        log.onLog("⚠️ inneravmservice 仍为旧 PID=$currentInnerPid，先重启以避免失效连接")
        client.executeShellCommand("kill -9 $currentInnerPid 2>/dev/null || true")

        val deadlineAt = System.currentTimeMillis() + INNER_AVM_REBIND_WAIT_TIMEOUT_MS
        while (System.currentTimeMillis() < deadlineAt) {
            delay(INNER_AVM_REBIND_POLL_MS)
            val refreshed = findInnerAvmPid(client)
            if (refreshed.isNullOrBlank()) continue
            if (refreshed != innerPidBeforeRestart) {
                log.onLog("✅ inneravmservice 已重启，新的 PID=$refreshed")
                return
            }
        }
        log.onLog("⚠️ inneravmservice 重启等待超时，将继续按拉起 Activity 路径触发")
    }

    /**
     * 注入前重启 innerAvmService，避免复用旧实例导致首帧链路不触发。
     *
     * 当前观测到在部分场景下，innerAvmService 保持旧 PID 时，`am start` 仅投递给
     * 现有 top-most 实例，可能无法触发有效首帧，进而导致 bridge socket 长时间未就绪。
     */
    private suspend fun restartInnerAvmBeforeInject(
        client: AdbClient,
        log: LogCallback
    ) {
        val innerPidBefore = findInnerAvmPid(client)
        if (innerPidBefore.isNullOrBlank()) {
            log.onLog("ℹ️ 注入前 inneravmservice 未运行，后续通过 Activity 按需拉起")
            return
        }

        log.onLog("🔄 注入前重启 inneravmservice (PID=$innerPidBefore)，确保链路冷启动")
        val killRaw = client.executeShellCommand(
            "kill -9 $innerPidBefore >/dev/null 2>&1; " +
                "echo __KILL_RC__:\$?; " +
                "echo __KILL_PID__:\$(pidof $INNER_AVM_PROCESS 2>/dev/null)"
        )
        val killObservation = parseProcessKillObservation(killRaw)
        when {
            killObservation.passwordRejected -> {
                log.onLog("⚠️ kill inneravmservice 失败：su 校验未通过（可能密码不正确）")
            }
            killObservation.markerMissing -> {
                val safeOutput = killRaw.trim().ifBlank { "<empty>" }
                log.onLog("⚠️ kill inneravmservice 结果不可解析：$safeOutput")
            }
            killObservation.killExitCode != 0 -> {
                val pidAfter = killObservation.pidAfterKill ?: "<none>"
                log.onLog("⚠️ kill inneravmservice 返回码=${killObservation.killExitCode}，PID快照=$pidAfter")
            }
            else -> {
                val pidAfter = killObservation.pidAfterKill ?: "<none>"
                log.onLog("✅ kill inneravmservice 命令已执行，PID快照=$pidAfter")
            }
        }

        val deadlineAt = System.currentTimeMillis() + INNER_AVM_PREINJECT_RESTART_TIMEOUT_MS
        while (System.currentTimeMillis() < deadlineAt) {
            delay(INNER_AVM_PREINJECT_RESTART_POLL_MS)
            val refreshed = findInnerAvmPid(client)
            if (refreshed.isNullOrBlank()) {
                log.onLog("✅ inneravmservice 已退出，等待后续 Activity 拉起新实例")
                return
            }
            if (refreshed != innerPidBefore) {
                log.onLog("✅ inneravmservice 已重启，新的 PID=$refreshed")
                return
            }
        }

        log.onLog("⚠️ 注入前 inneravmservice 重启等待超时，执行 force-stop 兜底")
        val forceStopOut = client.executeShellCommand("am force-stop $INNER_AVM_PROCESS 2>&1").trim()
        if (forceStopOut.isNotBlank()) {
            log.onLog("📋 force-stop 输出: $forceStopOut")
        }
        val forceStopDeadlineAt = System.currentTimeMillis() + INNER_AVM_FORCE_STOP_TIMEOUT_MS
        while (System.currentTimeMillis() < forceStopDeadlineAt) {
            delay(INNER_AVM_FORCE_STOP_POLL_MS)
            val refreshed = findInnerAvmPid(client)
            if (refreshed.isNullOrBlank()) {
                log.onLog("✅ force-stop 后 inneravmservice 已停止，后续按冷启动路径拉起")
                return
            }
            if (refreshed != innerPidBefore) {
                log.onLog("✅ force-stop 后 inneravmservice 已切换新 PID=$refreshed")
                return
            }
        }
        val lastPid = findInnerAvmPid(client).orEmpty().ifBlank { "<none>" }
        log.onLog("⚠️ force-stop 兜底未观察到 PID 变化（当前 PID=$lastPid），继续执行注入")
    }

    // ========== AVM 控制 ==========

    /**
     * 通过广播通知 AVM 收口退出。
     *
     * @return true = 广播成功发送且无异常
     */
    private suspend fun exitAvmViaBroadcast(client: AdbClient, log: LogCallback): Boolean {
        val out = client.executeShellCommand("$AVM_EXIT_BROADCAST_CMD 2>&1").trim()

        if (out.isNotBlank()) {
            log.onLog("📋 AVM 退出广播输出:\n$out")
        }

        val success = out.contains("Broadcast completed", ignoreCase = true) &&
            !out.contains("Exception", ignoreCase = true) &&
            !out.contains("Error", ignoreCase = true)

        if (success) {
            log.onLog("✅ 已通过广播触发 AVM 收口")
        } else {
            log.onLog("⚠️ AVM 收口广播失败，不再执行其他收口操作")
        }
        return success
    }

    /**
     * 注入后通过 Activity 路径触发一次 360 相机链路。
     */
    private suspend fun activateAvmViaActivity(client: AdbClient, log: LogCallback) {
        log.onLog("🎯 注入后触发 360 Activity: $AVM_ACTIVITY_COMPONENT")
        val startOut = client.executeShellCommand("$AVM_ACTIVITY_START_CMD 2>&1").trim()
        if (startOut.contains("Error", ignoreCase = true) ||
            startOut.contains("Exception", ignoreCase = true)
        ) {
            log.onLog("⚠️ Activity 唤起返回异常: $startOut")
            return
        }
        if (startOut.isNotBlank()) {
            log.onLog("📋 Activity 唤起输出: $startOut")
        }

        // 给系统一个窗口完成相机链路激活
        delay(AVM_ACTIVITY_STABILIZE_DELAY_MS)
    }

    /**
     * 在 bridge 就绪后通过广播收口 AVM。
     */
    private suspend fun closeAvmAfterBridgeReady(client: AdbClient, log: LogCallback) {
        log.onLog("ℹ️ 使用广播执行 AVM 收口（不发送按键）")
        exitAvmViaBroadcast(client, log)
    }

    // ========== Bridge Socket 就绪检测 ==========

    /**
     * 轮询等待 bridge socket 就绪。
     *
     * @param timeoutMs 超时时间（毫秒）
     * @return true = 在超时前已就绪
     */
    private suspend fun waitBridgeReady(client: AdbClient, timeoutMs: Long): Boolean {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            if (readBridgeReadinessState(client).ready) return true
            delay(BRIDGE_READY_WAIT_POLL_MS)
        }
        return false
    }

    /**
     * 注入后确保 bridge socket 就绪。
     *
     * 先等待一轮，若未就绪则通过补偿激活 Activity 重试。
     *
     * @return true = bridge 已就绪（socket + stream_ready）
     */
    private suspend fun ensureBridgeSocketReadyAfterInject(
        client: AdbClient,
        log: LogCallback
    ): Boolean {
        // 第一轮：等待 BRIDGE_READY_WAIT_TIMEOUT_MS
        if (waitBridgeReady(client, BRIDGE_READY_WAIT_TIMEOUT_MS)) {
            log.onLog("✅ bridge 已就绪（socket + stream_ready）")
            return true
        }

        // 补偿重试
        for (i in 0 until BRIDGE_READY_WAKE_RETRY_COUNT) {
            val attempt = i + 1
            log.onLog("⚠️ bridge 未就绪（等待 stream_ready），尝试补偿激活 360（$attempt/$BRIDGE_READY_WAKE_RETRY_COUNT）")
            activateAvmViaActivity(client, log)
            if (waitBridgeReady(client, BRIDGE_READY_WAIT_RETRY_TIMEOUT_MS)) {
                log.onLog("✅ bridge 已就绪（补偿激活后，socket + stream_ready）")
                return true
            }
        }
        return false
    }

    // ========== 注入时间标记 ==========

    /**
     * 将注入时间戳写入远程设备文件，供主工程哨兵读取。
     */
    private suspend fun syncLastInjectMarker(client: AdbClient, injectAtMs: Long) {
        client.executeShellCommand(
            "echo $injectAtMs > $REMOTE_LAST_INJECT_MARKER 2>/dev/null; " +
                "chmod 644 $REMOTE_LAST_INJECT_MARKER 2>/dev/null || true"
        )
    }

    private suspend fun markInjectingInProgress(client: AdbClient) {
        val nowMs = System.currentTimeMillis()
        client.executeShellCommand(
            "echo $nowMs > $REMOTE_INJECTING_MARKER 2>/dev/null; " +
                "chmod 644 $REMOTE_INJECTING_MARKER 2>/dev/null || true"
        )
    }

    private suspend fun clearInjectingInProgressMarker(client: AdbClient) {
        client.executeShellCommand("rm -f $REMOTE_INJECTING_MARKER 2>/dev/null || true")
    }

    private suspend fun syncFridaBundleVersionMarker(client: AdbClient) {
        client.executeShellCommand(
            "printf '%s' '$BUNDLED_FRIDA_BINARY_VERSION' > $REMOTE_FRIDA_BUNDLE_VERSION 2>/dev/null; " +
                "chmod 644 $REMOTE_FRIDA_BUNDLE_VERSION 2>/dev/null || true"
        )
    }

    // ========== 核心操作 ==========

    /**
     * 完整注入流程：重复注入检测 → 部署文件 → 启动 frida-server → frida-inject 注入 → bridge 就绪检测。
     *
     * @param host ADB 主机地址
     * @param port ADB 端口
     * @param log 日志回调
     */
    suspend fun inject(
        host: String,
        port: Int,
        log: LogCallback,
        strictRestart: Boolean = false,
        targetFps: Double = DEFAULT_BRIDGE_TARGET_FPS
    ) {
        if (!injectOperationRunning.compareAndSet(false, true)) {
            log.onLog("⚠️ 已有注入流程执行中（含目标进程轮询），跳过重复注入请求")
            return
        }
        val client = AdbClient(appContext)
        var fridaServerClient: AdbClient? = null
        var fridaServerStream: AdbShellStream? = null
        var fridaServerStreamJob: Job? = null
        val fridaServerStreamOutput = StringBuilder()
        var retainInjectingMarker = false
        val normalizedTargetFps = normalizeBridgeTargetFps(targetFps)
        val formattedTargetFps = formatBridgeTargetFps(normalizedTargetFps)
        val minIntervalMs = computeBridgeFrameIntervalMs(normalizedTargetFps)
        try {
            // 1. 连接
            log.onLog("⏳ 连接 ADB ($host:$port)...")
            client.connect(host, port)
            log.onLog("✅ ADB 已连接")
            log.onLog("🎯 本次 bridge 采集节流 targetFps=$formattedTargetFps minIntervalMs=$minIntervalMs")
            log.onLog("🧩 内置 Frida 二进制版本=$BUNDLED_FRIDA_BINARY_VERSION")
            markInjectingInProgress(client)
            log.onLog("ℹ️ 已写入注入中标记")

            // 2. 检查目标进程
            log.onLog("🔍 查找目标进程 $TARGET_PROCESS...")
            val pidLookup = findTargetPidWithRecovery(
                client = client,
                log = log,
                stageLabel = "初次查找目标进程",
                allowWakeUp = true
            )
            val pid = pidLookup?.pid
            if (pid == null) {
                log.onLog("❌ 目标进程 $TARGET_PROCESS 未运行，无法注入")
                explainMissingTargetProcess(client, log)
                return
            }
            var currentPid = pid
            if (pidLookup.source == "ps_fallback") {
                log.onLog("✅ 通过 ps 回退找到目标进程 PID=$currentPid（pidof 未命中）")
            } else {
                log.onLog("✅ 找到目标进程 PID=$currentPid")
            }

            val bridgeReadiness = readBridgeReadinessState(client)
            val entryDecision = decideInjectEntry(
                strictRestart = strictRestart,
                bridgeReady = bridgeReadiness.ready
            )
            if (entryDecision.shouldSkipBecauseSocketReady) {
                log.onLog("✅ bridge 已就绪（socket + stream_ready），跳过重复注入")
                val injectAtMs = System.currentTimeMillis()
                FridaInjectTimestampPreferences.setLastInjectAtMs(appContext, injectAtMs)
                FridaInjectTimestampPreferences.setLastInjectPid(appContext, currentPid)
                syncLastInjectMarker(client, injectAtMs)
                log.onLog("🕒 已刷新注入时间标记")
                return
            }
            if (strictRestart) {
                log.onLog("ℹ️ 本次注入启用 strict_restart，跳过 bridge ready / 重复注入短路")
                currentPid = prepareStrictReinject(client, currentPid, log) ?: run {
                    explainMissingTargetProcess(client, log)
                    return
                }
            }

            // 3. 基于时间戳的重复注入检测
            val nowMs = System.currentTimeMillis()
            val lastInjectAtMs = FridaInjectTimestampPreferences.getLastInjectAtMs(appContext)
            val lastInjectPid = FridaInjectTimestampPreferences.getLastInjectPid(appContext)

            if (entryDecision.shouldBypassDuplicateWindow) {
                if (lastInjectAtMs > 0) {
                    val elapsed = (nowMs - lastInjectAtMs).coerceAtLeast(0)
                    log.onLog("ℹ️ strict_restart 已绕过 60 秒重复注入窗口（距离上次 ${elapsed / 1000}s）")
                }
            } else if (lastInjectAtMs > 0) {
                val elapsed = (nowMs - lastInjectAtMs).coerceAtLeast(0)
                val duplicateDecision = decideDuplicateInjection(
                    lastInjectAtMs = lastInjectAtMs,
                    nowMs = nowMs,
                    bridgeSocketReady = bridgeReadiness.socketReady,
                    bridgeStreamReady = bridgeReadiness.streamReady,
                    lastInjectPid = lastInjectPid,
                    currentPid = currentPid
                )
                if (duplicateDecision.shouldSkip) {
                    log.onLog("⚠️ 检测到重复注入触发，距离上次注入仅 ${elapsed / 1000}s")
                    log.onLog("⏭️ 小于 60 秒窗口，直接跳过本次注入")
                    return
                }
                when (duplicateDecision.reason) {
                    "pid_changed" -> {
                        log.onLog(
                            "ℹ️ 距离上次注入 ${elapsed / 1000}s，但目标 PID 已变化 " +
                                "($lastInjectPid -> $currentPid)，忽略 60 秒窗口强制重注入"
                        )
                    }
                    "stream_not_ready" -> {
                        log.onLog(
                            "ℹ️ 距离上次注入 ${elapsed / 1000}s，bridge socket 已存在但 stream_ready 未达成，" +
                                "忽略 60 秒窗口强制重注入"
                        )
                    }
                    "socket_missing" -> {
                        log.onLog("ℹ️ 距离上次注入 ${elapsed / 1000}s，但 bridge socket 缺失，忽略 60 秒窗口强制重注入")
                    }
                    else -> {
                        log.onLog("ℹ️ 距离上次注入 ${elapsed / 1000}s，执行直接重注入（不重启目标进程）")
                    }
                }
            }

            // 4. 逐文件检查 & 版本比对（APK versionCode 一致则跳过，不一致或文件缺失则推送+MD5重试）
            log.onLog("📦 校验远程文件...")

            // 读取当前 APK versionCode 及远端已部署的版本号
            val currentVersionCode = try {
                val pm = appContext.packageManager
                val info = pm.getPackageInfo(appContext.packageName, 0)
                @Suppress("DEPRECATION")
                info.versionCode.toString()
            } catch (e: Exception) {
                Log.w(TAG, "getPackageInfo failed, fallback to '0'", e)
                "0"
            }
            val remoteVersionCode = client.executeShellCommand(
                "cat $REMOTE_DEPLOY_VERSION 2>/dev/null"
            ).trim()
            val versionMatch = remoteVersionCode == currentVersionCode
            val remoteFridaBundleVersion = client.executeShellCommand(
                "cat $REMOTE_FRIDA_BUNDLE_VERSION 2>/dev/null"
            ).trim().ifEmpty { null }
            val fridaBundleMatch = remoteFridaBundleVersion == BUNDLED_FRIDA_BINARY_VERSION
            if (versionMatch) {
                log.onLog("  ℹ️ 远端版本与当前 APK 一致（versionCode=$currentVersionCode），按需跳过")
            } else {
                val reason = if (remoteVersionCode.isEmpty()) "版本标记缺失" else "远端=$remoteVersionCode，当前=$currentVersionCode"
                log.onLog("  ⚠️ 版本不一致（$reason），将重新推送所有文件")
            }
            if (fridaBundleMatch) {
                log.onLog("  ℹ️ 远端 Frida 二进制 bundle 已匹配（$BUNDLED_FRIDA_BINARY_VERSION）")
            } else {
                val reason = if (remoteFridaBundleVersion.isNullOrBlank()) {
                    "bundle 标记缺失"
                } else {
                    "远端=$remoteFridaBundleVersion，当前=$BUNDLED_FRIDA_BINARY_VERSION"
                }
                log.onLog("  ⚠️ Frida 二进制 bundle 不一致（$reason），将重推 server/inject")
            }
            val localStageDir = ensureLocalStageDir()

            // frida-server
            val serverExists = remoteFileExists(client, REMOTE_FRIDA_SERVER)
            val reuseServerBinary = shouldReuseBundledFridaBinary(
                remoteExists = serverExists,
                remoteBundleVersion = remoteFridaBundleVersion
            )
            if (reuseServerBinary) {
                log.onLog("  ✅ frida-server 已就绪（bundle 一致）")
            } else {
                val localServerFile = File(localStageDir, LOCAL_STAGE_FRIDA_SERVER)
                decompressXzAssetToFile(ASSET_FRIDA_SERVER_XZ, localServerFile)
                val localServerMd5 = computeFileMd5(localServerFile)
                if (!serverExists) log.onLog("  📤 复制 frida-server（文件缺失，${localServerFile.length() / 1024 / 1024}MB）...")
                else log.onLog("  📤 重新复制 frida-server（bundle 变化，${localServerFile.length() / 1024 / 1024}MB）...")
                copyLocalAndVerify(client, localServerFile, REMOTE_FRIDA_SERVER, 493, localServerMd5, "frida-server", log)
            }

            // frida-inject
            val injectExists = remoteFileExists(client, REMOTE_FRIDA_INJECT)
            val reuseInjectBinary = shouldReuseBundledFridaBinary(
                remoteExists = injectExists,
                remoteBundleVersion = remoteFridaBundleVersion
            )
            if (reuseInjectBinary) {
                log.onLog("  ✅ frida-inject 已就绪（bundle 一致）")
            } else {
                val localInjectFile = File(localStageDir, LOCAL_STAGE_FRIDA_INJECT)
                decompressXzAssetToFile(ASSET_FRIDA_INJECT_XZ, localInjectFile)
                val localInjectMd5 = computeFileMd5(localInjectFile)
                if (!injectExists) log.onLog("  📤 复制 frida-inject（文件缺失）...")
                else log.onLog("  📤 重新复制 frida-inject（bundle 变化）...")
                copyLocalAndVerify(client, localInjectFile, REMOTE_FRIDA_INJECT, 493, localInjectMd5, "frida-inject", log)
            }

            // hook 脚本
            val localScriptFile = File(localStageDir, LOCAL_STAGE_HOOK_SCRIPT)
            renderHookScriptToFile(ASSET_HOOK_SCRIPT, localScriptFile, normalizedTargetFps)
            val localScriptMd5 = computeFileMd5(localScriptFile)
            val scriptExists = remoteFileExists(client, REMOTE_HOOK_SCRIPT)
            val remoteScriptMd5 = if (scriptExists) remoteFileMd5(client, REMOTE_HOOK_SCRIPT) else null
            val scriptUpToDate = scriptExists && remoteScriptMd5 == localScriptMd5
            if (scriptUpToDate) {
                log.onLog("  ✅ hook 脚本已就绪（targetFps=$formattedTargetFps）")
            } else {
                if (!scriptExists) {
                    log.onLog("  📤 复制 hook 脚本（文件缺失，targetFps=$formattedTargetFps）...")
                } else {
                    log.onLog("  📤 重新复制 hook 脚本（内容变化，targetFps=$formattedTargetFps）...")
                }
                copyLocalAndVerify(client, localScriptFile, REMOTE_HOOK_SCRIPT, 420, localScriptMd5, "hook 脚本", log)
            }

            // 所有文件就绪后，更新远端版本标记
            if (!versionMatch) {
                client.executeShellCommand("printf '%s' '$currentVersionCode' > $REMOTE_DEPLOY_VERSION")
                log.onLog("  📝 已更新远端版本标记（versionCode=$currentVersionCode）")
            }
            if (!fridaBundleMatch || !reuseServerBinary || !reuseInjectBinary) {
                syncFridaBundleVersionMarker(client)
                log.onLog("  📝 已更新远端 Frida bundle 标记（$BUNDLED_FRIDA_BINARY_VERSION）")
            }

            // 确保权限正确
            client.executeShellCommand("chmod 755 $REMOTE_FRIDA_SERVER $REMOTE_FRIDA_INJECT")

            // 5. 部署后校验：确认文件存在且可执行
            val serverExecOk = remoteFileExists(client, REMOTE_FRIDA_SERVER) &&
                remoteFileExecutable(client, REMOTE_FRIDA_SERVER)
            val injectExecOk = remoteFileExists(client, REMOTE_FRIDA_INJECT) &&
                remoteFileExecutable(client, REMOTE_FRIDA_INJECT)

            if (!serverExecOk || !injectExecOk) {
                log.onLog("❌ 文件部署校验失败，无法继续注入")
                val lsOut = client.executeShellCommand(
                    "ls -l $REMOTE_FRIDA_SERVER $REMOTE_FRIDA_INJECT 2>&1 || true"
                ).trim()
                if (lsOut.isNotEmpty()) {
                    log.onLog("📋 文件状态:\n$lsOut")
                }
                return
            }

            log.onLog("✅ 文件部署完成")

            // 6. 启动 frida-server（如果未运行）
            val serverRunningBeforeLaunch = isFridaServerRunning(client)
            val shouldRestartRunningServer = serverRunningBeforeLaunch && !fridaBundleMatch
            if (shouldRestartRunningServer) {
                log.onLog("🔄 检测到旧版 frida-server 正在运行，先回收后再加载 bundle=$BUNDLED_FRIDA_BINARY_VERSION")
                killProcessByName(client, "frida-server", "frida-server", log)
                if (waitForFridaServerStopped(client)) {
                    log.onLog("✅ 旧 frida-server 已退出")
                } else {
                    log.onLog("⚠️ 等待旧 frida-server 退出超时，继续尝试拉起新版本")
                }
            }
            if (!serverRunningBeforeLaunch || shouldRestartRunningServer) {
                log.onLog("🚀 启动 frida-server（托管模式，disable-preload）...")
                fridaServerClient = AdbClient(appContext).also { managedClient ->
                    managedClient.connect(host, port)
                    fridaServerStream = managedClient.openShellStream(
                        "echo ==== frida-server start ts=\$(date +%s%3N) ==== >> $REMOTE_FRIDA_SERVER_LOG; " +
                            "exec $REMOTE_FRIDA_SERVER --disable-preload -l 0.0.0.0 >> $REMOTE_FRIDA_SERVER_LOG 2>&1"
                    )
                    val stream = checkNotNull(fridaServerStream)
                    fridaServerStreamJob = CoroutineScope(Dispatchers.IO).launch {
                        runCatching {
                            stream.readLoop { chunk ->
                                synchronized(fridaServerStreamOutput) {
                                    appendTruncated(fridaServerStreamOutput, chunk)
                                }
                            }
                        }.onFailure { streamError ->
                            Log.w(TAG, "frida-server managed shell stream ended", streamError)
                        }
                    }
                }
                if (waitForFridaServerRunning(client)) {
                    log.onLog("✅ frida-server 已启动（前台托管中）")
                } else {
                    log.onLog("❌ frida-server 启动失败，停止后续注入")
                    val serverLog = readRemoteLogTail(client, REMOTE_FRIDA_SERVER_LOG)
                    if (serverLog.isNotBlank()) {
                        log.onLog("📋 frida-server 日志:\n${truncateForUi(serverLog)}")
                    }
                    val streamOutput = synchronized(fridaServerStreamOutput) {
                        fridaServerStreamOutput.toString().trim()
                    }
                    if (streamOutput.isNotBlank()) {
                        log.onLog("📋 托管 shell 输出:\n${truncateForUi(streamOutput)}")
                    }
                    return
                }
            } else {
                log.onLog("✅ frida-server 已在运行")
            }

            if (!ensureNoProtectedProcessFridaResidues(client, log, "注入前安全检查")) {
                return
            }

            ensureNoActiveManagedInjectSession(client, currentPid, log) ?: run {
                explainMissingTargetProcess(client, log)
                return
            }

            // 7. 注入前重启 inneravmservice，避免旧实例导致首帧迟迟不触发
            restartInnerAvmBeforeInject(client, log)

            // 8. 使用 frida-inject 注入脚本
            val freshPidLookup = findTargetPidWithRecovery(
                client = client,
                log = log,
                stageLabel = "注入前复查目标进程",
                allowWakeUp = true
            )
            val freshPid = freshPidLookup?.pid ?: run {
                log.onLog("❌ 目标进程已消失，无法注入")
                explainMissingTargetProcess(client, log)
                return
            }
            if (freshPidLookup.source == "ps_fallback") {
                log.onLog("ℹ️ 注入前目标 PID 由 ps 回退识别（pidof 未命中）")
            }
            log.onLog("💉 使用 frida-inject 注入到 PID=$freshPid...")
            log.onLog("ℹ️ 使用后台持有会话模式，禁用 eternalize 以避免污染 zygote/system_server")
            val injectStartMarker = startManagedFridaInjectSession(
                client = client,
                targetPid = freshPid,
                log = log
            ) ?: run {
                log.onLog("❌ 无法启动 frida-inject 后台会话")
                return
            }
            val (injectReady, injectLogWindow) = waitForManagedFridaInjectReady(
                client = client,
                log = log,
                startMarker = injectStartMarker
            )
            if (injectLogWindow.isNotEmpty()) {
                log.onLog("📋 frida-inject 输出:\n$injectLogWindow")
            }

            if (injectReady) {
                log.onLog("✅ 注入完成（后台会话持有中，脚本随 frida-inject 生命周期驻留）")

                // 10. 优先激活一次 360，再等待 bridge 就绪
                activateAvmViaActivity(client, log)

                // 11. 确认 bridge socket 就绪
                val bridgeReady = ensureBridgeSocketReadyAfterInject(client, log)

                if (bridgeReady) {
                    closeAvmAfterBridgeReady(client, log)
                    val injectAtMs = System.currentTimeMillis()
                    FridaInjectTimestampPreferences.setLastInjectAtMs(appContext, injectAtMs)
                    FridaInjectTimestampPreferences.setLastInjectPid(appContext, freshPid)
                    syncLastInjectMarker(client, injectAtMs)
                    log.onLog("🕒 已写入本次注入时间标记")
                } else {
                    retainInjectingMarker = true
                    log.onLog("⚠️ bridge 仍未就绪（socket + stream_ready 未同时满足），跳过收口并暂不写入注入时间标记，允许哨兵快速重试")
                }
            } else {
                cleanupAfterManagedInjectFailure(
                    client = client,
                    log = log,
                    reasonLabel = "注入失败收尾"
                )
                log.onLog("❌ 注入失败：后台会话未就绪或触发了系统进程污染守卫")
                return
            }

            log.onLog("🏁 注入流程完毕")

        } catch (e: Exception) {
            Log.e(TAG, "inject failed", e)
            log.onLog("❌ 错误: ${e.message}")
        } finally {
            runCatching { fridaServerStream?.close() }
            fridaServerStreamJob?.cancel()
            runCatching { fridaServerClient?.close() }
            if (!retainInjectingMarker) {
                runCatching { clearInjectingInProgressMarker(client) }
            }
            client.close()
            injectOperationRunning.set(false)
        }
    }

    /**
     * 还原注入状态：杀目标进程和 frida-inject、清理中间文件、保留 frida-server。
     *
     * @param host ADB 主机地址
     * @param port ADB 端口
     * @param log 日志回调
     */
    suspend fun restore(host: String, port: Int, log: LogCallback) {
        val client = AdbClient(appContext)
        try {
            log.onLog("⏳ 连接 ADB ($host:$port)...")
            client.connect(host, port)
            log.onLog("✅ ADB 已连接")

            restoreInjectedState(client, log)

            log.onLog("🏁 恢复流程完毕")

        } catch (e: Exception) {
            Log.e(TAG, "restore failed", e)
            log.onLog("❌ 错误: ${e.message}")
        } finally {
            client.close()
        }
    }

    /**
     * 还原注入状态的内部实现。
     *
     * 操作步骤：
     * 1. 杀死目标进程 avm3d_service（等待系统保活拉起干净实例）
     * 2. 杀死 frida-server 并删除其二进制文件
     * 3. 杀死 frida-inject 并删除其二进制文件
     * 4. 清理所有中间文件（脚本、日志、socket、时间标记）
     * 5. 清理本地注入时间标记
     * 6. 等待目标进程恢复
     */
    private suspend fun restoreInjectedState(client: AdbClient, log: LogCallback) {
        log.onLog("🔄 正在还原：杀死所有相关进程并清理所有远端文件...")

        for (target in buildInjectedProcessCleanupOrder(TARGET_PROCESS)) {
            killProcessByName(client, target.processName, target.displayName, log)
        }

        // 删除所有远端文件（包括二进制及部署版本标记）
        client.executeShellCommand(
            "rm -f $REMOTE_FRIDA_SERVER $REMOTE_FRIDA_INJECT " +
                "$REMOTE_HOOK_SCRIPT $REMOTE_DEPLOY_VERSION " +
                "$REMOTE_BRIDGE_SOCKET $REMOTE_STREAM_READY_MARKER " +
                    "$REMOTE_LAST_INJECT_MARKER $REMOTE_INJECTING_MARKER 2>/dev/null || true"
        )
        log.onLog("  ✅ 已删除所有远端文件（含 frida-server/frida-inject 二进制及部署版本标记）")

        // 清理本地注入时间标记
        FridaInjectTimestampPreferences.clear(appContext)
        log.onLog("  🕒 已清理注入时间标记")

        // 等待目标进程恢复
        delay(1000)
        val restartedPid = findTargetPid(client)
        if (restartedPid != null) {
            log.onLog("✅ 目标进程已恢复运行 (PID=$restartedPid)")
        } else {
            log.onLog("⚠️ 目标进程尚未恢复，等待系统拉起")
        }

        val residues = detectProtectedProcessFridaResidues(client)
        if (residues.isNotEmpty()) {
            log.onLog("⚠️ 恢复后仍检测到系统进程存在 Frida 残留，建议重启设备后再继续联调")
            residues.forEach { residue ->
                log.onLog("  • ${residue.processName} (PID=${residue.pid}) 命中 ${residue.evidence} 证据")
            }
        }
    }
}
