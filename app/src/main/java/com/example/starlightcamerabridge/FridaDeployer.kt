package com.example.starlightcamerabridge

import android.content.Context
import android.util.Log
import com.example.starlightcamerabridge.adb.AdbClient
import com.example.starlightcamerabridge.adb.AdbRootShell
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import org.tukaani.xz.XZInputStream
import java.io.File
import java.io.IOException
import java.util.concurrent.atomic.AtomicBoolean

/**
 * 重复注入跳过窗口（毫秒）。
 * 距离上次成功注入在此窗口内的新注入请求将被直接跳过。
 */
internal const val DUPLICATE_INJECT_SKIP_WINDOW_MS = 60000L

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

internal fun decideDuplicateInjection(
    lastInjectAtMs: Long,
    nowMs: Long,
    bridgeSocketReady: Boolean,
    lastInjectPid: String?,
    currentPid: String
): DuplicateInjectDecision {
    if (!shouldSkipDuplicateInjection(lastInjectAtMs, nowMs)) {
        return DuplicateInjectDecision(
            shouldSkip = false,
            reason = "outside_window"
        )
    }
    if (bridgeSocketReady) {
        return DuplicateInjectDecision(
            shouldSkip = true,
            reason = "socket_ready"
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
        const val REMOTE_BRIDGE_SOCKET = "$REMOTE_TMP/starlight_bridge.sock"
        const val REMOTE_LAST_INJECT_MARKER = "$REMOTE_TMP/starlight_bridge_last_inject_ms"
        const val REMOTE_INJECTING_MARKER = "$REMOTE_TMP/starlight_bridge_injecting"
        /** 远端部署版本标记文件，内容为推送时的 APK versionCode */
        const val REMOTE_DEPLOY_VERSION = "$REMOTE_TMP/starlight_bridge_deploy.version"

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
        val out = client.executeShellCommand("pidof frida-server 2>/dev/null").trim()
        return out.isNotEmpty()
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
     * 检测 bridge socket 是否已就绪。
     * 同时检查文件存在性和 /proc/net/unix 中的实际监听状态。
     */
    private suspend fun isBridgeSocketReady(client: AdbClient): Boolean {
        val out = client.executeShellCommand(
            "if [ -S $REMOTE_BRIDGE_SOCKET ] && grep -F \" $REMOTE_BRIDGE_SOCKET\" /proc/net/unix >/dev/null 2>&1; then echo YES; else echo NO; fi"
        ).trim()
        return out.contains("YES")
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
        log: LogCallback
    ): String? {
        log.onLog("🔁 重复注入：先重启目标进程 $TARGET_PROCESS (PID=$oldPid)")
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
    private suspend fun waitBridgeSocketReady(client: AdbClient, timeoutMs: Long): Boolean {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            if (isBridgeSocketReady(client)) return true
            delay(BRIDGE_READY_WAIT_POLL_MS)
        }
        return false
    }

    /**
     * 注入后确保 bridge socket 就绪。
     *
     * 先等待一轮，若未就绪则通过补偿激活 Activity 重试。
     *
     * @return true = bridge socket 已就绪
     */
    private suspend fun ensureBridgeSocketReadyAfterInject(
        client: AdbClient,
        log: LogCallback
    ): Boolean {
        // 第一轮：等待 BRIDGE_READY_WAIT_TIMEOUT_MS
        if (waitBridgeSocketReady(client, BRIDGE_READY_WAIT_TIMEOUT_MS)) {
            log.onLog("✅ bridge socket 已就绪")
            return true
        }

        // 补偿重试
        for (i in 0 until BRIDGE_READY_WAKE_RETRY_COUNT) {
            val attempt = i + 1
            log.onLog("⚠️ bridge socket 未就绪，尝试补偿激活 360（$attempt/$BRIDGE_READY_WAKE_RETRY_COUNT）")
            activateAvmViaActivity(client, log)
            if (waitBridgeSocketReady(client, BRIDGE_READY_WAIT_RETRY_TIMEOUT_MS)) {
                log.onLog("✅ bridge socket 已就绪（补偿激活后）")
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

    // ========== 核心操作 ==========

    /**
     * 完整注入流程：重复注入检测 → 部署文件 → 启动 frida-server → frida-inject 注入 → bridge 就绪检测。
     *
     * @param host ADB 主机地址
     * @param port ADB 端口
     * @param log 日志回调
     */
    suspend fun inject(host: String, port: Int, log: LogCallback) {
        if (!injectOperationRunning.compareAndSet(false, true)) {
            log.onLog("⚠️ 已有注入流程执行中（含目标进程轮询），跳过重复注入请求")
            return
        }
        val client = AdbClient(appContext)
        var retainInjectingMarker = false
        try {
            // 1. 连接
            log.onLog("⏳ 连接 ADB ($host:$port)...")
            client.connect(host, port)
            log.onLog("✅ ADB 已连接")
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
            if (pidLookup.source == "ps_fallback") {
                log.onLog("✅ 通过 ps 回退找到目标进程 PID=$pid（pidof 未命中）")
            } else {
                log.onLog("✅ 找到目标进程 PID=$pid")
            }

            val bridgeSocketReady = isBridgeSocketReady(client)
            if (bridgeSocketReady) {
                log.onLog("✅ bridge socket 已就绪，跳过重复注入")
                val injectAtMs = System.currentTimeMillis()
                FridaInjectTimestampPreferences.setLastInjectAtMs(appContext, injectAtMs)
                FridaInjectTimestampPreferences.setLastInjectPid(appContext, pid)
                syncLastInjectMarker(client, injectAtMs)
                log.onLog("🕒 已刷新注入时间标记")
                return
            }

            // 3. 基于时间戳的重复注入检测
            val nowMs = System.currentTimeMillis()
            val lastInjectAtMs = FridaInjectTimestampPreferences.getLastInjectAtMs(appContext)
            val lastInjectPid = FridaInjectTimestampPreferences.getLastInjectPid(appContext)

            if (lastInjectAtMs > 0) {
                val elapsed = (nowMs - lastInjectAtMs).coerceAtLeast(0)
                val duplicateDecision = decideDuplicateInjection(
                    lastInjectAtMs = lastInjectAtMs,
                    nowMs = nowMs,
                    bridgeSocketReady = bridgeSocketReady,
                    lastInjectPid = lastInjectPid,
                    currentPid = pid
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
                                "($lastInjectPid -> $pid)，忽略 60 秒窗口强制重注入"
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
            if (versionMatch) {
                log.onLog("  ℹ️ 远端版本与当前 APK 一致（versionCode=$currentVersionCode），按需跳过")
            } else {
                val reason = if (remoteVersionCode.isEmpty()) "版本标记缺失" else "远端=$remoteVersionCode，当前=$currentVersionCode"
                log.onLog("  ⚠️ 版本不一致（$reason），将重新推送所有文件")
            }
            val localStageDir = ensureLocalStageDir()

            // frida-server
            val serverExists = remoteFileExists(client, REMOTE_FRIDA_SERVER)
            if (serverExists && versionMatch) {
                log.onLog("  ✅ frida-server 已就绪（版本一致）")
            } else {
                val localServerFile = File(localStageDir, LOCAL_STAGE_FRIDA_SERVER)
                decompressXzAssetToFile(ASSET_FRIDA_SERVER_XZ, localServerFile)
                val localServerMd5 = computeFileMd5(localServerFile)
                if (!serverExists) log.onLog("  📤 复制 frida-server（文件缺失，${localServerFile.length() / 1024 / 1024}MB）...")
                else log.onLog("  📤 重新复制 frida-server（版本变更，${localServerFile.length() / 1024 / 1024}MB）...")
                copyLocalAndVerify(client, localServerFile, REMOTE_FRIDA_SERVER, 493, localServerMd5, "frida-server", log)
            }

            // frida-inject
            val injectExists = remoteFileExists(client, REMOTE_FRIDA_INJECT)
            if (injectExists && versionMatch) {
                log.onLog("  ✅ frida-inject 已就绪（版本一致）")
            } else {
                val localInjectFile = File(localStageDir, LOCAL_STAGE_FRIDA_INJECT)
                decompressXzAssetToFile(ASSET_FRIDA_INJECT_XZ, localInjectFile)
                val localInjectMd5 = computeFileMd5(localInjectFile)
                if (!injectExists) log.onLog("  📤 复制 frida-inject（文件缺失）...")
                else log.onLog("  📤 重新复制 frida-inject（版本变更）...")
                copyLocalAndVerify(client, localInjectFile, REMOTE_FRIDA_INJECT, 493, localInjectMd5, "frida-inject", log)
            }

            // hook 脚本
            val localScriptFile = File(localStageDir, LOCAL_STAGE_HOOK_SCRIPT)
            copyAssetToFile(ASSET_HOOK_SCRIPT, localScriptFile)
            val localScriptMd5 = computeFileMd5(localScriptFile)
            val scriptExists = remoteFileExists(client, REMOTE_HOOK_SCRIPT)
            if (scriptExists && versionMatch) {
                log.onLog("  ✅ hook 脚本已就绪（版本一致）")
            } else {
                if (!scriptExists) log.onLog("  📤 复制 hook 脚本（文件缺失）...")
                else log.onLog("  📤 重新复制 hook 脚本（版本变更）...")
                copyLocalAndVerify(client, localScriptFile, REMOTE_HOOK_SCRIPT, 420, localScriptMd5, "hook 脚本", log)
            }

            // 所有文件就绪后，更新远端版本标记
            if (!versionMatch) {
                client.executeShellCommand("printf '%s' '$currentVersionCode' > $REMOTE_DEPLOY_VERSION")
                log.onLog("  📝 已更新远端版本标记（versionCode=$currentVersionCode）")
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
            if (!isFridaServerRunning(client)) {
                log.onLog("🚀 启动 frida-server...")
                client.executeShellCommand("$REMOTE_FRIDA_SERVER -l 0.0.0.0 -D")
                delay(2000)
                if (isFridaServerRunning(client)) {
                    log.onLog("✅ frida-server 已启动")
                } else {
                    log.onLog("⚠️ frida-server 可能未正常启动，继续尝试注入...")
                }
            } else {
                log.onLog("✅ frida-server 已在运行")
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
            val injectOutput = client.executeShellCommand(
                "$REMOTE_FRIDA_INJECT -p $freshPid -s $REMOTE_HOOK_SCRIPT -e " +
                    "> $REMOTE_TMP/frida_inject.log 2>&1; echo __RC:\$?"
            )
            delay(1000)

            // 9. 验证注入结果
            val injectLog = client.executeShellCommand("cat $REMOTE_TMP/frida_inject.log 2>/dev/null").trim()
            if (injectLog.isNotEmpty()) {
                log.onLog("📋 frida-inject 输出:\n$injectLog")
            }

            // 解析退出码
            val rcLine = injectOutput.lineSequence().firstOrNull { it.contains("__RC:") }
            val exitCode = rcLine ?: ""
            val isRcZero = exitCode.contains("__RC:0")
            val errorKeywords = listOf(
                "not found", "No such file", "Permission denied",
                "Exec format error", "unable to connect", "failed"
            )
            val hasError = errorKeywords.any { injectLog.contains(it, ignoreCase = true) }

            if (isRcZero && !hasError) {
                log.onLog("✅ 注入完成（eternalize 模式，脚本已常驻目标进程）")

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
                    log.onLog("⚠️ bridge socket 仍未就绪，跳过收口并暂不写入注入时间标记，允许哨兵快速重试")
                }
            } else {
                val displayExit = exitCode.ifBlank { "unknown" }
                log.onLog("❌ 注入失败（exit=$displayExit）")
                return
            }

            log.onLog("🏁 注入流程完毕")

        } catch (e: Exception) {
            Log.e(TAG, "inject failed", e)
            log.onLog("❌ 错误: ${e.message}")
        } finally {
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

        // 杀死目标进程
        val targetPids = client.executeShellCommand("pidof $TARGET_PROCESS 2>/dev/null").trim()
        if (targetPids.isNotEmpty()) {
            client.executeShellCommand("kill -9 $targetPids 2>/dev/null || true")
            log.onLog("  ✅ 已杀死目标进程 $TARGET_PROCESS (PID=$targetPids)")
        } else {
            log.onLog("  ℹ️ 目标进程 $TARGET_PROCESS 未运行")
        }

        // 杀死 frida-server
        val serverPid = client.executeShellCommand("pidof frida-server 2>/dev/null").trim()
        if (serverPid.isNotEmpty()) {
            client.executeShellCommand("kill -9 $serverPid 2>/dev/null || true")
            log.onLog("  ✅ 已杀死 frida-server (PID=$serverPid)")
        } else {
            log.onLog("  ℹ️ frida-server 未运行")
        }

        // 杀死 frida-inject
        val injectPid = client.executeShellCommand("pidof frida-inject 2>/dev/null").trim()
        if (injectPid.isNotEmpty()) {
            client.executeShellCommand("kill -9 $injectPid 2>/dev/null || true")
            log.onLog("  ✅ 已杀死 frida-inject (PID=$injectPid)")
        }

        // 删除所有远端文件（包括二进制及部署版本标记）
        client.executeShellCommand(
            "rm -f $REMOTE_FRIDA_SERVER $REMOTE_FRIDA_INJECT " +
                "$REMOTE_HOOK_SCRIPT $REMOTE_DEPLOY_VERSION " +
                "$REMOTE_TMP/frida_inject.log " +
                "$REMOTE_BRIDGE_SOCKET $REMOTE_LAST_INJECT_MARKER $REMOTE_INJECTING_MARKER 2>/dev/null || true"
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
    }
}
