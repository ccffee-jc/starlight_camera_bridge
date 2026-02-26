package com.example.starlightcamerabridge.helper

import android.content.Context
import android.util.Log
import com.example.starlightcamerabridge.adb.AdbClient
import com.example.starlightcamerabridge.adb.AdbConnectionPreferences
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import java.security.MessageDigest

/**
 * Root Helper 二进制部署器。
 *
 * 从 APK assets 推送 avm_root_helper 到 /data/local/tmp/，
 * 使用 MD5 校验避免重复部署，然后启动 helper 进程。
 */
class RootHelperDeployer(private val context: Context) {

    companion object {
        private const val TAG = "RootHelperDeployer"
        private const val ASSET_HELPER = "root/avm_root_helper"
        private const val ADB_HOST = "127.0.0.1"
    }

    fun interface LogCallback {
        fun onLog(message: String)
    }

    sealed class DeployResult {
        object Success : DeployResult()
        object AlreadyRunning : DeployResult()
        data class Error(val message: String) : DeployResult()
    }

    /**
     * 部署并启动 avm_root_helper 完整流程。
     *
     * @param host ADB 主机
     * @param port ADB 端口
     * @param forceUyvy 是否强制 UYVY 格式
     * @param log 日志回调
     */
    suspend fun deployAndStart(
        host: String,
        port: Int,
        forceUyvy: Boolean = false,
        log: LogCallback
    ): DeployResult = withContext(Dispatchers.IO) {
        val client = AdbClient(context)
        try {
            // 1. 连接 ADB
            log.onLog("⏳ 连接 ADB ($host:$port)...")
            client.connect(host, port)
            log.onLog("✅ ADB 已连接")

            // 2. 检查是否已在运行
            val runningPid = client.executeShellCommand(RootHelperCommands.checkRunning()).trim()
            if (runningPid.isNotEmpty()) {
                log.onLog("✅ avm_root_helper 已在运行 (PID=$runningPid)")
                return@withContext DeployResult.AlreadyRunning
            }

            // 3. 部署二进制文件
            log.onLog("📦 检查 helper 二进制...")
            val needDeploy = deployIfNeeded(client, log)

            // 4. 清理并启动
            log.onLog("🧹 清理旧状态...")
            client.executeShellCommand(RootHelperCommands.killHelper())
            delay(500)
            client.executeShellCommand(RootHelperCommands.clearStopFlag())
            client.executeShellCommand(RootHelperCommands.cleanupSocket())

            log.onLog("🚀 启动 avm_root_helper...")
            client.executeShellCommand(RootHelperCommands.startHelper(forceUyvy))
            delay(2000)

            // 5. 验证启动
            val pid = client.executeShellCommand(RootHelperCommands.checkRunning()).trim()
            if (pid.isEmpty()) {
                val helperLog = client.executeShellCommand(RootHelperCommands.tailLog(10)).trim()
                log.onLog("❌ helper 启动失败，日志:\n$helperLog")
                return@withContext DeployResult.Error("helper 未能启动")
            }

            log.onLog("✅ avm_root_helper 已启动 (PID=$pid)")

            // 6. 等待 socket 文件创建
            log.onLog("⏳ 等待 socket 就绪...")
            var socketReady = false
            for (i in 1..10) {
                val exists = client.executeShellCommand(
                    "test -S ${RootHelperCommands.SOCKET_PATH} && echo YES || echo NO"
                ).trim()
                if (exists.contains("YES")) {
                    socketReady = true
                    break
                }
                delay(500)
            }

            if (!socketReady) {
                log.onLog("⚠️ Socket 文件尚未创建，helper 可能还在等待 vcapserver 连接")
            } else {
                log.onLog("✅ Socket 就绪: ${RootHelperCommands.SOCKET_PATH}")
            }

            log.onLog("🏁 部署完成")
            DeployResult.Success

        } catch (e: Exception) {
            Log.e(TAG, "deploy failed", e)
            log.onLog("❌ 错误: ${e.message}")
            DeployResult.Error(e.message ?: "未知错误")
        } finally {
            client.close()
        }
    }

    /**
     * 停止 avm_root_helper（优雅停止 + 强制杀死）。
     */
    suspend fun stop(host: String, port: Int, log: LogCallback) = withContext(Dispatchers.IO) {
        val client = AdbClient(context)
        try {
            log.onLog("⏳ 连接 ADB...")
            client.connect(host, port)

            // 先写停止标志（优雅）
            log.onLog("🛑 发送停止信号...")
            client.executeShellCommand(RootHelperCommands.writeStopFlag())
            delay(2000)

            // 检查是否已停止
            val pid = client.executeShellCommand(RootHelperCommands.checkRunning()).trim()
            if (pid.isNotEmpty()) {
                log.onLog("⚠️ 优雅停止超时，强制杀死...")
                client.executeShellCommand(RootHelperCommands.killHelper())
                delay(500)
            }

            // 清理
            client.executeShellCommand(RootHelperCommands.cleanupSocket())
            client.executeShellCommand(RootHelperCommands.clearStopFlag())
            log.onLog("✅ avm_root_helper 已停止")

        } catch (e: Exception) {
            log.onLog("❌ 停止失败: ${e.message}")
        } finally {
            client.close()
        }
    }

    // ========== 内部方法 ==========

    /**
     * 如果设备上的 helper 版本与 assets 不一致则重新部署。
     *
     * @return true=已重新部署, false=跳过
     */
    private suspend fun deployIfNeeded(client: AdbClient, log: LogCallback): Boolean {
        // 读取 asset
        val assetBytes = try {
            context.assets.open(ASSET_HELPER).use { it.readBytes() }
        } catch (e: Exception) {
            log.onLog("⚠️ assets 中无 helper 二进制: ${e.message}")
            // 检查设备上是否已有
            val check = client.executeShellCommand(RootHelperCommands.checkBinary()).trim()
            if (check.contains("exists")) {
                log.onLog("  ✅ 使用设备上已有版本")
                return false
            }
            throw Exception("assets 无 helper 且设备上也不存在")
        }

        val localMd5 = md5(assetBytes)
        log.onLog("  📋 本地 MD5=$localMd5 (${assetBytes.size} bytes)")

        // 设备上的 MD5
        val deviceMd5 = client.executeShellCommand(
            "md5sum ${RootHelperCommands.HELPER_PATH} 2>/dev/null"
        ).trim().split("\\s+".toRegex()).firstOrNull() ?: ""

        if (localMd5 == deviceMd5 && deviceMd5.isNotEmpty()) {
            log.onLog("  ✅ MD5 一致，跳过部署")
            return false
        }

        // 需要推送
        log.onLog("  📤 推送 helper (${assetBytes.size} bytes)...")
        client.pushFileViaShell(assetBytes, RootHelperCommands.HELPER_PATH, mode = 493) // 0755
        client.executeShellCommand("chmod 755 ${RootHelperCommands.HELPER_PATH}")

        // 验证
        val uploadedMd5 = client.executeShellCommand(
            "md5sum ${RootHelperCommands.HELPER_PATH} 2>/dev/null"
        ).trim().split("\\s+".toRegex()).firstOrNull() ?: ""

        if (uploadedMd5 != localMd5) {
            throw Exception("部署后 MD5 不匹配: 预期=$localMd5, 实际=$uploadedMd5")
        }

        log.onLog("  ✅ 部署完成，MD5 校验通过")
        return true
    }

    private fun md5(bytes: ByteArray): String {
        val digest = MessageDigest.getInstance("MD5")
        return digest.digest(bytes).joinToString("") { "%02x".format(it) }
    }
}
