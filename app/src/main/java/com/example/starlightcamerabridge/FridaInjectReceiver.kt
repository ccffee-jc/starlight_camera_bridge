package com.example.starlightcamerabridge

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log
import com.example.starlightcamerabridge.adb.AdbConnectionPreferences
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import java.util.concurrent.atomic.AtomicBoolean

/**
 * 广播接收器，用于通过 ADB 命令触发 Frida 注入/恢复。
 *
 * 用法：
 *   注入：adb shell am broadcast -a com.example.starlightcamerabridge.ACTION_INJECT
 *   恢复：adb shell am broadcast -a com.example.starlightcamerabridge.ACTION_RESTORE
 */
class FridaInjectReceiver : BroadcastReceiver() {

    companion object {
        private const val TAG = "FridaInjectReceiver"
        const val ACTION_INJECT = "com.example.starlightcamerabridge.ACTION_INJECT"
        const val ACTION_RESTORE = "com.example.starlightcamerabridge.ACTION_RESTORE"
        private val operationRunning = AtomicBoolean(false)
    }

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    override fun onReceive(context: Context, intent: Intent) {
        val action = intent.action ?: return
        Log.i(TAG, "收到广播: $action")

        val appContext = context.applicationContext
        val host = intent.getStringExtra("host")
            ?: AdbConnectionPreferences.getHost(appContext)
        val port = intent.getStringExtra("port")?.toIntOrNull()
            ?: AdbConnectionPreferences.getPort(appContext)

        Log.i(TAG, "使用连接: $host:$port")

        val deployer = FridaDeployer(appContext)
        val logCallback = FridaDeployer.LogCallback { msg ->
            Log.i(TAG, msg)
        }

        when (action) {
            ACTION_INJECT -> {
                scope.launch {
                    if (!operationRunning.compareAndSet(false, true)) {
                        Log.w(TAG, "已有注入/恢复流程执行中，忽略重复注入广播")
                        return@launch
                    }
                    Log.i(TAG, "===== 开始注入 =====")
                    try {
                        deployer.inject(host, port, logCallback)
                    } finally {
                        operationRunning.set(false)
                        Log.i(TAG, "===== 注入流程结束 =====")
                    }
                }
            }
            ACTION_RESTORE -> {
                scope.launch {
                    if (!operationRunning.compareAndSet(false, true)) {
                        Log.w(TAG, "已有注入/恢复流程执行中，忽略恢复广播")
                        return@launch
                    }
                    Log.i(TAG, "===== 开始恢复 =====")
                    try {
                        deployer.restore(host, port, logCallback)
                    } finally {
                        operationRunning.set(false)
                        Log.i(TAG, "===== 恢复流程结束 =====")
                    }
                }
            }
        }
    }
}
