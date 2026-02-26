package com.example.starlightcamerabridge.adb

import android.content.Context

/**
 * ADB 连接参数（Host / Port）的本地持久化配置。
 */
object AdbConnectionPreferences {

    private const val PREFS = "adb_connection_prefs"
    private const val KEY_HOST = "adb_host"
    private const val KEY_PORT = "adb_port"

    private const val DEFAULT_HOST = "127.0.0.1"
    private const val DEFAULT_PORT = 5557

    private fun prefs(context: Context) =
        context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    /**
     * 获取已保存的 ADB Host。
     */
    fun getHost(context: Context): String =
        prefs(context).getString(KEY_HOST, DEFAULT_HOST) ?: DEFAULT_HOST

    /**
     * 获取已保存的 ADB Port。
     */
    fun getPort(context: Context): Int =
        prefs(context).getInt(KEY_PORT, DEFAULT_PORT)

    /**
     * 保存 ADB 连接参数。
     */
    fun save(context: Context, host: String, port: Int) {
        prefs(context).edit()
            .putString(KEY_HOST, host)
            .putInt(KEY_PORT, port)
            .apply()
    }
}
