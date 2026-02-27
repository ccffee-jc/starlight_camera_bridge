package com.example.starlightcamerabridge

import android.content.Context
import android.content.SharedPreferences

/**
 * 记录最近一次 Frida 注入的时间戳，用于重复注入跳过判断和主工程节流基准读取。
 */
object FridaInjectTimestampPreferences {

    private const val PREFS = "frida_inject_timestamp_prefs"
    private const val KEY_LAST_INJECT_AT_MS = "last_inject_at_ms"
    private const val KEY_LAST_INJECT_PID = "last_inject_pid"

    private fun prefs(context: Context): SharedPreferences =
        context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    fun getLastInjectAtMs(context: Context): Long =
        prefs(context).getLong(KEY_LAST_INJECT_AT_MS, 0L)

    fun setLastInjectAtMs(context: Context, timestampMs: Long) {
        prefs(context).edit().putLong(KEY_LAST_INJECT_AT_MS, timestampMs).apply()
    }

    fun getLastInjectPid(context: Context): String? =
        prefs(context).getString(KEY_LAST_INJECT_PID, null)
            ?.trim()
            ?.takeIf { it.isNotEmpty() }

    fun setLastInjectPid(context: Context, pid: String) {
        prefs(context).edit().putString(KEY_LAST_INJECT_PID, pid).apply()
    }

    fun clear(context: Context) {
        prefs(context).edit()
            .remove(KEY_LAST_INJECT_AT_MS)
            .remove(KEY_LAST_INJECT_PID)
            .apply()
    }
}
