package com.example.starlightcamerabridge.adb

import android.content.Context
import android.content.SharedPreferences

/**
 * ADB 连接参数（Host / Port）的本地持久化配置。
 */
object AdbConnectionPreferences {

    private const val PREFS = "adb_connection_prefs"
    private const val KEY_HOST = "adb_host"
    private const val KEY_PORT = "adb_port"

    private const val DEFAULT_HOST = "127.0.0.1"
    private const val DEFAULT_PORT = 5557

    private fun appContext(context: Context): Context = context.applicationContext

    private fun deviceProtectedContext(context: Context): Context =
        appContext(context).createDeviceProtectedStorageContext()

    private fun deviceProtectedPrefs(context: Context): SharedPreferences =
        deviceProtectedContext(context).getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    private fun legacyPrefs(context: Context): SharedPreferences =
        appContext(context).getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    /**
     * 获取已保存的 ADB Host。
     */
    fun getHost(context: Context): String =
        resolveHost(
            deviceProtectedHost = readDeviceProtectedHost(context),
            legacyHost = readLegacyHost(context)
        )

    /**
     * 获取已保存的 ADB Port。
     */
    fun getPort(context: Context): Int =
        resolvePort(
            deviceProtectedPort = readDeviceProtectedPort(context),
            legacyPort = readLegacyPort(context)
        )

    /**
     * 保存 ADB 连接参数。
     */
    fun save(context: Context, host: String, port: Int) {
        deviceProtectedPrefs(context).edit()
            .putString(KEY_HOST, host)
            .putInt(KEY_PORT, port)
            .commit()
    }

    internal fun migrateLegacyValueIfNeeded(context: Context): Boolean {
        val devicePrefs = deviceProtectedPrefs(context)
        if (devicePrefs.contains(KEY_HOST) || devicePrefs.contains(KEY_PORT)) return false

        safeMoveToDeviceProtectedStorage(context)
        if (devicePrefs.contains(KEY_HOST) || devicePrefs.contains(KEY_PORT)) {
            return true
        }

        val legacyHost = readLegacyHost(context)
        val legacyPort = readLegacyPort(context)
        if (!shouldMigrateLegacyValue(devicePrefs.contains(KEY_HOST) || devicePrefs.contains(KEY_PORT), legacyHost != null || legacyPort != null)) {
            return false
        }

        devicePrefs.edit()
            .putString(KEY_HOST, legacyHost ?: DEFAULT_HOST)
            .putInt(KEY_PORT, legacyPort ?: DEFAULT_PORT)
            .commit()
        return true
    }

    internal fun shouldMigrateLegacyValue(deviceProtectedHasValue: Boolean, legacyHasValue: Boolean): Boolean =
        !deviceProtectedHasValue && legacyHasValue

    internal fun resolveHost(deviceProtectedHost: String?, legacyHost: String?): String =
        (deviceProtectedHost ?: legacyHost)?.takeIf { it.isNotBlank() } ?: DEFAULT_HOST

    internal fun resolvePort(deviceProtectedPort: Int?, legacyPort: Int?): Int {
        val port = deviceProtectedPort ?: legacyPort ?: DEFAULT_PORT
        return if (port in 1..65535) port else DEFAULT_PORT
    }

    private fun safeMoveToDeviceProtectedStorage(context: Context) {
        runCatching {
            deviceProtectedContext(context).moveSharedPreferencesFrom(appContext(context), PREFS)
        }
    }

    private fun readDeviceProtectedHost(context: Context): String? {
        migrateLegacyValueIfNeeded(context)
        val prefs = deviceProtectedPrefs(context)
        return if (prefs.contains(KEY_HOST)) prefs.getString(KEY_HOST, DEFAULT_HOST) else null
    }

    private fun readDeviceProtectedPort(context: Context): Int? {
        migrateLegacyValueIfNeeded(context)
        val prefs = deviceProtectedPrefs(context)
        return if (prefs.contains(KEY_PORT)) prefs.getInt(KEY_PORT, DEFAULT_PORT) else null
    }

    private fun readLegacyHost(context: Context): String? {
        return runCatching {
            val prefs = legacyPrefs(context)
            if (!prefs.contains(KEY_HOST)) null else prefs.getString(KEY_HOST, DEFAULT_HOST)
        }.getOrNull()
    }

    private fun readLegacyPort(context: Context): Int? {
        return runCatching {
            val prefs = legacyPrefs(context)
            if (!prefs.contains(KEY_PORT)) null else prefs.getInt(KEY_PORT, DEFAULT_PORT)
        }.getOrNull()
    }
}
