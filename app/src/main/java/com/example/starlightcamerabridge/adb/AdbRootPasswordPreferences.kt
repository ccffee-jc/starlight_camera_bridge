package com.example.starlightcamerabridge.adb

import android.content.Context
import android.content.SharedPreferences

/**
 * ADB Root 提权密码的本地持久化配置。
 */
object AdbRootPasswordPreferences {

    private const val PREFS = "adb_root_password_prefs"
    private const val KEY_PASSWORD = "adb_root_password"
    private const val DEFAULT_PASSWORD = "sgmw**HK_305"

    private fun appContext(context: Context): Context = context.applicationContext

    private fun deviceProtectedContext(context: Context): Context =
        appContext(context).createDeviceProtectedStorageContext()

    private fun deviceProtectedPrefs(context: Context): SharedPreferences =
        deviceProtectedContext(context).getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    private fun legacyPrefs(context: Context): SharedPreferences =
        appContext(context).getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    /**
     * 获取已保存的提权密码。
     *
     * @param context Android 上下文
     * @return 提权密码，未设置时返回默认密码
     */
    fun getPassword(context: Context): String =
        resolvePassword(
            deviceProtectedPassword = readDeviceProtectedPassword(context),
            legacyPassword = readLegacyPassword(context)
        )

    /**
     * 保存提权密码。
     *
     * @param context Android 上下文
     * @param password 待保存的提权密码
     */
    fun setPassword(context: Context, password: String) {
        deviceProtectedPrefs(context).edit().putString(KEY_PASSWORD, password).commit()
    }

    /**
     * 清除已保存的提权密码。
     *
     * @param context Android 上下文
     */
    fun clearPassword(context: Context) {
        deviceProtectedPrefs(context).edit().remove(KEY_PASSWORD).commit()
    }

    internal fun migrateLegacyValueIfNeeded(context: Context): Boolean {
        val devicePrefs = deviceProtectedPrefs(context)
        if (devicePrefs.contains(KEY_PASSWORD)) return false

        safeMoveToDeviceProtectedStorage(context)
        if (devicePrefs.contains(KEY_PASSWORD)) {
            return true
        }

        val legacyPassword = readLegacyPassword(context)
        if (!shouldMigrateLegacyValue(devicePrefs.contains(KEY_PASSWORD), legacyPassword != null)) {
            return false
        }

        devicePrefs.edit().putString(KEY_PASSWORD, legacyPassword ?: DEFAULT_PASSWORD).commit()
        return true
    }

    internal fun shouldMigrateLegacyValue(deviceProtectedHasValue: Boolean, legacyHasValue: Boolean): Boolean =
        !deviceProtectedHasValue && legacyHasValue

    internal fun resolvePassword(deviceProtectedPassword: String?, legacyPassword: String?): String =
        deviceProtectedPassword?.takeIf { it.isNotBlank() }
            ?: legacyPassword?.takeIf { it.isNotBlank() }
            ?: DEFAULT_PASSWORD

    private fun safeMoveToDeviceProtectedStorage(context: Context) {
        runCatching {
            deviceProtectedContext(context).moveSharedPreferencesFrom(appContext(context), PREFS)
        }
    }

    private fun readDeviceProtectedPassword(context: Context): String? {
        migrateLegacyValueIfNeeded(context)
        val prefs = deviceProtectedPrefs(context)
        return if (prefs.contains(KEY_PASSWORD)) prefs.getString(KEY_PASSWORD, null) else null
    }

    private fun readLegacyPassword(context: Context): String? {
        return runCatching {
            val prefs = legacyPrefs(context)
            if (!prefs.contains(KEY_PASSWORD)) null else prefs.getString(KEY_PASSWORD, null)
        }.getOrNull()
    }
}
