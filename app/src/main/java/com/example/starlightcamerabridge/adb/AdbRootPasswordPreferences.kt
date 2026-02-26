package com.example.starlightcamerabridge.adb

import android.content.Context

/**
 * ADB Root 提权密码的本地持久化配置。
 */
object AdbRootPasswordPreferences {

    private const val PREFS = "adb_root_password_prefs"
    private const val KEY_PASSWORD = "adb_root_password"
    private const val DEFAULT_PASSWORD = "sgmw**HK_305"

    private fun prefs(context: Context) =
        context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    /**
     * 获取已保存的提权密码。
     *
     * @param context Android 上下文
     * @return 提权密码，未设置时返回默认密码
     */
    fun getPassword(context: Context): String =
        prefs(context).getString(KEY_PASSWORD, null)
            ?.takeIf { it.isNotBlank() }
            ?: DEFAULT_PASSWORD

    /**
     * 保存提权密码。
     *
     * @param context Android 上下文
     * @param password 待保存的提权密码
     */
    fun setPassword(context: Context, password: String) {
        prefs(context).edit().putString(KEY_PASSWORD, password).apply()
    }

    /**
     * 清除已保存的提权密码。
     *
     * @param context Android 上下文
     */
    fun clearPassword(context: Context) {
        prefs(context).edit().remove(KEY_PASSWORD).apply()
    }
}
