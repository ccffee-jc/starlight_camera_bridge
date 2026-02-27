package com.example.starlightcamerabridge.adb

import android.content.Context

/**
 * ADB Root 命令包装器：优先复用 adbd root，必要时回退 su -p 提权，并提供日志脱敏字符串。
 */
object AdbRootShell {

    data class RootCommand(
        val raw: String,
        val logSafe: String
    )

    /**
     * 根据开关与密码包装提权命令。
     *
     * 执行策略：
     * 1. 若当前 adb shell 已是 root（id -u = 0），直接执行原始命令；
     * 2. 否则回退为 su -p 提权执行。
     *
     * @param command 原始命令
     * @param enableRoot 是否启用提权
     * @param password 提权密码
     * @return 提权包装后的命令与脱敏日志串
     */
    fun wrapCommandWithPassword(command: String, enableRoot: Boolean, password: String): RootCommand {
        if (!enableRoot) return RootCommand(command, command)
        val trimmed = password.trim()
        if (trimmed.isBlank()) return RootCommand(command, command)
        val escapedCmd = escapeSingleQuotes(command)
        val escapedPwd = escapeSingleQuotes(trimmed)
        val raw =
            "if [ \"\$(id -u 2>/dev/null)\" = \"0\" ]; then sh -c '$escapedCmd'; " +
                "else su -p '$escapedPwd' 0 sh -c '$escapedCmd'; fi"
        val logSafe =
            "if [ \"\$(id -u 2>/dev/null)\" = \"0\" ]; then sh -c '$escapedCmd'; " +
                "else su -p '***' 0 sh -c '$escapedCmd'; fi"
        return RootCommand(raw, logSafe)
    }

    /**
     * 从配置读取提权开关与密码后包装命令。
     *
     * @param context Android 上下文
     * @param command 原始命令
     * @return 提权包装后的命令与脱敏日志串
     */
    fun wrapIfEnabled(context: Context, command: String): RootCommand {
        val password = AdbRootPasswordPreferences.getPassword(context)
        return wrapCommandWithPassword(command, true, password)
    }

    /**
     * 转义单引号，避免 shell 命令拼接被截断。
     *
     * @param command 原始命令
     * @return 转义后的命令字符串
     */
    fun escapeSingleQuotes(command: String): String {
        return command.replace("'", "'\''")
    }
}
