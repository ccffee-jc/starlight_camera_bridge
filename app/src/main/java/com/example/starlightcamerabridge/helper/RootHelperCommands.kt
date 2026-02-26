package com.example.starlightcamerabridge.helper

/**
 * Root Helper 路径常量与命令模板。
 *
 * avm_root_helper 以 root 身份运行在目标设备上，
 * 连接 vcapserver 并向 App 透传 dmabuf fd。
 */
object RootHelperCommands {

    const val TARGET_DIR   = "/data/local/tmp"
    const val HELPER_PATH  = "$TARGET_DIR/avm_root_helper"
    const val SOCKET_PATH  = "$TARGET_DIR/avm_helper.sock"
    const val TAG_PATH     = "$TARGET_DIR/avm_helper.tag"
    const val STOP_PATH    = "$TARGET_DIR/avm_helper.stop"
    const val LOG_PATH     = "$TARGET_DIR/avm_root_helper.log"
    const val VCAP_SOCKET  = "/data/system/avm_svr"

    /** 检查 helper 进程是否在运行 */
    fun checkRunning(): String =
        "pidof avm_root_helper 2>/dev/null || true"

    /** 检查 helper 二进制文件是否存在 */
    fun checkBinary(): String =
        "test -x $HELPER_PATH && echo exists || echo missing"

    /** 清除停止标志 */
    fun clearStopFlag(): String =
        "rm -f $STOP_PATH"

    /** 写入停止标志（优雅停止） */
    fun writeStopFlag(): String =
        "echo stop > $STOP_PATH"

    /** 清理旧 socket 文件 */
    fun cleanupSocket(): String =
        "rm -f $SOCKET_PATH 2>/dev/null || true"

    /**
     * 启动 helper 进程。
     *
     * @param forceUyvy 是否强制 UYVY 格式
     */
    fun startHelper(forceUyvy: Boolean = false): String {
        val forceFlag = if (forceUyvy) " --force-uyvy" else ""
        return "( $HELPER_PATH" +
                " --vcap $VCAP_SOCKET" +
                " --socket $SOCKET_PATH" +
                " --tag $TAG_PATH" +
                " --stop $STOP_PATH" +
                " --cmd 0 --param 0" +
                " --video-cmd 5 --video-param 1" +
                " --timeout-ms 8000" +
                "$forceFlag" +
                " </dev/null >$LOG_PATH 2>&1 & ) &"
    }

    /** 强制杀死 helper 进程 */
    fun killHelper(): String =
        "pkill -f avm_root_helper 2>/dev/null || true"

    /** 获取 helper 日志末尾 */
    fun tailLog(lines: Int = 20): String =
        "tail -n $lines $LOG_PATH 2>/dev/null || echo '(no log)'"

    /** 获取 tag 文件（存活检测） */
    fun readTag(): String =
        "cat $TAG_PATH 2>/dev/null || echo '0'"
}
