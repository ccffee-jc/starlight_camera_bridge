package com.example.starlightcamerabridge

import android.content.Context

internal object BridgeTargetFpsPreferences {
    private const val PREFS_NAME = "bridge_target_fps_prefs"
    private const val KEY_TARGET_FPS = "target_fps"

    fun load(context: Context): Double {
        val stored = context.applicationContext
            .getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .getString(KEY_TARGET_FPS, null)
            ?.toDoubleOrNull()
        return normalizeBridgeTargetFps(stored ?: DEFAULT_BRIDGE_TARGET_FPS)
    }

    fun save(context: Context, targetFps: Double) {
        context.applicationContext
            .getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .edit()
            .putString(KEY_TARGET_FPS, formatBridgeTargetFps(targetFps))
            .apply()
    }
}
