package pro.trafficwrapper

import android.content.Context

object TransportLifecycleStore {
    private const val PREFS_NAME = "trafficwrapper_lifecycle"
    private const val KEY_KEEP_ALIVE = "keep_alive"
    private const val KEY_MODE = "mode"
    private const val KEY_BATTERY_HINT_DISMISSED = "battery_hint_dismissed"
    private const val KEY_OEM_BACKGROUND_HINT_DISMISSED = "oem_background_hint_dismissed"
    private const val KEY_OEM_HINT_ACKNOWLEDGED = "oem_hint_acknowledged"
    private const val KEY_BATTERY_RESTRICTED_LAST = "battery_restricted_last"
    private const val KEY_BATTERY_OPT_RESTRICTED_LAST = "battery_opt_restricted_last"
    private const val KEY_BATTERY_NOTIFICATION_SHOWN_AT_MS = "battery_notification_shown_at_ms"
    private const val KEY_TELEMETRY = "telemetry"
    private const val KEY_TELEMETRY_REMOTE_OFF = "telemetry_remote_off"

    fun rememberActiveTransport(context: Context, mode: TransportChoice) {
        prefs(context).edit()
            .putBoolean(KEY_KEEP_ALIVE, true)
            .putString(KEY_MODE, mode.name)
            .apply()
    }

    fun rememberStopped(context: Context) {
        prefs(context).edit()
            .putBoolean(KEY_KEEP_ALIVE, false)
            .apply()
    }

    fun shouldKeepAlive(context: Context): Boolean =
        prefs(context).getBoolean(KEY_KEEP_ALIVE, false)

    fun preferredMode(context: Context): TransportChoice =
        runCatching {
            TransportChoice.valueOf(
                prefs(context).getString(KEY_MODE, TransportChoice.AUTO.name) ?: TransportChoice.AUTO.name,
            )
        }.getOrDefault(TransportChoice.AUTO)

    fun batteryHintDismissed(context: Context): Boolean =
        prefs(context).getBoolean(KEY_BATTERY_HINT_DISMISSED, false)

    fun dismissBatteryHint(context: Context) {
        prefs(context).edit()
            .putBoolean(KEY_BATTERY_HINT_DISMISSED, true)
            .apply()
    }

    fun oemBackgroundHintDismissed(context: Context): Boolean =
        prefs(context).getBoolean(KEY_OEM_BACKGROUND_HINT_DISMISSED, false)

    fun dismissOemBackgroundHint(context: Context) {
        prefs(context).edit()
            .putBoolean(KEY_OEM_BACKGROUND_HINT_DISMISSED, true)
            .apply()
    }

    fun oemHintAcknowledged(context: Context): Boolean =
        prefs(context).getBoolean(KEY_OEM_HINT_ACKNOWLEDGED, false)

    fun acknowledgeOemHint(context: Context) {
        prefs(context).edit()
            .putBoolean(KEY_OEM_HINT_ACKNOWLEDGED, true)
            .apply()
    }

    fun lastBatteryRestricted(context: Context): Boolean =
        prefs(context).getBoolean(KEY_BATTERY_RESTRICTED_LAST, false)

    fun setLastBatteryRestricted(context: Context, restricted: Boolean) {
        prefs(context).edit()
            .putBoolean(KEY_BATTERY_RESTRICTED_LAST, restricted)
            .apply()
    }

    fun lastBatteryOptimizationRestricted(context: Context): Boolean =
        prefs(context).getBoolean(KEY_BATTERY_OPT_RESTRICTED_LAST, false)

    fun setLastBatteryOptimizationRestricted(context: Context, restricted: Boolean) {
        prefs(context).edit()
            .putBoolean(KEY_BATTERY_OPT_RESTRICTED_LAST, restricted)
            .apply()
    }

    fun shouldShowBatteryRestrictionNotification(context: Context, nowMs: Long): Boolean {
        val lastShownAtMs = prefs(context).getLong(KEY_BATTERY_NOTIFICATION_SHOWN_AT_MS, 0L)
        return lastShownAtMs <= 0L || nowMs - lastShownAtMs >= BATTERY_NOTIFICATION_MIN_INTERVAL_MS
    }

    fun markBatteryRestrictionNotificationShown(context: Context, nowMs: Long) {
        prefs(context).edit()
            .putLong(KEY_BATTERY_NOTIFICATION_SHOWN_AT_MS, nowMs)
            .apply()
    }

    fun telemetryEnabled(context: Context): Boolean =
        prefs(context).getBoolean(KEY_TELEMETRY, !DeploymentConfig.IS_PUBLIC_PLATFORM) &&
            !prefs(context).getBoolean(KEY_TELEMETRY_REMOTE_OFF, false) &&
            (if (DeploymentConfig.IS_PUBLIC_PLATFORM) {
                true
            } else {
                BuildConfig.TELEMETRY_ENDPOINT.isNotBlank() &&
                    System.currentTimeMillis() < BuildConfig.TELEMETRY_EXPIRY_UNIX_MS
            })

    fun setTelemetryEnabled(context: Context, on: Boolean) {
        val editor = prefs(context).edit()
            .putBoolean(KEY_TELEMETRY, on)
        if (on) {
            editor.remove(KEY_TELEMETRY_REMOTE_OFF)
        }
        editor.apply()
        if (!on) {
            Telemetry.clearLocal(context)
        }
    }

    fun telemetryRemoteOff(context: Context): Boolean =
        prefs(context).getBoolean(KEY_TELEMETRY_REMOTE_OFF, false)

    fun setTelemetryRemoteOff(context: Context, off: Boolean) {
        prefs(context).edit()
            .putBoolean(KEY_TELEMETRY_REMOTE_OFF, off)
            .apply()
        if (off) {
            Telemetry.clearLocal(context)
        }
    }

    private fun prefs(context: Context) =
        context.applicationContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    private const val BATTERY_NOTIFICATION_MIN_INTERVAL_MS = 24L * 60L * 60L * 1000L
}
