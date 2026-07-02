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
    private const val KEY_HTTP_PROXY = "http_proxy"
    private const val KEY_DIRECT_UPDATE_FALLBACK = "direct_update_fallback"
    private const val KEY_DISCOVERY_SUBSCRIPTION = "discovery_subscription"
    private const val KEY_SERVICE_NOTIFICATIONS = "service_notifications"
    private const val KEY_SERVICE_NOTIFICATION_TUNNEL_AT = "service_notification_tunnel_at"
    private const val KEY_SERVICE_NOTIFICATION_APPROVAL_AT = "service_notification_approval_at"
    private const val KEY_SERVICE_NOTIFICATION_QUOTA_AT = "service_notification_quota_at"
    private const val KEY_VPN = "vpn"
    private const val KEY_VPN_MODE = "vpn_mode"
    private const val KEY_VPN_ALLOWED_APPS = "vpn_allowed_apps"
    private const val KEY_VPN_KILL_SWITCH = "vpn_kill_switch"
    private const val KEY_VPN_LAST_UDP_ROUTE = "vpn_last_udp_route"

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

    fun httpProxyEnabled(context: Context): Boolean =
        httpProxyPreference(
            if (prefs(context).contains(KEY_HTTP_PROXY)) {
                prefs(context).getBoolean(KEY_HTTP_PROXY, false)
            } else {
                null
            },
        )

    fun setHttpProxyEnabled(context: Context, on: Boolean) {
        prefs(context).edit()
            .putBoolean(KEY_HTTP_PROXY, on)
            .apply()
    }

    fun directUpdateFallbackEnabled(context: Context): Boolean =
        directUpdateFallbackPreference(
            if (prefs(context).contains(KEY_DIRECT_UPDATE_FALLBACK)) {
                prefs(context).getBoolean(KEY_DIRECT_UPDATE_FALLBACK, false)
            } else {
                null
            },
        )

    fun setDirectUpdateFallbackEnabled(context: Context, on: Boolean) {
        prefs(context).edit()
            .putBoolean(KEY_DIRECT_UPDATE_FALLBACK, on)
            .apply()
    }

    fun discoverySubscriptionEnabled(context: Context): Boolean =
        discoverySubscriptionPreference(
            if (prefs(context).contains(KEY_DISCOVERY_SUBSCRIPTION)) {
                prefs(context).getBoolean(KEY_DISCOVERY_SUBSCRIPTION, false)
            } else {
                null
            },
        )

    fun setDiscoverySubscriptionEnabled(context: Context, on: Boolean) {
        prefs(context).edit()
            .putBoolean(KEY_DISCOVERY_SUBSCRIPTION, on)
            .apply()
    }

    fun serviceNotificationsEnabled(context: Context): Boolean =
        serviceNotificationsPreference(
            if (prefs(context).contains(KEY_SERVICE_NOTIFICATIONS)) {
                prefs(context).getBoolean(KEY_SERVICE_NOTIFICATIONS, true)
            } else {
                null
            },
        )

    fun setServiceNotificationsEnabled(context: Context, on: Boolean) {
        prefs(context).edit()
            .putBoolean(KEY_SERVICE_NOTIFICATIONS, on)
            .apply()
    }

    fun shouldShowServiceNotification(context: Context, kind: ServiceNotificationKind, nowMs: Long): Boolean {
        val shownAt = prefs(context).getLong(serviceNotificationKey(kind), 0L)
        return shouldShowServiceNotificationAt(shownAt, nowMs, SERVICE_NOTIFICATION_MIN_INTERVAL_MS)
    }

    fun markServiceNotificationShown(context: Context, kind: ServiceNotificationKind, nowMs: Long) {
        prefs(context).edit()
            .putLong(serviceNotificationKey(kind), nowMs)
            .apply()
    }

    fun vpnEnabled(context: Context): Boolean =
        vpnPreference(
            if (prefs(context).contains(KEY_VPN)) {
                prefs(context).getBoolean(KEY_VPN, false)
            } else {
                null
            },
        )

    fun setVpnEnabled(context: Context, on: Boolean) {
        prefs(context).edit()
            .putBoolean(KEY_VPN, on)
            .apply()
    }

    fun vpnMode(context: Context): VpnTrafficMode =
        VpnTrafficMode.fromWireName(prefs(context).getString(KEY_VPN_MODE, null))

    fun setVpnMode(context: Context, mode: VpnTrafficMode) {
        prefs(context).edit()
            .putString(KEY_VPN_MODE, mode.wireName)
            .apply()
    }

    fun vpnAllowedApps(context: Context): Set<String> {
        val stored = prefs(context).getStringSet(KEY_VPN_ALLOWED_APPS, null)
        return vpnAllowedAppsPreference(stored)
    }

    fun setVpnAllowedApps(context: Context, packages: Set<String>) {
        prefs(context).edit()
            .putStringSet(
                KEY_VPN_ALLOWED_APPS,
                packages
                    .map { it.trim() }
                    .filter { it.isNotBlank() }
                    .toSortedSet(),
            )
            .apply()
    }

    fun vpnKillSwitchEnabled(context: Context): Boolean =
        vpnKillSwitchPreference(
            if (prefs(context).contains(KEY_VPN_KILL_SWITCH)) {
                prefs(context).getBoolean(KEY_VPN_KILL_SWITCH, true)
            } else {
                null
            },
        )

    fun setVpnKillSwitchEnabled(context: Context, on: Boolean) {
        prefs(context).edit()
            .putBoolean(KEY_VPN_KILL_SWITCH, on)
            .apply()
    }

    fun lastVpnUdpRoute(context: Context): String =
        prefs(context).getString(KEY_VPN_LAST_UDP_ROUTE, "")?.trim().orEmpty()

    fun setLastVpnUdpRoute(context: Context, route: String) {
        prefs(context).edit()
            .putString(KEY_VPN_LAST_UDP_ROUTE, route.trim())
            .apply()
    }

    private fun prefs(context: Context) =
        context.applicationContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    private fun serviceNotificationKey(kind: ServiceNotificationKind): String =
        when (kind) {
            ServiceNotificationKind.TUNNEL_DOWN -> KEY_SERVICE_NOTIFICATION_TUNNEL_AT
            ServiceNotificationKind.APPROVAL_REQUIRED -> KEY_SERVICE_NOTIFICATION_APPROVAL_AT
            ServiceNotificationKind.QUOTA_LOW -> KEY_SERVICE_NOTIFICATION_QUOTA_AT
        }

    private const val BATTERY_NOTIFICATION_MIN_INTERVAL_MS = 24L * 60L * 60L * 1000L
    private const val SERVICE_NOTIFICATION_MIN_INTERVAL_MS = 6L * 60L * 60L * 1000L
}

internal fun httpProxyPreference(stored: Boolean?): Boolean = stored ?: false

internal fun directUpdateFallbackPreference(stored: Boolean?): Boolean = stored ?: false

internal fun discoverySubscriptionPreference(stored: Boolean?): Boolean = stored ?: false

internal fun serviceNotificationsPreference(stored: Boolean?): Boolean = stored ?: true

internal fun shouldShowServiceNotificationAt(lastShownAtMs: Long, nowMs: Long, minIntervalMs: Long): Boolean =
    lastShownAtMs <= 0L || nowMs - lastShownAtMs >= minIntervalMs

enum class ServiceNotificationKind {
    TUNNEL_DOWN,
    APPROVAL_REQUIRED,
    QUOTA_LOW,
}

enum class VpnTrafficMode(val wireName: String) {
    FULL("full"),
    SPLIT("split"),
    ;

    companion object {
        fun fromWireName(value: String?): VpnTrafficMode =
            entries.firstOrNull { it.wireName == value } ?: FULL
    }
}

internal fun vpnPreference(stored: Boolean?): Boolean = stored ?: false

internal fun vpnKillSwitchPreference(stored: Boolean?): Boolean = stored ?: true

internal fun vpnAllowedAppsPreference(stored: Set<String>?): Set<String> =
    stored
        ?.map { it.trim() }
        ?.filter { it.isNotBlank() }
        ?.toSortedSet()
        ?: setOf(TELEGRAM_PACKAGE)
