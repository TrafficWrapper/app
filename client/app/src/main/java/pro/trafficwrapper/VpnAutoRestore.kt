package pro.trafficwrapper

import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.util.Log

internal object VpnAutoRestore {
    fun preferenceEnabled(context: Context): Boolean =
        BuildConfig.VPN_ENABLED && TransportLifecycleStore.vpnEnabled(context.applicationContext)

    fun maybeRestore(context: Context, reason: String): Boolean {
        val appContext = context.applicationContext
        val state = TransportRuntime.state
        if (!shouldAttemptVpnAutoRestore(
                vpnFeatureEnabled = BuildConfig.VPN_ENABLED,
                vpnPreferenceEnabled = TransportLifecycleStore.vpnEnabled(appContext),
                vpnActive = state.vpnActive,
                vpnTransition = state.vpnTransition,
            )
        ) {
            return false
        }
        if (VpnService.prepare(appContext) != null) {
            Log.i(LOG_TAG, "vpn auto-restore deferred: permission required reason=$reason")
            TransportRuntime.state = TransportRuntime.state.copy(
                vpnEnabled = true,
                vpnActive = false,
                vpnTransition = VpnTransition.NONE,
            )
            return false
        }
        TransportRuntime.state = TransportRuntime.state.copy(
            vpnEnabled = true,
            vpnTransition = VpnTransition.STARTING,
        )
        startVpnService(appContext)
        Log.i(LOG_TAG, "vpn auto-restore requested: reason=$reason")
        return true
    }

    fun startVpnService(context: Context) {
        if (!BuildConfig.VPN_ENABLED) return
        val intent = vpnServiceIntent(context.applicationContext, ACTION_VPN_START)
        if (Build.VERSION.SDK_INT >= 26) {
            context.applicationContext.startForegroundService(intent)
        } else {
            context.applicationContext.startService(intent)
        }
    }

    private fun vpnServiceIntent(context: Context, action: String): Intent =
        Intent(action).setClassName(context.packageName, TW_VPN_SERVICE_CLASS)

    private const val LOG_TAG = "TWVpnRestore"
    private const val TW_VPN_SERVICE_CLASS = "pro.trafficwrapper.TwVpnService"
    private const val ACTION_VPN_START = "pro.trafficwrapper.action.VPN_START"
}

internal fun shouldAttemptVpnAutoRestore(
    vpnFeatureEnabled: Boolean,
    vpnPreferenceEnabled: Boolean,
    vpnActive: Boolean,
    vpnTransition: VpnTransition = VpnTransition.NONE,
): Boolean = vpnFeatureEnabled &&
    vpnPreferenceEnabled &&
    !vpnActive &&
    vpnTransition == VpnTransition.NONE
