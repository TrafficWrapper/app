package pro.netcloud.trafficwrapper

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Build
import android.util.Log

class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent?) {
        val action = intent?.action ?: return
        if (action != Intent.ACTION_BOOT_COMPLETED && action != Intent.ACTION_MY_PACKAGE_REPLACED) return
        if (!TransportLifecycleStore.shouldKeepAlive(context)) {
            Log.i(LOG_TAG, "autostart skipped: action=$action keepAlive=false")
            return
        }
        val mode = TransportLifecycleStore.preferredMode(context).name
        val serviceIntent = Intent(context, AutoTransportService::class.java)
            .setAction(AutoTransportService.ACTION_START)
            .putExtra(AutoTransportService.EXTRA_MODE, mode)
        runCatching {
            if (Build.VERSION.SDK_INT >= 26) {
                context.startForegroundService(serviceIntent)
            } else {
                context.startService(serviceIntent)
            }
            Log.i(LOG_TAG, "autostart requested: action=$action mode=$mode")
        }.onFailure {
            Log.w(LOG_TAG, "autostart failed: action=$action message=${it.message}")
        }
    }

    private companion object {
        private const val LOG_TAG = "TWBootReceiver"
    }
}
