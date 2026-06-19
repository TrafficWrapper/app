package pro.trafficwrapper

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Build
import android.util.Log

class TransportBackstopReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent?) {
        if (intent?.action != AutoTransportService.ACTION_BACKSTOP) return
        if (!TransportLifecycleStore.shouldKeepAlive(context)) return
        AutoTransportService.scheduleBackstopAlarm(context)
        if (!AutoTransportService.requestBackstopResync(context)) {
            Log.w(LOG_TAG, "backstop cold start: active transport worker is not running")
            val serviceIntent = Intent(context, AutoTransportService::class.java)
                .setAction(AutoTransportService.ACTION_BACKSTOP)
                .putExtra(AutoTransportService.EXTRA_MODE, TransportLifecycleStore.preferredMode(context).name)
            runCatching {
                if (Build.VERSION.SDK_INT >= 26) {
                    context.startForegroundService(serviceIntent)
                } else {
                    context.startService(serviceIntent)
                }
            }.onFailure {
                Log.w(LOG_TAG, "backstop cold start failed: ${it.message}")
            }
        }
    }

    private companion object {
        private const val LOG_TAG = "TWBackstopReceiver"
    }
}
