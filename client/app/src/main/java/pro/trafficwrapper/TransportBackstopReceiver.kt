package pro.trafficwrapper

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
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
        // A VPN lost to a process death (crash / system kill) is brought back here as well, not
        // only at boot. Failures are logged; the sticky restart and the next resume retry.
        runCatching { VpnAutoRestore.maybeRestoreWithTransport(context.applicationContext, "backstop") }
            .onFailure { Log.w(LOG_TAG, "backstop vpn restore failed: ${it.message}") }
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
                // Android 12+ refuses background foreground-service starts from an inexact alarm
                // (no exact-alarm permission, battery optimisation on). Nothing in the background
                // may start it then, so ask the user: opening the app restarts the transport.
                Log.w(LOG_TAG, "backstop cold start failed: ${it.message}")
                showColdStartBlockedNotification(context.applicationContext)
            }
        }
    }

    private fun showColdStartBlockedNotification(context: Context) {
        runCatching {
            val manager = context.getSystemService(NotificationManager::class.java) ?: return
            manager.createNotificationChannel(
                NotificationChannel(
                    SERVICE_ALERT_CHANNEL_ID,
                    context.getString(R.string.service_alert_channel),
                    NotificationManager.IMPORTANCE_DEFAULT,
                ),
            )
            val text = context.getString(R.string.service_alert_tunnel_text)
            val notification = Notification.Builder(context, SERVICE_ALERT_CHANNEL_ID)
                .setSmallIcon(R.drawable.ic_notification)
                .setContentTitle(context.getString(R.string.service_alert_tunnel_title))
                .setContentText(text)
                .setStyle(Notification.BigTextStyle().bigText(text))
                .setContentIntent(mainActivityLaunchPendingIntent(context))
                .setAutoCancel(true)
                .build()
            manager.notify(SERVICE_TUNNEL_DOWN_NOTIFICATION_ID, notification)
        }.onFailure {
            Log.w(LOG_TAG, "backstop notification failed: ${it.message}")
        }
    }

    private companion object {
        private const val LOG_TAG = "TWBackstopReceiver"
        private const val SERVICE_ALERT_CHANNEL_ID = "service-alerts"

        // Same id as AutoTransportService's tunnel-down alert: one "not carrying traffic" alert.
        private const val SERVICE_TUNNEL_DOWN_NOTIFICATION_ID = 1313
    }
}
