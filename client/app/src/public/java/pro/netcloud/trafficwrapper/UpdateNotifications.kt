package pro.netcloud.trafficwrapper

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import androidx.annotation.StringRes

object UpdateNotifications {
    fun showDownloadProgress(context: Context, downloadedBytes: Long, totalBytes: Long) {
        val manager = manager(context)
        ensureChannel(context, manager)
        val notification = Notification.Builder(context, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle(context.getString(R.string.update_notification_title))
            .setContentText(context.getString(R.string.update_notification_downloading))
            .setOngoing(true)
            .apply {
                if (totalBytes > 0) {
                    setProgress(
                        (totalBytes / PROGRESS_SCALE).coerceAtLeast(1).toInt(),
                        (downloadedBytes / PROGRESS_SCALE).coerceAtLeast(0).toInt(),
                        false,
                    )
                } else {
                    setProgress(0, 0, true)
                }
            }
            .build()
        manager.notify(DOWNLOAD_NOTIFICATION_ID, notification)
    }

    fun showInstallStatus(context: Context, @StringRes textRes: Int) {
        val manager = manager(context)
        ensureChannel(context, manager)
        val notification = Notification.Builder(context, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle(context.getString(R.string.update_notification_title))
            .setContentText(context.getString(textRes))
            .setAutoCancel(true)
            .build()
        manager.notify(STATUS_NOTIFICATION_ID, notification)
    }

    fun clearDownload(context: Context) {
        manager(context).cancel(DOWNLOAD_NOTIFICATION_ID)
    }

    private fun ensureChannel(context: Context, manager: NotificationManager) {
        val channel = NotificationChannel(
            CHANNEL_ID,
            context.getString(R.string.update_notification_channel),
            NotificationManager.IMPORTANCE_LOW,
        )
        manager.createNotificationChannel(channel)
    }

    private fun manager(context: Context): NotificationManager =
        context.getSystemService(NotificationManager::class.java)

    private const val CHANNEL_ID = "updates"
    private const val DOWNLOAD_NOTIFICATION_ID = 1401
    private const val STATUS_NOTIFICATION_ID = 1402
    private const val PROGRESS_SCALE = 1024L
}
