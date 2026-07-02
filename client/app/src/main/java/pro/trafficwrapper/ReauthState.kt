package pro.trafficwrapper

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.util.Log

internal fun isDeviceNotApprovedMessage(value: String?): Boolean =
    value
        ?.lowercase()
        ?.let { text ->
            text.contains("device is not approved") || text.contains("device_not_approved")
        } == true

internal fun isExplicitDeviceNotApprovedResponse(httpCode: Int, body: String): Boolean =
    httpCode == 403 && isDeviceNotApprovedMessage(body)

internal fun reauthRequiredAuthState(current: AuthUiState): AuthUiState =
    current.copy(
        authorized = false,
        inProgress = false,
        statusTextRes = R.string.enrollment_status_pending,
        errorTextRes = null,
        message = "",
    )

internal fun markPublicDeviceReauthRequired(context: Context, reason: String) {
    if (!DeploymentConfig.IS_PUBLIC_PLATFORM) return
    val appContext = context.applicationContext
    TransportRuntime.auth = reauthRequiredAuthState(TransportRuntime.auth)
    TransportRuntime.state = TransportRuntime.state.copy(
        handshakeEstablished = false,
        tunnelStable = false,
        carryingTransport = "",
        stateTextRes = R.string.state_idle,
    )
    Log.w(REAUTH_LOG_TAG, "public device authorization revoked by orchestrator: $reason")
    showReauthNotification(appContext)
}

private fun showReauthNotification(context: Context) {
    if (!TransportLifecycleStore.serviceNotificationsEnabled(context)) return
    val nowMs = System.currentTimeMillis()
    if (!TransportLifecycleStore.shouldShowServiceNotification(
            context,
            ServiceNotificationKind.APPROVAL_REQUIRED,
            nowMs,
        )
    ) {
        return
    }
    runCatching {
        val manager = context.getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(
            NotificationChannel(
                SERVICE_ALERT_CHANNEL_ID,
                context.getString(R.string.service_alert_channel),
                NotificationManager.IMPORTANCE_DEFAULT,
            ),
        )
        val text = context.getString(R.string.service_alert_approval_text)
        val notification = Notification.Builder(context, SERVICE_ALERT_CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle(context.getString(R.string.service_alert_approval_title))
            .setContentText(text)
            .setStyle(Notification.BigTextStyle().bigText(text))
            .setContentIntent(mainActivityLaunchPendingIntent(context))
            .setAutoCancel(true)
            .build()
        manager.notify(SERVICE_APPROVAL_REQUIRED_NOTIFICATION_ID, notification)
        TransportLifecycleStore.markServiceNotificationShown(
            context,
            ServiceNotificationKind.APPROVAL_REQUIRED,
            nowMs,
        )
    }.onFailure {
        Log.w(REAUTH_LOG_TAG, "reauth notification failed: ${it.message}")
    }
}

private const val REAUTH_LOG_TAG = "TWReauth"
private const val SERVICE_ALERT_CHANNEL_ID = "service-alerts"
private const val SERVICE_APPROVAL_REQUIRED_NOTIFICATION_ID = 1314
