package pro.netcloud.trafficwrapper

import android.app.PendingIntent
import android.content.Context
import android.content.Intent

internal fun mainActivityLaunchPendingIntent(context: Context): PendingIntent {
    val intent = Intent(context, MainActivity::class.java)
        .addFlags(
            Intent.FLAG_ACTIVITY_NEW_TASK or
                Intent.FLAG_ACTIVITY_CLEAR_TOP or
                Intent.FLAG_ACTIVITY_SINGLE_TOP,
        )
    return PendingIntent.getActivity(
        context,
        MAIN_ACTIVITY_NOTIFICATION_REQUEST_CODE,
        intent,
        PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
    )
}

internal fun batteryHintPendingIntent(context: Context): PendingIntent {
    val intent = Intent(context, MainActivity::class.java)
        .setAction(ACTION_OPEN_BATTERY_HINT)
        .addFlags(
            Intent.FLAG_ACTIVITY_NEW_TASK or
                Intent.FLAG_ACTIVITY_CLEAR_TOP or
                Intent.FLAG_ACTIVITY_SINGLE_TOP,
        )
    return PendingIntent.getActivity(
        context,
        BATTERY_HINT_NOTIFICATION_REQUEST_CODE,
        intent,
        PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
    )
}

internal const val ACTION_OPEN_BATTERY_HINT = "pro.netcloud.trafficwrapper.action.OPEN_BATTERY_HINT"

private const val MAIN_ACTIVITY_NOTIFICATION_REQUEST_CODE = 1300
private const val BATTERY_HINT_NOTIFICATION_REQUEST_CODE = 1311
