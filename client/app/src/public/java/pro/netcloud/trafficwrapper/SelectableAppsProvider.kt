package pro.netcloud.trafficwrapper

import android.content.Context
import android.content.pm.LauncherApps
import android.os.Process
import java.util.Locale

internal fun loadSelectableApps(context: Context): List<InstalledAppInfo> {
    val launcherApps = context.getSystemService(LauncherApps::class.java) ?: return fallbackTelegram()
    val density = context.resources.displayMetrics.densityDpi
    val activities = runCatching {
        launcherApps.getActivityList(null, Process.myUserHandle())
    }.getOrElse {
        return fallbackTelegram()
    }
    val apps = activities
        .distinctBy { it.applicationInfo.packageName }
        .map { activity ->
            val packageName = activity.applicationInfo.packageName
            InstalledAppInfo(
                packageName = packageName,
                label = activity.label?.toString().orEmpty().ifBlank { packageName },
                support = supportForPackage(packageName),
                icon = runCatching { activity.getIcon(density) }.getOrNull(),
            )
        }
        .sortedWith(compareBy<InstalledAppInfo> { supportOrder(it.support) }.thenBy { it.label.lowercase(Locale.ROOT) })
    return apps.ifEmpty { fallbackTelegram() }
}

private fun fallbackTelegram(): List<InstalledAppInfo> =
    listOf(
        InstalledAppInfo(
            packageName = TELEGRAM_PACKAGE,
            label = "Telegram",
            support = ProxySupport.AUTO_TELEGRAM,
            icon = null,
        ),
    )
