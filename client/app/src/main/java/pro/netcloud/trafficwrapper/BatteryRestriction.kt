package pro.netcloud.trafficwrapper

import android.app.ActivityManager
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.PowerManager
import android.provider.Settings
import android.util.Log
import android.widget.Toast
import java.util.Locale

data class BatteryRestrictionState(
    val restricted: Boolean = false,
    val batteryOptimizationRestricted: Boolean = false,
    val backgroundRestricted: Boolean = false,
    val oemHintNeeded: Boolean = false,
    val oemMakerKey: String = OEM_MAKER_GENERIC,
)

data class OemBatteryGuide(
    val makerKey: String,
    val body: String,
)

internal fun refreshBatteryRestrictionRuntime(context: Context) {
    val appContext = context.applicationContext
    val state = currentBatteryRestrictionState(appContext)
    val previouslyBatteryRestricted = TransportLifecycleStore.lastBatteryOptimizationRestricted(appContext)
    TransportRuntime.batteryRestriction = state
    if (previouslyBatteryRestricted && !state.batteryOptimizationRestricted) {
        sendBatteryHintTelemetry(
            appContext,
            BATTERY_HINT_ACTION_GRANTED,
            restricted = state.restricted,
            oem = state.oemMakerKey,
        )
    }
    if (!state.restricted) {
        BatteryRestrictionNotifier.cancel(appContext)
    }
    TransportLifecycleStore.setLastBatteryRestricted(appContext, state.restricted)
    TransportLifecycleStore.setLastBatteryOptimizationRestricted(appContext, state.batteryOptimizationRestricted)
}

internal fun currentBatteryRestrictionState(context: Context): BatteryRestrictionState {
    val appContext = context.applicationContext
    val batteryRestricted = runCatching {
        appContext.getSystemService(PowerManager::class.java)
            ?.isIgnoringBatteryOptimizations(appContext.packageName) != true
    }.getOrDefault(true)
    val backgroundRestricted = runCatching {
        Build.VERSION.SDK_INT >= 28 &&
            appContext.getSystemService(ActivityManager::class.java)?.isBackgroundRestricted == true
    }.getOrDefault(false)
    return batteryRestrictionStateFromSignals(
        batteryRestricted = batteryRestricted,
        backgroundRestricted = backgroundRestricted,
        manufacturer = Build.MANUFACTURER,
        brand = Build.BRAND,
        oemHintAcknowledged = TransportLifecycleStore.oemHintAcknowledged(appContext),
    )
}

internal fun openBatteryRestrictionFlow(context: Context) {
    val appContext = context.applicationContext
    val state = currentBatteryRestrictionState(appContext)
    sendBatteryHintTelemetry(
        appContext,
        BATTERY_HINT_ACTION_TAPPED,
        restricted = state.restricted,
        oem = state.oemMakerKey,
    )
    if (BuildConfig.FLAVOR == PRIVATE_FLAVOR && state.batteryOptimizationRestricted) {
        requestBatteryOptimizationExemption(appContext)
    }
    TransportRuntime.showBatteryGuide = true
}

internal fun oemBatteryGuide(): OemBatteryGuide {
    return oemBatteryGuideFor(oemMakerKey(Build.MANUFACTURER, Build.BRAND))
}

internal fun oemBatteryGuideFor(makerKey: String): OemBatteryGuide =
    when (makerKey) {
        OEM_MAKER_HUAWEI -> OemBatteryGuide(
            makerKey = OEM_MAKER_HUAWEI,
            body = "Huawei/Honor (EMUI):\n\n" +
                "1. Настройки -> Батарея -> Запуск приложений -> TrafficWrapper -> " +
                "выключить «Управлять автоматически» -> включить «Автозапуск», " +
                "«Косвенный запуск» и «Работа в фоне».\n\n" +
                "2. Настройки -> Приложения -> TrafficWrapper -> Батарея -> «Не ограничивать».",
        )
        OEM_MAKER_SAMSUNG -> OemBatteryGuide(
            makerKey = OEM_MAKER_SAMSUNG,
            body = "Samsung/One UI:\n\n" +
                "Настройки -> Приложения -> TrafficWrapper -> Батарея -> выберите " +
                "«Без ограничений» или включите «Разрешить фоновую активность».\n\n" +
                "Также проверьте: Настройки -> Батарея -> Ограничения фонового использования -> " +
                "уберите TrafficWrapper из спящих и глубоко спящих приложений.",
        )
        OEM_MAKER_XIAOMI -> OemBatteryGuide(
            makerKey = OEM_MAKER_XIAOMI,
            body = "Xiaomi/Redmi/POCO:\n\n" +
                "Настройки -> Приложения -> TrafficWrapper -> Экономия батареи -> " +
                "«Нет ограничений». Затем включите автозапуск для TrafficWrapper.",
        )
        OEM_MAKER_OPPO -> OemBatteryGuide(
            makerKey = OEM_MAKER_OPPO,
            body = "OPPO/Realme/OnePlus:\n\n" +
                "Настройки -> Батарея -> Управление батареей приложения -> TrafficWrapper -> " +
                "разрешите фоновую активность и автозапуск, отключите оптимизацию батареи для приложения.",
        )
        OEM_MAKER_VIVO -> OemBatteryGuide(
            makerKey = OEM_MAKER_VIVO,
            body = "Vivo/iQOO:\n\n" +
                "Настройки -> Батарея -> Высокое фоновое энергопотребление -> TrafficWrapper -> разрешить. " +
                "Также включите автозапуск и снимите ограничения батареи в карточке приложения.",
        )
        else -> OemBatteryGuide(
            makerKey = OEM_MAKER_GENERIC,
            body = "Откройте системные настройки TrafficWrapper и разрешите работу в фоне: " +
                "батарея без ограничений, фоновая активность разрешена, автозапуск включён, " +
                "приложение не находится в списках спящих или ограниченных.",
        )
    }

internal fun batteryRestrictionStateFromSignals(
    batteryRestricted: Boolean,
    backgroundRestricted: Boolean,
    manufacturer: String,
    brand: String,
    oemHintAcknowledged: Boolean,
): BatteryRestrictionState {
    val makerKey = oemMakerKey(manufacturer, brand)
    val oemHintNeeded = isAggressiveOemMaker(makerKey) && !oemHintAcknowledged
    return BatteryRestrictionState(
        restricted = batteryRestricted,
        batteryOptimizationRestricted = batteryRestricted,
        backgroundRestricted = backgroundRestricted,
        oemHintNeeded = oemHintNeeded,
        oemMakerKey = makerKey,
    )
}

internal fun oemMakerKey(manufacturer: String, brand: String): String {
    val maker = "$manufacturer $brand".lowercase(Locale.ROOT)
    return when {
        maker.contains("huawei") || maker.contains("honor") -> OEM_MAKER_HUAWEI
        maker.contains("xiaomi") || maker.contains("redmi") || maker.contains("poco") -> OEM_MAKER_XIAOMI
        maker.contains("oppo") || maker.contains("realme") || maker.contains("oneplus") -> OEM_MAKER_OPPO
        maker.contains("vivo") || maker.contains("iqoo") -> OEM_MAKER_VIVO
        maker.contains("samsung") -> OEM_MAKER_SAMSUNG
        maker.contains("google") || maker.contains("pixel") -> "google"
        maker.contains("motorola") -> "motorola"
        maker.contains("nothing") -> "nothing"
        else -> OEM_MAKER_GENERIC
    }
}

internal fun isAggressiveOemMaker(makerKey: String): Boolean =
    makerKey in setOf(OEM_MAKER_HUAWEI, OEM_MAKER_XIAOMI, OEM_MAKER_OPPO, OEM_MAKER_VIVO)

internal fun oemDisplayName(makerKey: String): String =
    when (makerKey) {
        OEM_MAKER_HUAWEI -> "Huawei/Honor"
        OEM_MAKER_XIAOMI -> "Xiaomi/Redmi/POCO"
        OEM_MAKER_OPPO -> "OPPO/Realme/OnePlus"
        OEM_MAKER_VIVO -> "Vivo/iQOO"
        OEM_MAKER_SAMSUNG -> "Samsung"
        "google" -> "Google/Pixel"
        "motorola" -> "Motorola"
        "nothing" -> "Nothing"
        else -> "устройство"
    }

internal fun openOemBatterySettings(context: Context) {
    val appContext = context.applicationContext
    val opened = if (oemBatteryGuide().makerKey == OEM_MAKER_HUAWEI) {
        HUAWEI_BATTERY_COMPONENTS.any { component ->
            runCatching {
                appContext.startActivity(
                    Intent()
                        .setComponent(component)
                        .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
                )
            }.isSuccess
        }
    } else {
        false
    }
    if (!opened) {
        openAppDetailsSettings(appContext)
    }
}

internal fun acknowledgeOemBatteryHint(context: Context) {
    val appContext = context.applicationContext
    TransportLifecycleStore.acknowledgeOemHint(appContext)
    val state = currentBatteryRestrictionState(appContext)
    TransportRuntime.batteryRestriction = state
    TransportRuntime.showBatteryGuide = false
    if (!state.restricted) {
        BatteryRestrictionNotifier.cancel(appContext)
    }
    TransportLifecycleStore.setLastBatteryRestricted(appContext, state.restricted)
    TransportLifecycleStore.setLastBatteryOptimizationRestricted(appContext, state.batteryOptimizationRestricted)
    sendBatteryHintTelemetry(
        appContext,
        BATTERY_HINT_ACTION_OEM_ACK,
        restricted = state.restricted,
        oem = state.oemMakerKey,
    )
}

internal fun sendBatteryHintTelemetry(
    context: Context,
    action: String,
    restricted: Boolean,
    oem: String = oemMakerKey(Build.MANUFACTURER, Build.BRAND),
) {
    Telemetry.event(
        context.applicationContext,
        "battery_hint",
        "action" to action,
        "mfr" to Build.MANUFACTURER,
        "oem" to oem,
        "restricted" to restricted,
        "rsn" to action,
    )
}

private fun requestBatteryOptimizationExemption(context: Context) {
    val packageUri = Uri.parse("package:${context.packageName}")
    val requestIntent = Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS, packageUri)
        .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
    runCatching {
        context.startActivity(requestIntent)
    }.onFailure {
        val settingsIntent = Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        runCatching { context.startActivity(settingsIntent) }
            .onFailure { Toast.makeText(context, R.string.battery_hint_settings_failed, Toast.LENGTH_LONG).show() }
    }
}

private fun openAppDetailsSettings(context: Context) {
    val intent = Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS)
        .setData(Uri.parse("package:${context.packageName}"))
        .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
    runCatching { context.startActivity(intent) }
        .onFailure { Toast.makeText(context, R.string.battery_hint_settings_failed, Toast.LENGTH_LONG).show() }
}

object BatteryRestrictionNotifier {
    fun maybeNotify(context: Context) {
        val appContext = context.applicationContext
        val state = currentBatteryRestrictionState(appContext)
        if (!state.restricted) {
            cancel(appContext)
            return
        }
        val nowMs = System.currentTimeMillis()
        if (!TransportLifecycleStore.shouldShowBatteryRestrictionNotification(appContext, nowMs)) return
        val manager = appContext.getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(
            NotificationChannel(
                CHANNEL_ID,
                appContext.getString(R.string.battery_notification_channel),
                NotificationManager.IMPORTANCE_LOW,
            ),
        )
        val oemOnly = state.oemHintNeeded &&
            !state.batteryOptimizationRestricted &&
            !state.backgroundRestricted
        val notification = Notification.Builder(appContext, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle(
                appContext.getString(
                    if (oemOnly) R.string.battery_oem_notification_title else R.string.battery_notification_title,
                ),
            )
            .setContentText(
                if (oemOnly) {
                    appContext.getString(R.string.battery_oem_notification_text, oemDisplayName(state.oemMakerKey))
                } else {
                    appContext.getString(R.string.battery_notification_text)
                },
            )
            .setContentIntent(batteryHintPendingIntent(appContext))
            .setAutoCancel(true)
            .build()
        runCatching {
            manager.notify(NOTIFICATION_ID, notification)
            TransportLifecycleStore.markBatteryRestrictionNotificationShown(appContext, nowMs)
            sendBatteryHintTelemetry(
                appContext,
                BATTERY_HINT_ACTION_SHOWN,
                restricted = true,
                oem = state.oemMakerKey,
            )
        }.onFailure {
            Log.w(LOG_TAG, "battery restriction notification failed: ${it.message}")
        }
    }

    fun cancel(context: Context) {
        runCatching {
            context.applicationContext.getSystemService(NotificationManager::class.java)
                .cancel(NOTIFICATION_ID)
        }
    }

    private const val CHANNEL_ID = "battery_restriction"
    private const val NOTIFICATION_ID = 1310
    private const val LOG_TAG = "TWBatteryHint"
}

internal const val BATTERY_HINT_ACTION_SHOWN = "shown"
internal const val BATTERY_HINT_ACTION_TAPPED = "tapped"
internal const val BATTERY_HINT_ACTION_GRANTED = "granted"
internal const val BATTERY_HINT_ACTION_DISMISSED = "dismissed"
internal const val BATTERY_HINT_ACTION_OEM_ACK = "oem_ack"

private const val PRIVATE_FLAVOR = "private"

internal const val OEM_MAKER_HUAWEI = "huawei"
internal const val OEM_MAKER_XIAOMI = "xiaomi"
internal const val OEM_MAKER_OPPO = "oppo"
internal const val OEM_MAKER_VIVO = "vivo"
internal const val OEM_MAKER_SAMSUNG = "samsung"
internal const val OEM_MAKER_GENERIC = "generic"

private val HUAWEI_BATTERY_COMPONENTS = listOf(
    ComponentName(
        "com.huawei.systemmanager",
        "com.huawei.systemmanager.startupmgr.ui.StartupNormalAppListActivity",
    ),
    ComponentName(
        "com.huawei.systemmanager",
        "com.huawei.systemmanager.appcontrol.activity.StartupAppControlActivity",
    ),
    ComponentName(
        "com.huawei.systemmanager",
        "com.huawei.systemmanager.optimize.process.ProtectActivity",
    ),
)
