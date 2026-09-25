package pro.trafficwrapper

import android.app.ActivityManager
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.PackageInstaller
import android.os.Build

/**
 * Only a process with a visible activity may start the confirm activity itself; a foreground
 * service (VPN) or a background process is subject to background activity launch restrictions.
 */
internal fun installConfirmationMayStartDirectly(processImportance: Int): Boolean =
    processImportance == ActivityManager.RunningAppProcessInfo.IMPORTANCE_FOREGROUND ||
        processImportance == ActivityManager.RunningAppProcessInfo.IMPORTANCE_VISIBLE

class UpdateInstallReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != ACTION_INSTALL_RESULT) return
        when (val status = intent.getIntExtra(PackageInstaller.EXTRA_STATUS, PackageInstaller.STATUS_FAILURE)) {
            PackageInstaller.STATUS_PENDING_USER_ACTION -> {
                TransportRuntime.updates = TransportRuntime.updates.copy(
                    installInProgress = true,
                    installStatusTextRes = R.string.update_install_waiting_user,
                    installErrorTextRes = null,
                )
                val confirmIntent = pendingUserIntent(intent) ?: return
                // A background receiver may not start activities (APP-L30): always offer the
                // confirmation as a notification, and open it directly only while the app is
                // visible, where the launch is allowed.
                runCatching { UpdateNotifications.showInstallConfirmation(context, confirmIntent) }
                if (installConfirmationMayStartDirectly(currentProcessImportance())) {
                    confirmIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                    runCatching { context.startActivity(confirmIntent) }
                }
            }

            PackageInstaller.STATUS_SUCCESS -> {
                TransportRuntime.updates = TransportRuntime.updates.copy(
                    installInProgress = false,
                    installStatusTextRes = R.string.update_install_success,
                    installErrorTextRes = null,
                )
                UpdateNotifications.showInstallStatus(context, R.string.update_install_success)
                runCatching {
                    context.startActivity(
                        Intent(context, MainActivity::class.java)
                            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP),
                    )
                }
            }

            else -> {
                val errorRes = errorTextFor(status)
                TransportRuntime.updates = TransportRuntime.updates.copy(
                    installInProgress = false,
                    installStatusTextRes = null,
                    installErrorTextRes = errorRes,
                )
                UpdateNotifications.showInstallStatus(context, errorRes)
            }
        }
    }

    private fun currentProcessImportance(): Int =
        runCatching {
            ActivityManager.RunningAppProcessInfo().also { ActivityManager.getMyMemoryState(it) }.importance
        }.getOrDefault(ActivityManager.RunningAppProcessInfo.IMPORTANCE_GONE)

    @Suppress("DEPRECATION")
    private fun pendingUserIntent(intent: Intent): Intent? =
        if (Build.VERSION.SDK_INT >= 33) {
            intent.getParcelableExtra(Intent.EXTRA_INTENT, Intent::class.java)
        } else {
            intent.getParcelableExtra(Intent.EXTRA_INTENT)
        }

    private fun errorTextFor(status: Int): Int =
        when (status) {
            PackageInstaller.STATUS_FAILURE_BLOCKED -> R.string.update_install_blocked
            PackageInstaller.STATUS_FAILURE_CONFLICT -> R.string.update_install_conflict
            PackageInstaller.STATUS_FAILURE_INCOMPATIBLE -> R.string.update_install_incompatible
            PackageInstaller.STATUS_FAILURE_INVALID -> R.string.update_install_invalid
            PackageInstaller.STATUS_FAILURE_STORAGE -> R.string.update_install_storage
            PackageInstaller.STATUS_FAILURE_TIMEOUT -> R.string.update_install_timeout
            PackageInstaller.STATUS_FAILURE_ABORTED -> R.string.update_install_aborted
            else -> R.string.update_install_failed
        }

    companion object {
        const val ACTION_INSTALL_RESULT = "pro.trafficwrapper.action.UPDATE_INSTALL_RESULT"
    }
}
