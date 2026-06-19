package pro.trafficwrapper

import android.content.Context
import androidx.work.Constraints
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.NetworkType
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.Worker
import androidx.work.WorkerParameters
import java.text.DateFormat
import java.util.Date
import java.util.concurrent.TimeUnit

class UpdateCheckWorker(
    context: Context,
    params: WorkerParameters,
) : Worker(context, params) {
    override fun doWork(): Result {
        val transport = TransportRuntime.state
        val auth = TransportRuntime.auth
        val socksListen = transport.socksListen.ifBlank { auth.provisionedSOCKS }
        if (!auth.authorized || !transport.handshakeEstablished || socksListen.isBlank()) {
            return Result.success()
        }
        val outcome = UpdateRepository(applicationContext).check(
            auth = auth,
            socksListen = socksListen,
            allowProvisioningFallback = false,
            activeTransportOverride = transport.activeTransport,
        )
        val checkedAt = DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT)
            .format(Date())
        when (outcome.status) {
            UpdateCheckStatus.AVAILABLE -> {
                TransportRuntime.updates = updateStateFromOutcome(
                    outcome = outcome,
                    checkedAt = checkedAt,
                    showSheet = false,
                )
                UpdateNotifications.showInstallStatus(
                    applicationContext,
                    R.string.update_notification_available,
                )
            }

            UpdateCheckStatus.LATEST -> {
                TransportRuntime.updates = DistributionUiState(
                    statusTextRes = R.string.update_status_latest,
                    availableVersionName = outcome.manifest?.versionName.orEmpty(),
                    availableVersionCode = outcome.manifest?.versionCode ?: 0,
                    source = outcome.source?.name.orEmpty(),
                    baseUrl = outcome.baseUrl,
                    totalBytes = outcome.manifest?.apkSize ?: 0,
                    changelog = outcome.manifest?.changelogRu.orEmpty(),
                    lastCheckedAt = checkedAt,
                )
            }

            UpdateCheckStatus.ERROR -> {
                if (outcome.mandatoryDegraded) {
                    TransportRuntime.updates = updateStateFromOutcome(
                        outcome = outcome,
                        checkedAt = checkedAt,
                        showSheet = false,
                    )
                }
            }
        }
        return Result.success()
    }

    companion object {
        fun schedule(context: Context) {
            val constraints = Constraints.Builder()
                .setRequiredNetworkType(NetworkType.CONNECTED)
                .setRequiresBatteryNotLow(true)
                .build()
            val request = PeriodicWorkRequestBuilder<UpdateCheckWorker>(
                REPEAT_INTERVAL_HOURS,
                TimeUnit.HOURS,
                FLEX_INTERVAL_HOURS,
                TimeUnit.HOURS,
            )
                .setConstraints(constraints)
                .build()
            WorkManager.getInstance(context.applicationContext).enqueueUniquePeriodicWork(
                WORK_NAME,
                ExistingPeriodicWorkPolicy.UPDATE,
                request,
            )
        }

        private const val WORK_NAME = "trafficwrapper-update-check"
        private const val REPEAT_INTERVAL_HOURS = 12L
        private const val FLEX_INTERVAL_HOURS = 2L
    }
}
