package pro.trafficwrapper

import android.content.Context
import androidx.work.Constraints
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.ForegroundInfo
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
        val directFallback = TransportLifecycleStore.directUpdateFallbackEnabled(applicationContext)
        if ((!auth.authorized || !transport.handshakeEstablished || socksListen.isBlank()) && !directFallback) {
            return Result.success()
        }
        runCatching {
            DiscoveryRepository(applicationContext).maybeRefresh(socksListen = socksListen)
        }.onSuccess { result ->
            if (result?.applied == true) {
                android.util.Log.i("TWPublicUpdate", "public discovery refreshed seq=${result.seq}")
            }
        }.onFailure { error ->
            android.util.Log.w("TWPublicUpdate", "public discovery refresh failed", error)
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
                if (shouldAutoDownloadUpdate(
                        UpdateNetworkPolicy.currentPolicy(applicationContext),
                        UpdateNetworkPolicy.underlyingNetworkKind(applicationContext),
                    )
                ) {
                    downloadAvailableUpdate(auth, socksListen, transport.activeTransport, checkedAt)
                } else {
                    UpdateNotifications.showInstallStatus(
                        applicationContext,
                        R.string.update_notification_available,
                    )
                }
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

    private fun downloadAvailableUpdate(
        auth: AuthUiState,
        socksListen: String,
        activeTransport: String,
        checkedAt: String,
    ) {
        setForegroundAsync(
            ForegroundInfo(
                AUTO_DOWNLOAD_NOTIFICATION_ID,
                UpdateNotifications.downloadForegroundNotification(applicationContext),
            ),
        ).get()
        TransportRuntime.updates = TransportRuntime.updates.copy(
            inProgress = true,
            downloadInProgress = true,
            statusTextRes = R.string.update_status_downloading,
            errorTextRes = null,
            downloadedBytes = 0,
        )
        val result = UpdateRepository(applicationContext).downloadAndVerify(
            auth = auth,
            socksListen = socksListen,
            allowProvisioningFallback = false,
            activeTransportOverride = activeTransport,
        ) { downloaded, total ->
            TransportRuntime.updates = TransportRuntime.updates.copy(
                downloadedBytes = downloaded,
                totalBytes = total,
            )
            if (total > 0) {
                UpdateNotifications.showDownloadProgress(applicationContext, downloaded, total)
            }
        }
        UpdateNotifications.clearDownload(applicationContext)
        TransportRuntime.updates = updateStateFromOutcome(
            outcome = result,
            checkedAt = checkedAt,
            showSheet = false,
        ).copy(inProgress = false, downloadInProgress = false)
        if (result.status == UpdateCheckStatus.AVAILABLE && result.apkFile != null) {
            UpdateNotifications.showInstallStatus(
                applicationContext,
                R.string.update_notification_ready,
            )
        } else if (result.status == UpdateCheckStatus.ERROR) {
            UpdateNotifications.showInstallStatus(
                applicationContext,
                result.errorTextRes ?: R.string.update_error_unknown,
            )
        }
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
        private const val AUTO_DOWNLOAD_NOTIFICATION_ID = 1403
    }
}
