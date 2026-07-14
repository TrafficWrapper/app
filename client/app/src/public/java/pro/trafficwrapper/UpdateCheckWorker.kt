package pro.trafficwrapper

import android.content.Context
import android.content.pm.ServiceInfo
import android.util.Log
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
        )
        val checkedAt = DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT)
            .format(Date())
        when (outcome.status) {
            UpdateCheckStatus.AVAILABLE -> {
                val availableState = updateStateFromOutcome(
                    outcome = outcome,
                    checkedAt = checkedAt,
                    showSheet = false,
                )
                val gateState = TransportRuntime.state
                val carrying = gateState.isCarryingTrafficNow()
                val mandatory = outcome.manifest?.requiresInstalledUpdate() == true
                // AVAILABLE outcomes carry a source; PLATFORM is the conservative fallback.
                val source = outcome.source ?: UpdateSource.PLATFORM
                if (shouldAutoDownloadUpdateWithCarry(
                        UpdateNetworkPolicy.currentPolicy(applicationContext),
                        UpdateNetworkPolicy.underlyingNetworkKind(applicationContext),
                        source = source,
                        carrying = carrying,
                        mandatory = mandatory,
                    )
                ) {
                    downloadAvailableUpdate(
                        auth = auth,
                        socksListen = socksListen,
                        checkedAt = checkedAt,
                        availableState = availableState,
                    )
                } else {
                    TransportRuntime.updates = availableState
                    showInstallStatusSafely(R.string.update_notification_available)
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
                TransportRuntime.updates = backgroundUpdateErrorState(outcome, checkedAt)
                Log.w(
                    LOG_TAG,
                    "background update check failed " +
                        "errorRes=${outcome.errorTextRes} mandatoryDegraded=${outcome.mandatoryDegraded}",
                )
            }
        }
        return Result.success()
    }

    private fun downloadAvailableUpdate(
        auth: AuthUiState,
        socksListen: String,
        checkedAt: String,
        availableState: DistributionUiState,
    ) {
        val downloadLease = sharedUpdateDownloadGuard.tryAcquire()
        if (downloadLease == null) {
            Log.i(LOG_TAG, "background update download skipped: another download owns the guard")
            return
        }
        try {
            TransportRuntime.updates = availableState.copy(
                inProgress = true,
                downloadInProgress = true,
                statusTextRes = R.string.update_status_downloading,
                errorTextRes = null,
                downloadedBytes = 0,
            )
            tryForegroundPromotion(
                promote = {
                    setForegroundAsync(
                        ForegroundInfo(
                            AUTO_DOWNLOAD_NOTIFICATION_ID,
                            UpdateNotifications.downloadForegroundNotification(applicationContext),
                            ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC,
                        ),
                    ).get()
                },
                onFailure = { error ->
                    Log.w(
                        LOG_TAG,
                        "background update foreground promotion failed; continuing without FGS",
                        error,
                    )
                },
            )
            val progressThrottle = UpdateProgressThrottle()
            val result = UpdateRepository(applicationContext).downloadAndVerify(
                auth = auth,
                socksListen = socksListen,
            ) { downloaded, total ->
                if (progressThrottle.shouldPublish(downloaded, total)) {
                    TransportRuntime.updates = TransportRuntime.updates.copy(
                        downloadedBytes = downloaded,
                        totalBytes = total,
                    )
                }
            }
            TransportRuntime.updates = updateStateFromOutcome(
                outcome = result,
                checkedAt = checkedAt,
                showSheet = false,
            ).copy(inProgress = false, downloadInProgress = false)
            if (result.status == UpdateCheckStatus.AVAILABLE && result.apkFile != null) {
                showInstallStatusSafely(R.string.update_notification_ready)
            } else if (result.status == UpdateCheckStatus.ERROR) {
                showInstallStatusSafely(result.errorTextRes ?: R.string.update_error_unknown)
            }
        } catch (error: Throwable) {
            Log.w(LOG_TAG, "background update download failed", error)
            TransportRuntime.updates = failedUpdateDownloadState(TransportRuntime.updates)
            showInstallStatusSafely(R.string.update_notification_available)
        } finally {
            try {
                clearDownloadNotificationSafely()
                TransportRuntime.updates = finishedUpdateDownloadState(TransportRuntime.updates)
            } finally {
                downloadLease.release()
            }
        }
    }

    private fun showInstallStatusSafely(textRes: Int) {
        try {
            UpdateNotifications.showInstallStatus(applicationContext, textRes)
        } catch (error: Throwable) {
            Log.w(LOG_TAG, "background update status notification failed", error)
        }
    }

    private fun clearDownloadNotificationSafely() {
        try {
            UpdateNotifications.clearDownload(applicationContext)
        } catch (error: Throwable) {
            Log.w(LOG_TAG, "background update progress notification cleanup failed", error)
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
        private const val LOG_TAG = "TWPublicUpdate"
    }
}
