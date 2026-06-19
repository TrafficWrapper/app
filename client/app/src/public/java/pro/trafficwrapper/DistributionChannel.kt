package pro.trafficwrapper

import android.content.Context
import android.os.Handler
import android.os.Looper
import android.util.Log
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import java.text.DateFormat
import java.util.Date
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

object DistributionChannel {
    private val updateExecutor = Executors.newSingleThreadExecutor()
    private val autoUpdateExecutor = Executors.newSingleThreadExecutor()
    private val autoUpdateActive = AtomicBoolean(false)

    @Volatile
    private var lastAutoUpdateCheckAtMs = 0L

    @Volatile
    private var lastAutoUpdateRoute: String? = null

    fun schedule(context: Context) = Unit

    fun maybeCheckAutomatically(
        context: Context,
        auth: AuthUiState,
        socksListen: String,
        activeTransport: String,
        nowMs: Long,
        mainHandler: Handler,
    ) {
        if (!auth.authorized) return
        if (TransportRuntime.updates.inProgress) return
        if (
            lastAutoUpdateCheckAtMs > 0 &&
            nowMs - lastAutoUpdateCheckAtMs < AUTO_UPDATE_MIN_INTERVAL_MS &&
            lastAutoUpdateRoute == activeTransport
        ) {
            return
        }
        if (!autoUpdateActive.compareAndSet(false, true)) return
        lastAutoUpdateCheckAtMs = nowMs
        lastAutoUpdateRoute = activeTransport
        autoUpdateExecutor.execute {
            try {
                mainHandler.post {
                    TransportRuntime.updates = TransportRuntime.updates.copy(
                        inProgress = true,
                        downloadInProgress = false,
                        statusTextRes = R.string.update_checking,
                        errorTextRes = null,
                    )
                }
                val result = UpdateRepository(context.applicationContext).check(
                    auth = auth,
                    socksListen = socksListen,
                    allowProvisioningFallback = false,
                    activeTransportOverride = activeTransport,
                )
                val checkedAt = DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT)
                    .format(Date())
                mainHandler.post {
                    TransportRuntime.updates = updateStateFromOutcome(
                        outcome = result,
                        checkedAt = checkedAt,
                        showSheet = result.status == UpdateCheckStatus.AVAILABLE,
                    ).copy(inProgress = false, downloadInProgress = false)
                }
                Log.i(LOG_TAG, "auto update check completed route=$activeTransport status=${result.status}")
            } catch (error: Throwable) {
                Log.w(LOG_TAG, "auto update check failed: ${error.message}")
                mainHandler.post {
                    TransportRuntime.updates = TransportRuntime.updates.copy(inProgress = false)
                }
            } finally {
                autoUpdateActive.set(false)
            }
        }
    }

    fun requestUpdateCheck(context: Context, auth: AuthUiState, socksListen: String) {
        performUpdateCheck(context.applicationContext, auth, socksListen)
    }

    fun requestInstall(
        context: Context,
        auth: AuthUiState,
        socksListen: String,
        updates: DistributionUiState,
    ) {
        if (updates.apkPath.isNotBlank()) {
            startUpdateInstall(context.applicationContext, updates)
        } else {
            performUpdateDownloadAndInstall(context.applicationContext, auth, socksListen)
        }
    }

    fun openInstallSettings(context: Context) {
        UpdateInstaller(context.applicationContext).openInstallSettings()
    }

    @Composable
    fun Panel(
        context: Context,
        updates: DistributionUiState,
        auth: AuthUiState,
        socksListen: String,
    ) {
        Text(
            text = stringResource(R.string.update_title),
            style = MaterialTheme.typography.titleLarge,
        )
        Text(
            text = stringResource(R.string.update_current_version, BuildConfig.VERSION_NAME, BuildConfig.VERSION_CODE),
            modifier = Modifier.padding(top = 8.dp),
        )
        Button(
            enabled = !updates.inProgress && auth.authorized,
            onClick = { performUpdateCheck(context.applicationContext, auth, socksListen) },
            modifier = Modifier
                .fillMaxWidth()
                .padding(top = 10.dp),
        ) {
            Text(
                text = stringResource(
                    if (updates.inProgress && !updates.downloadInProgress) {
                        R.string.update_checking
                    } else {
                        R.string.update_check_button
                    },
                ),
            )
        }
        Text(
            text = stringResource(updates.statusTextRes),
            modifier = Modifier.padding(top = 8.dp),
            style = MaterialTheme.typography.bodyLarge,
        )
        if (updates.availableVersionName.isNotBlank()) {
            Text(
                text = stringResource(
                    R.string.update_published_version,
                    updates.availableVersionName,
                    updates.availableVersionCode,
                ),
                modifier = Modifier.padding(top = 6.dp),
            )
        }
        if (updates.changelog.isNotBlank()) {
            Text(
                text = stringResource(R.string.update_changelog_title),
                modifier = Modifier.padding(top = 8.dp),
                style = MaterialTheme.typography.titleSmall,
            )
            Text(
                text = updates.changelog,
                modifier = Modifier.padding(top = 4.dp),
                style = MaterialTheme.typography.bodyMedium,
            )
        }
        if (updates.downloadInProgress && updates.totalBytes > 0) {
            LinearProgressIndicator(
                progress = { (updates.downloadedBytes.toFloat() / updates.totalBytes.toFloat()).coerceIn(0f, 1f) },
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(top = 8.dp),
            )
            Text(
                text = stringResource(R.string.update_download_progress, updates.downloadedBytes, updates.totalBytes),
                modifier = Modifier.padding(top = 6.dp),
            )
        } else if (updates.downloadedBytes > 0) {
            Text(
                text = stringResource(R.string.update_downloaded_bytes, updates.downloadedBytes),
                modifier = Modifier.padding(top = 6.dp),
            )
        }
        if (updates.availableVersionCode > BuildConfig.VERSION_CODE.toLong()) {
            Button(
                enabled = !updates.inProgress && !updates.installInProgress,
                onClick = {
                    if (updates.apkPath.isNotBlank()) {
                        startUpdateInstall(context.applicationContext, updates)
                    } else {
                        performUpdateDownloadAndInstall(context.applicationContext, auth, socksListen)
                    }
                },
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(top = 10.dp),
            ) {
                Text(
                    text = stringResource(
                        when {
                            updates.downloadInProgress -> R.string.update_downloading
                            updates.installInProgress -> R.string.update_installing
                            else -> R.string.update_install_button
                        },
                    ),
                )
            }
        }
        updates.installStatusTextRes?.let { statusRes ->
            Text(
                text = stringResource(statusRes),
                modifier = Modifier.padding(top = 6.dp),
            )
        }
        updates.installErrorTextRes?.let { errorRes ->
            Text(
                text = stringResource(errorRes),
                modifier = Modifier.padding(top = 8.dp),
                color = MaterialTheme.colorScheme.error,
            )
            if (errorRes == R.string.update_install_permission_required) {
                OutlinedButton(
                    onClick = { UpdateInstaller(context.applicationContext).openInstallSettings() },
                    modifier = Modifier.padding(top = 8.dp),
                ) {
                    Text(text = stringResource(R.string.update_install_open_settings))
                }
            }
        }
        if (updates.mandatoryDegraded) {
            Text(
                text = stringResource(R.string.update_mandatory_degraded_detail),
                modifier = Modifier.padding(top = 8.dp),
                color = MaterialTheme.colorScheme.error,
            )
        }
        if (updates.lastCheckedAt.isNotBlank()) {
            Text(
                text = stringResource(R.string.update_last_checked, updates.lastCheckedAt),
                modifier = Modifier.padding(top = 6.dp),
            )
        }
        updates.errorTextRes?.let { errorRes ->
            Text(
                text = stringResource(errorRes),
                modifier = Modifier.padding(top = 8.dp),
                color = MaterialTheme.colorScheme.error,
            )
        }
    }

    @Composable
    fun AvailableSheet(
        context: Context,
        updates: DistributionUiState,
        auth: AuthUiState,
        socksListen: String,
    ) {
        if (
            updates.showAvailableSheet &&
            updates.availableVersionCode > BuildConfig.VERSION_CODE.toLong() &&
            (updates.mandatoryRequired || updates.snoozedUntilMs <= System.currentTimeMillis())
        ) {
            UpdateAvailableSheet(
                updates = updates,
                onInstall = {
                    if (updates.apkPath.isNotBlank()) {
                        startUpdateInstall(context.applicationContext, updates)
                    } else {
                        performUpdateDownloadAndInstall(
                            context = context.applicationContext,
                            auth = auth,
                            socksListen = socksListen,
                        )
                    }
                },
                onLater = { snoozeUpdateSheet() },
                onDismiss = {
                    if (!updates.mandatoryRequired) {
                        TransportRuntime.updates = TransportRuntime.updates.copy(showAvailableSheet = false)
                    }
                },
            )
        }
    }

    private fun performUpdateCheck(context: Context, auth: AuthUiState, socksListen: String) {
        TransportRuntime.updates = TransportRuntime.updates.copy(
            inProgress = true,
            downloadInProgress = false,
            statusTextRes = R.string.update_checking,
            errorTextRes = null,
            availableVersionName = "",
            availableVersionCode = 0,
            downloadedBytes = 0,
            totalBytes = 0,
            apkPath = "",
            changelog = "",
            mandatoryRequired = false,
            mandatoryDegraded = false,
            showAvailableSheet = false,
            installInProgress = false,
            installStatusTextRes = null,
            installErrorTextRes = null,
        )
        updateExecutor.execute {
            val mainHandler = Handler(Looper.getMainLooper())
            val result = UpdateRepository(context).check(auth, socksListen)
            val checkedAt = DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT)
                .format(Date())
            mainHandler.post {
                TransportRuntime.updates = updateStateFromOutcome(
                    outcome = result,
                    checkedAt = checkedAt,
                    showSheet = false,
                ).copy(inProgress = false, downloadInProgress = false)
            }
        }
    }

    private fun performUpdateDownloadAndInstall(context: Context, auth: AuthUiState, socksListen: String) {
        TransportRuntime.updates = TransportRuntime.updates.copy(
            inProgress = true,
            downloadInProgress = true,
            statusTextRes = R.string.update_status_downloading,
            errorTextRes = null,
            downloadedBytes = 0,
            apkPath = "",
            showAvailableSheet = false,
            installInProgress = false,
            installStatusTextRes = null,
            installErrorTextRes = null,
        )
        updateExecutor.execute {
            val mainHandler = Handler(Looper.getMainLooper())
            val activeTransport = TransportRuntime.state.activeTransport
            val result = UpdateRepository(context).downloadAndVerify(
                auth = auth,
                socksListen = socksListen,
                activeTransportOverride = activeTransport,
            ) { downloaded, total ->
                mainHandler.post {
                    TransportRuntime.updates = TransportRuntime.updates.copy(
                        downloadedBytes = downloaded,
                        totalBytes = total,
                    )
                }
                if (total > 0) {
                    UpdateNotifications.showDownloadProgress(context, downloaded, total)
                }
            }
            UpdateNotifications.clearDownload(context)
            val checkedAt = DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT)
                .format(Date())
            mainHandler.post {
                val nextState = updateStateFromOutcome(
                    outcome = result,
                    checkedAt = checkedAt,
                    showSheet = false,
                ).copy(inProgress = false, downloadInProgress = false)
                TransportRuntime.updates = nextState
                if (result.status == UpdateCheckStatus.AVAILABLE && nextState.apkPath.isNotBlank()) {
                    startUpdateInstall(context, nextState)
                }
            }
        }
    }

    private fun startUpdateInstall(context: Context, updates: DistributionUiState) {
        if (updates.apkPath.isBlank()) {
            TransportRuntime.updates = updates.copy(installErrorTextRes = R.string.update_install_missing_apk)
            return
        }
        TransportRuntime.updates = updates.copy(
            installInProgress = true,
            downloadInProgress = false,
            installStatusTextRes = R.string.update_install_starting,
            installErrorTextRes = null,
            showAvailableSheet = false,
        )
        updateExecutor.execute {
            val result = UpdateInstaller(context).install(updates.apkPath)
            Handler(Looper.getMainLooper()).post {
                TransportRuntime.updates = TransportRuntime.updates.copy(
                    installInProgress = result.started,
                    installStatusTextRes = if (result.started) result.textRes else null,
                    installErrorTextRes = if (result.started) null else result.textRes,
                    showAvailableSheet = false,
                )
            }
            if (result.started) {
                UpdateNotifications.showInstallStatus(context, result.textRes)
            }
        }
    }

    private fun snoozeUpdateSheet() {
        TransportRuntime.updates = TransportRuntime.updates.copy(
            showAvailableSheet = false,
            snoozedUntilMs = System.currentTimeMillis() + UPDATE_SNOOZE_MS,
        )
    }

    @OptIn(ExperimentalMaterial3Api::class)
    @Composable
    private fun UpdateAvailableSheet(
        updates: DistributionUiState,
        onInstall: () -> Unit,
        onLater: () -> Unit,
        onDismiss: () -> Unit,
    ) {
        val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
        val mandatory = updates.mandatoryRequired
        ModalBottomSheet(
            onDismissRequest = {
                if (!mandatory) onDismiss()
            },
            sheetState = sheetState,
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(20.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                Text(
                    text = stringResource(R.string.update_sheet_title),
                    style = MaterialTheme.typography.titleLarge,
                )
                Text(
                    text = stringResource(
                        R.string.update_sheet_version,
                        updates.availableVersionName,
                        updates.availableVersionCode,
                    ),
                )
                if (updates.totalBytes > 0) {
                    Text(
                        text = stringResource(
                            R.string.update_sheet_size,
                            updates.totalBytes / BYTES_IN_MEGABYTE.toDouble(),
                        ),
                    )
                }
                Text(
                    text = updates.changelog.ifBlank { stringResource(R.string.update_changelog_empty) },
                )
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    Button(
                        onClick = onInstall,
                        enabled = !updates.installInProgress,
                    ) {
                        Text(text = stringResource(R.string.update_install_button))
                    }
                    if (!mandatory) {
                        TextButton(onClick = onLater) {
                            Text(text = stringResource(R.string.update_later_button))
                        }
                    }
                }
            }
        }
    }

    private const val LOG_TAG = "TWDistribution"
    private const val AUTO_UPDATE_MIN_INTERVAL_MS = 20 * 1000L
    private const val UPDATE_SNOOZE_MS = 24 * 60 * 60 * 1000L
    private const val BYTES_IN_MEGABYTE = 1024 * 1024L
}
