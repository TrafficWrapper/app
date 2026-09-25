package pro.trafficwrapper

fun updateStateFromOutcome(
    outcome: UpdateCheckOutcome,
    checkedAt: String,
    showSheet: Boolean,
): DistributionUiState {
    val manifest = outcome.manifest
    val mandatory = manifest?.requiresInstalledUpdate() == true
    return when (outcome.status) {
        UpdateCheckStatus.LATEST -> DistributionUiState(
            statusTextRes = R.string.update_status_latest,
            availableVersionName = manifest?.versionName.orEmpty(),
            availableVersionCode = manifest?.versionCode ?: 0,
            source = outcome.source?.name.orEmpty(),
            baseUrl = outcome.baseUrl,
            totalBytes = manifest?.apkSize ?: 0,
            changelog = manifest?.changelogRu.orEmpty(),
            lastCheckedAt = checkedAt,
        )

        UpdateCheckStatus.AVAILABLE -> DistributionUiState(
            statusTextRes = R.string.update_status_available,
            availableVersionName = manifest?.versionName.orEmpty(),
            availableVersionCode = manifest?.versionCode ?: 0,
            source = outcome.source?.name.orEmpty(),
            baseUrl = outcome.baseUrl,
            downloadedBytes = outcome.downloadedBytes,
            totalBytes = outcome.totalBytes,
            apkPath = outcome.apkFile?.absolutePath.orEmpty(),
            changelog = manifest?.changelogRu.orEmpty(),
            mandatoryRequired = mandatory,
            mandatoryDegraded = false,
            showAvailableSheet = showSheet,
            lastCheckedAt = checkedAt,
        )

        UpdateCheckStatus.ERROR -> DistributionUiState(
            statusTextRes = if (outcome.mandatoryDegraded) {
                R.string.update_status_mandatory_degraded
            } else {
                R.string.update_status_error
            },
            errorTextRes = outcome.errorTextRes ?: R.string.update_error_unknown,
            availableVersionName = manifest?.versionName.orEmpty(),
            availableVersionCode = manifest?.versionCode ?: 0,
            source = outcome.source?.name.orEmpty(),
            baseUrl = outcome.baseUrl,
            changelog = manifest?.changelogRu.orEmpty(),
            mandatoryRequired = mandatory,
            mandatoryDegraded = outcome.mandatoryDegraded,
            showAvailableSheet = false,
            lastCheckedAt = checkedAt,
        )
    }
}

/** Automatic (probe-loop) update checks: normal cadence and retry cadence after a failed check. */
internal const val AUTO_UPDATE_CHECK_INTERVAL_MS = 3 * 60 * 60 * 1000L
internal const val AUTO_UPDATE_RETRY_INTERVAL_MS = 60 * 60 * 1000L

/**
 * APP-M22: whether an automatic update check is due. The first check after start runs at once;
 * later ones only after [AUTO_UPDATE_CHECK_INTERVAL_MS] (or [AUTO_UPDATE_RETRY_INTERVAL_MS] after a
 * failure), independent of route changes. [nowMs] and [lastCheckAtMs] are elapsedRealtime.
 */
internal fun autoUpdateCheckDue(nowMs: Long, lastCheckAtMs: Long?, lastCheckFailed: Boolean): Boolean {
    if (lastCheckAtMs == null || nowMs < lastCheckAtMs) return true
    val interval = if (lastCheckFailed) AUTO_UPDATE_RETRY_INTERVAL_MS else AUTO_UPDATE_CHECK_INTERVAL_MS
    return nowMs - lastCheckAtMs >= interval
}

/** No automatic check while a check, a download or an installation is running. */
internal fun autoUpdateCheckBlocked(state: DistributionUiState): Boolean =
    state.inProgress || state.downloadInProgress || state.installInProgress

/**
 * APP-M22: merges the result of an automatic check into the current UI state instead of
 * replacing it, so a downloaded APK, install progress and "Later" survive a periodic re-check.
 * The bottom sheet is raised only when [offerSheet] is set (the caller offers it once per new
 * versionCode) and stays as it is for a version the user has already seen.
 */
internal fun mergeAutoUpdateCheckState(
    current: DistributionUiState,
    outcome: UpdateCheckOutcome,
    checkedAt: String,
    offerSheet: Boolean,
    installedVersionCode: Long,
): DistributionUiState {
    if (autoUpdateCheckBlocked(current)) return current
    val next = updateStateFromOutcome(outcome = outcome, checkedAt = checkedAt, showSheet = false)
        .copy(inProgress = false, downloadInProgress = false, snoozedUntilMs = current.snoozedUntilMs)
    return when (outcome.status) {
        UpdateCheckStatus.AVAILABLE -> {
            val sameVersion = current.availableVersionCode > 0 &&
                next.availableVersionCode == current.availableVersionCode
            if (sameVersion) {
                next.copy(
                    apkPath = current.apkPath,
                    downloadedBytes = if (current.apkPath.isNotBlank()) current.downloadedBytes else next.downloadedBytes,
                    installStatusTextRes = current.installStatusTextRes,
                    installErrorTextRes = current.installErrorTextRes,
                    showAvailableSheet = current.showAvailableSheet || offerSheet,
                )
            } else {
                next.copy(showAvailableSheet = offerSheet, snoozedUntilMs = 0)
            }
        }

        UpdateCheckStatus.LATEST -> next

        UpdateCheckStatus.ERROR ->
            if (current.availableVersionCode > installedVersionCode) {
                // Keep the known update (and a downloaded APK) over a transient background failure.
                current.copy(lastCheckedAt = checkedAt)
            } else {
                next
            }
    }
}
