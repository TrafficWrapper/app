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
