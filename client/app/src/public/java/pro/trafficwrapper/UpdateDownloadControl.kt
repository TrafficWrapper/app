package pro.trafficwrapper

import java.util.concurrent.atomic.AtomicBoolean

internal class UpdateDownloadGuard {
    private val active = AtomicBoolean(false)

    fun tryAcquire(): Boolean = active.compareAndSet(false, true)

    fun release() {
        active.compareAndSet(true, false)
    }
}

internal val sharedUpdateDownloadGuard = UpdateDownloadGuard()

internal class UpdateProgressThrottle(
    private val minIntervalMs: Long = 1_000L,
    private val nowMs: () -> Long = { System.nanoTime() / 1_000_000L },
) {
    private var lastPublishedAtMs: Long? = null
    private var completionPublished = false

    init {
        require(minIntervalMs > 0)
    }

    fun shouldPublish(downloadedBytes: Long, totalBytes: Long): Boolean {
        val now = nowMs()
        val completed = totalBytes > 0 && downloadedBytes >= totalBytes
        val lastPublished = lastPublishedAtMs
        val shouldPublish = when {
            lastPublished == null -> true
            completed && !completionPublished -> true
            completed -> false
            now - lastPublished >= minIntervalMs -> true
            else -> false
        }
        if (shouldPublish) {
            lastPublishedAtMs = now
            completionPublished = completed
        }
        return shouldPublish
    }
}

internal fun tryForegroundPromotion(
    promote: () -> Unit,
    onFailure: (Throwable) -> Unit,
): Boolean =
    try {
        promote()
        true
    } catch (error: Throwable) {
        onFailure(error)
        false
    }

internal fun backgroundUpdateErrorState(
    outcome: UpdateCheckOutcome,
    checkedAt: String,
): DistributionUiState =
    updateStateFromOutcome(
        outcome = outcome,
        checkedAt = checkedAt,
        showSheet = false,
    ).copy(inProgress = false, downloadInProgress = false)

internal fun failedUpdateDownloadState(current: DistributionUiState): DistributionUiState =
    current.copy(
        inProgress = false,
        downloadInProgress = false,
        statusTextRes = R.string.update_status_available,
        errorTextRes = R.string.update_error_unknown,
        showAvailableSheet = false,
    )

internal fun finishedUpdateDownloadState(current: DistributionUiState): DistributionUiState =
    current.copy(inProgress = false, downloadInProgress = false)
