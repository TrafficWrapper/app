package pro.trafficwrapper

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

class UpdateDownloadControlTest {
    @Test
    fun leaseReleasesGuardOnlyOnce() {
        var releaseCount = 0
        val lease = UpdateDownloadLease { releaseCount += 1 }

        lease.release()
        lease.release()

        assertEquals(1, releaseCount)
    }

    @Test
    fun staleLeaseCannotReleaseTheNextOwner() {
        val guard = UpdateDownloadGuard()

        val firstLease = checkNotNull(guard.tryAcquire())
        assertNull(guard.tryAcquire())
        firstLease.release()

        val secondLease = checkNotNull(guard.tryAcquire())
        firstLease.release()
        assertNull(guard.tryAcquire())

        secondLease.release()
        checkNotNull(guard.tryAcquire()).release()
    }

    @Test
    fun foregroundPromotionFailureIsReportedWithoutEscaping() {
        val expected = IllegalStateException("foreground rejected")
        var observed: Throwable? = null

        val promoted = tryForegroundPromotion(
            promote = { throw expected },
            onFailure = { observed = it },
        )

        assertFalse(promoted)
        assertSame(expected, observed)
    }

    @Test
    fun progressPublishesAtMostOncePerSecondAndAtCompletion() {
        var nowMs = 100L
        val throttle = UpdateProgressThrottle(nowMs = { nowMs })

        assertTrue(throttle.shouldPublish(downloadedBytes = 1, totalBytes = 100))
        nowMs = 1_099L
        assertFalse(throttle.shouldPublish(downloadedBytes = 50, totalBytes = 100))
        nowMs = 1_100L
        assertTrue(throttle.shouldPublish(downloadedBytes = 51, totalBytes = 100))
        nowMs = 1_101L
        assertTrue(throttle.shouldPublish(downloadedBytes = 100, totalBytes = 100))
        assertFalse(throttle.shouldPublish(downloadedBytes = 100, totalBytes = 100))
    }

    @Test
    fun failedAndFinishedDownloadStatesAlwaysClearProgress() {
        val downloading = DistributionUiState(
            inProgress = true,
            downloadInProgress = true,
            statusTextRes = R.string.update_status_downloading,
            availableVersionName = "0.2.0",
            availableVersionCode = 30,
            downloadedBytes = 123,
            totalBytes = 456,
            showAvailableSheet = true,
        )

        val failed = failedUpdateDownloadState(downloading)
        assertFalse(failed.inProgress)
        assertFalse(failed.downloadInProgress)
        assertEquals(R.string.update_status_available, failed.statusTextRes)
        assertEquals(R.string.update_error_unknown, failed.errorTextRes)
        assertFalse(failed.showAvailableSheet)
        assertEquals("0.2.0", failed.availableVersionName)

        val finished = finishedUpdateDownloadState(downloading)
        assertFalse(finished.inProgress)
        assertFalse(finished.downloadInProgress)
        assertEquals(123L, finished.downloadedBytes)
    }

    @Test
    fun nonMandatoryBackgroundErrorProducesVisibleUiState() {
        val state = backgroundUpdateErrorState(
            outcome = UpdateCheckOutcome(
                status = UpdateCheckStatus.ERROR,
                mandatoryDegraded = false,
                errorTextRes = R.string.update_error_network,
            ),
            checkedAt = "now",
        )

        assertFalse(state.inProgress)
        assertFalse(state.downloadInProgress)
        assertEquals(R.string.update_status_error, state.statusTextRes)
        assertEquals(R.string.update_error_network, state.errorTextRes)
        assertFalse(state.mandatoryDegraded)
        assertEquals("now", state.lastCheckedAt)
    }
}
