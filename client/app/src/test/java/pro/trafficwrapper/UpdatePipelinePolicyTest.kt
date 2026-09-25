package pro.trafficwrapper

import android.app.ActivityManager
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class UpdatePipelinePolicyTest {
    private val sha = "b".repeat(64)

    @Test
    fun partialDownloadIsKeyedBySignedHashAndSizeOnly() {
        val text = updatePartialMetadataText(sha.uppercase(), 1_000)
        assertTrue(updatePartialMetadataMatches(text, sha, 1_000))
        assertFalse(updatePartialMetadataMatches(text, "c".repeat(64), 1_000))
        assertFalse(updatePartialMetadataMatches(text, sha, 1_001))
        // Metadata written by older versions (URL and ETag of another worker) still resumes.
        val legacy = "url=http://worker-a:8080/tw/app-public-32.apk\nsha256=$sha\nsize=1000\netag=\"abc\"\n"
        assertTrue(updatePartialMetadataMatches(legacy, sha, 1_000))
        // ETag-only metadata carries no APK identity.
        assertFalse(updatePartialMetadataMatches("\"abc\"\n", sha, 1_000))
        assertFalse(updatePartialMetadataMatches(null, sha, 1_000))
    }

    @Test
    fun hashMismatchIsTerminalForTheEndpoint() {
        assertTrue(updateDownloadErrorIsTerminal(UpdateVerificationException(R.string.update_error_apk_hash)))
        assertFalse(updateDownloadErrorIsTerminal(UpdateVerificationException(R.string.update_error_download)))
        assertFalse(updateDownloadErrorIsTerminal(java.io.IOException("reset")))
    }

    @Test
    fun staleCacheFilesAreSelected() {
        val names = listOf(
            "app-release-30.apk",
            "app-release-31.apk",
            "app-release-31.apk.part",
            "app-release-32.apk",
            "app-release-32.apk.part",
            "app-release-32.apk.etag",
            "app-release-33.apk.part",
            "app-release-33.apk.etag",
            "unrelated.txt",
        )
        assertEquals(
            listOf("app-release-30.apk", "app-release-31.apk", "app-release-31.apk.part"),
            staleUpdateCacheFileNames(names, installedVersionCode = 31),
        )
        assertEquals(
            listOf(
                "app-release-30.apk",
                "app-release-31.apk",
                "app-release-31.apk.part",
                "app-release-33.apk.part",
                "app-release-33.apk.etag",
            ),
            staleUpdateCacheFileNames(names, installedVersionCode = 31, targetVersionCode = 32),
        )
    }

    @Test
    fun pruneUpdateCacheDeletesStaleFiles() {
        val dir = java.nio.file.Files.createTempDirectory("tw-update-cache").toFile()
        try {
            listOf("app-release-31.apk", "app-release-32.apk", "app-release-32.apk.part").forEach {
                File(dir, it).writeText("x")
            }
            pruneUpdateCache(dir, installedVersionCode = 32)
            assertTrue(dir.list().isNullOrEmpty())
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun installConfirmationStartsDirectlyOnlyWhenVisible() {
        assertTrue(installConfirmationMayStartDirectly(ActivityManager.RunningAppProcessInfo.IMPORTANCE_FOREGROUND))
        assertTrue(installConfirmationMayStartDirectly(ActivityManager.RunningAppProcessInfo.IMPORTANCE_VISIBLE))
        assertFalse(
            installConfirmationMayStartDirectly(ActivityManager.RunningAppProcessInfo.IMPORTANCE_FOREGROUND_SERVICE),
        )
        assertFalse(installConfirmationMayStartDirectly(ActivityManager.RunningAppProcessInfo.IMPORTANCE_CACHED))
    }

    @Test
    fun autoUpdateChecksAreHoursApart() {
        assertTrue(autoUpdateCheckDue(nowMs = 5_000, lastCheckAtMs = null, lastCheckFailed = false))
        assertFalse(autoUpdateCheckDue(nowMs = 5_000 + 20_000, lastCheckAtMs = 5_000, lastCheckFailed = false))
        assertFalse(autoUpdateCheckDue(nowMs = 5_000 + 59 * 60_000, lastCheckAtMs = 5_000, lastCheckFailed = true))
        assertTrue(autoUpdateCheckDue(nowMs = 5_000 + 60 * 60_000, lastCheckAtMs = 5_000, lastCheckFailed = true))
        assertFalse(autoUpdateCheckDue(nowMs = 5_000 + 2 * 60 * 60_000, lastCheckAtMs = 5_000, lastCheckFailed = false))
        assertTrue(autoUpdateCheckDue(nowMs = 5_000 + AUTO_UPDATE_CHECK_INTERVAL_MS, lastCheckAtMs = 5_000, lastCheckFailed = false))
        assertTrue(AUTO_UPDATE_RETRY_INTERVAL_MS >= 30 * 60_000)
    }

    @Test
    fun autoCheckIsSkippedWhileDownloadingOrInstalling() {
        assertTrue(autoUpdateCheckBlocked(DistributionUiState(downloadInProgress = true)))
        assertTrue(autoUpdateCheckBlocked(DistributionUiState(installInProgress = true)))
        assertTrue(autoUpdateCheckBlocked(DistributionUiState(inProgress = true)))
        assertFalse(autoUpdateCheckBlocked(DistributionUiState()))
    }

    @Test
    fun sameVersionRecheckKeepsApkSnoozeAndDoesNotReopenSheet() {
        val current = DistributionUiState(
            statusTextRes = R.string.update_status_available,
            availableVersionName = "0.1.99",
            availableVersionCode = 99_999,
            apkPath = "/cache/updates/app-release-99999.apk",
            downloadedBytes = 1_000,
            totalBytes = 1_000,
            showAvailableSheet = false,
            snoozedUntilMs = 123_456,
        )
        val merged = mergeAutoUpdateCheckState(
            current = current,
            outcome = availableOutcome(99_999),
            checkedAt = "now",
            offerSheet = false,
            installedVersionCode = 31,
        )
        assertEquals(current.apkPath, merged.apkPath)
        assertEquals(123_456L, merged.snoozedUntilMs)
        assertFalse(merged.showAvailableSheet)
        assertEquals("now", merged.lastCheckedAt)
    }

    @Test
    fun newVersionOffersTheSheetOnce() {
        val current = DistributionUiState(availableVersionCode = 99_998, snoozedUntilMs = 123_456)
        val merged = mergeAutoUpdateCheckState(current, availableOutcome(99_999), "now", offerSheet = true, installedVersionCode = 31)
        assertTrue(merged.showAvailableSheet)
        assertEquals(0L, merged.snoozedUntilMs)
        assertEquals(99_999L, merged.availableVersionCode)
    }

    @Test
    fun autoCheckDoesNotClobberRunningInstallOrKnownUpdate() {
        val installing = DistributionUiState(availableVersionCode = 99_999, installInProgress = true)
        assertSame(installing, mergeAutoUpdateCheckState(installing, availableOutcome(99_999), "now", true, 31))

        val known = DistributionUiState(availableVersionCode = 99_999, apkPath = "/x.apk")
        val afterError = mergeAutoUpdateCheckState(
            current = known,
            outcome = UpdateCheckOutcome(status = UpdateCheckStatus.ERROR, errorTextRes = R.string.update_error_network),
            checkedAt = "now",
            offerSheet = false,
            installedVersionCode = 31,
        )
        assertEquals("/x.apk", afterError.apkPath)
        assertEquals(99_999L, afterError.availableVersionCode)
    }

    private fun availableOutcome(versionCode: Long): UpdateCheckOutcome {
        val manifest = UpdateManifest(
            schema = 1,
            namespace = "apk-update-v1",
            seq = 1,
            versionCode = versionCode,
            versionName = "0.1.99",
            apkUrl = "app-public-$versionCode.apk",
            apkSize = 1_000,
            sha256 = sha,
            signingCertSha256 = "",
            minSupportedVersion = 0,
            mandatory = false,
            changelogRu = "",
            releasedAt = "",
            timestamp = "2026-09-25T10:00:00Z",
            expiresAt = "2026-12-24T10:00:00Z",
        )
        return UpdateCheckOutcome(
            status = UpdateCheckStatus.AVAILABLE,
            manifest = manifest,
            source = UpdateSource.PLATFORM,
            totalBytes = manifest.apkSize,
        )
    }
}
