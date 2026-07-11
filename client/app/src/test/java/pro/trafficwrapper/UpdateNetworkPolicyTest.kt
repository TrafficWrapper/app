package pro.trafficwrapper

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class UpdateNetworkPolicyTest {
    @Test
    fun autoDownloadWaitsForCarryButMandatoryMinVersionCanProceed() {
        val enabled = UpdateAutoDownloadPolicy(
            autoDownloadEnabled = true,
            wifiEnabled = true,
            mobileEnabled = false,
        )
        val mandatoryByMinVersion = updateManifestForPolicyTest(
            minSupportedVersion = BuildConfig.VERSION_CODE.toLong() + 1,
        ).requiresInstalledUpdate()

        assertFalse(
            shouldAutoDownloadUpdateWithCarry(
                enabled,
                UpdateNetworkKind.WIFI,
                carrying = false,
                mandatory = false,
            ),
        )
        assertTrue(
            shouldAutoDownloadUpdateWithCarry(
                enabled,
                UpdateNetworkKind.WIFI,
                carrying = true,
                mandatory = false,
            ),
        )
        assertTrue(mandatoryByMinVersion)
        assertTrue(
            shouldAutoDownloadUpdateWithCarry(
                enabled,
                UpdateNetworkKind.WIFI,
                carrying = false,
                mandatory = mandatoryByMinVersion,
            ),
        )
        assertFalse(
            shouldAutoDownloadUpdateWithCarry(
                enabled.copy(autoDownloadEnabled = false),
                UpdateNetworkKind.WIFI,
                carrying = true,
                mandatory = true,
            ),
        )
    }

    @Test
    fun autoDownloadPolicyKeepsDefaultBehaviorOff() {
        val policy = UpdateAutoDownloadPolicy(
            autoDownloadEnabled = false,
            wifiEnabled = true,
            mobileEnabled = true,
        )

        assertFalse(shouldAutoDownloadUpdate(policy, UpdateNetworkKind.WIFI))
        assertFalse(shouldAutoDownloadUpdate(policy, UpdateNetworkKind.CELLULAR))
    }

    @Test
    fun autoDownloadPolicyAllowsWifiAndBlocksCellularByDefault() {
        val policy = UpdateAutoDownloadPolicy(
            autoDownloadEnabled = true,
            wifiEnabled = true,
            mobileEnabled = false,
        )

        assertTrue(shouldAutoDownloadUpdate(policy, UpdateNetworkKind.WIFI))
        assertTrue(shouldAutoDownloadUpdate(policy, UpdateNetworkKind.ETHERNET))
        assertFalse(shouldAutoDownloadUpdate(policy, UpdateNetworkKind.CELLULAR))
        assertFalse(shouldAutoDownloadUpdate(policy, UpdateNetworkKind.METERED))
        assertFalse(shouldAutoDownloadUpdate(policy, UpdateNetworkKind.NONE))
    }

    @Test
    fun autoDownloadPolicyAllowsCellularOnlyWhenOptedIn() {
        val policy = UpdateAutoDownloadPolicy(
            autoDownloadEnabled = true,
            wifiEnabled = true,
            mobileEnabled = true,
        )

        assertTrue(shouldAutoDownloadUpdate(policy, UpdateNetworkKind.CELLULAR))
        assertTrue(shouldAutoDownloadUpdate(policy, UpdateNetworkKind.METERED))
    }

    @Test
    fun meteredWifiRequiresMobileOptIn() {
        val kind = classifyUpdateNetworkCapabilities(
            wifi = true,
            cellular = false,
            ethernet = false,
            vpn = false,
            internet = true,
            notMetered = false,
        )
        assertTrue(kind == UpdateNetworkKind.METERED)

        val wifiOnly = UpdateAutoDownloadPolicy(
            autoDownloadEnabled = true,
            wifiEnabled = true,
            mobileEnabled = false,
        )
        assertFalse(shouldAutoDownloadUpdate(wifiOnly, kind!!))

        val mobileAllowed = wifiOnly.copy(mobileEnabled = true)
        assertTrue(shouldAutoDownloadUpdate(mobileAllowed, kind))
    }

    @Test
    fun activeCellularWinsOverFallbackWifi() {
        val selected = chooseUpdateNetworkKind(
            activeKind = UpdateNetworkKind.CELLULAR,
            underlyingKinds = emptyList(),
            fallbackKinds = listOf(UpdateNetworkKind.WIFI),
        )

        assertTrue(selected == UpdateNetworkKind.CELLULAR)
    }

    @Test
    fun fallbackTreatsAnyMeteredCandidateAsMetered() {
        val selected = chooseUpdateNetworkKind(
            activeKind = null,
            underlyingKinds = emptyList(),
            fallbackKinds = listOf(UpdateNetworkKind.WIFI, UpdateNetworkKind.METERED),
        )

        assertTrue(selected == UpdateNetworkKind.METERED)
    }
}

private fun updateManifestForPolicyTest(minSupportedVersion: Long): UpdateManifest =
    UpdateManifest(
        schema = 1,
        namespace = "update-v1",
        seq = 1,
        versionCode = BuildConfig.VERSION_CODE.toLong() + 1,
        versionName = "test",
        apkUrl = "app.apk",
        apkSize = 1,
        sha256 = "sha256",
        signingCertSha256 = "cert",
        minSupportedVersion = minSupportedVersion,
        mandatory = false,
        changelogRu = "",
        releasedAt = "2030-01-01T00:00:00Z",
        timestamp = "2030-01-01T00:00:00Z",
        expiresAt = "2030-01-02T00:00:00Z",
    )
