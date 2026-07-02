package pro.trafficwrapper

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class UpdateNetworkPolicyTest {
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
