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
    }
}
