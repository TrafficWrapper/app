package pro.trafficwrapper

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class TwVpnServicePolicyTest {
    @Test
    fun alwaysOnSystemStartIsTreatedAsVpnStart() {
        assertEquals(VpnStartKind.SYSTEM_START, vpnStartKind("android.net.VpnService"))
        assertEquals(VpnStartKind.SYSTEM_START, vpnStartKind(null))
    }

    @Test
    fun appActionsKeepTheirMeaning() {
        assertEquals(VpnStartKind.APP_START, vpnStartKind(TwVpnService.ACTION_VPN_START))
        assertEquals(VpnStartKind.STOP, vpnStartKind(TwVpnService.ACTION_VPN_STOP))
        assertEquals(VpnStartKind.IGNORE, vpnStartKind("pro.trafficwrapper.action.SOMETHING_ELSE"))
    }
}

class TwVpnServiceRestorePolicyTest {
    @Test
    fun nullIntentIsAStickyRestartNotAnAlwaysOnStart() {
        assertEquals(VpnStartKind.STICKY_RESTART, vpnStartKindForIntent(hasIntent = false, action = null))
        // An intent without action (older always-on starts) keeps the system-start meaning.
        assertEquals(VpnStartKind.SYSTEM_START, vpnStartKindForIntent(hasIntent = true, action = null))
        assertEquals(
            VpnStartKind.SYSTEM_START,
            vpnStartKindForIntent(hasIntent = true, action = VPN_SERVICE_INTERFACE_ACTION),
        )
        assertEquals(
            VpnStartKind.APP_START,
            vpnStartKindForIntent(hasIntent = true, action = TwVpnService.ACTION_VPN_START),
        )
        assertEquals(VpnStartKind.STOP, vpnStartKindForIntent(hasIntent = true, action = TwVpnService.ACTION_VPN_STOP))
    }

    @Test
    fun stickyRestartRestoresOnlyARequestedVpn() {
        assertTrue(shouldRestoreVpnOnStickyRestart(true, true, true, true))
        assertFalse(shouldRestoreVpnOnStickyRestart(false, true, true, true))
        // User switched VPN off (or it was revoked) before the process died: stay off.
        assertFalse(shouldRestoreVpnOnStickyRestart(true, false, true, true))
        // Transport stopped by the user: a VPN without transport would carry nothing.
        assertFalse(shouldRestoreVpnOnStickyRestart(true, true, false, true))
        // Another VPN app took over while we were dead.
        assertFalse(shouldRestoreVpnOnStickyRestart(true, true, true, false))
    }
}

class NetworkRecoveryGateTest {
    @Test
    fun repeatedCallbacksForTheSameNetworkWaitForTheBackoff() {
        val gate = NetworkRecoveryGate<String>()
        assertTrue(gate.shouldReconnectNow("wifi"))
        // Signal strength / link property updates on the same network must not rebuild again.
        repeat(10) { assertFalse(gate.shouldReconnectNow("wifi")) }
    }

    @Test
    fun theNetworkJustTriedDoesNotTriggerAnImmediateRetry() {
        val gate = NetworkRecoveryGate<String>()
        gate.onAttempt("wifi")
        // Registering the blackhole callback replays the current network: no retry loop.
        assertFalse(gate.shouldReconnectNow("wifi"))
        gate.onAttempt(null)
        assertFalse(gate.shouldReconnectNow("wifi"))
    }

    @Test
    fun aNewOrReturningNetworkReconnectsImmediately() {
        val gate = NetworkRecoveryGate<String>()
        gate.onAttempt("wifi")
        assertTrue(gate.shouldReconnectNow("cell"))
        assertFalse(gate.shouldReconnectNow("cell"))
        gate.onLost("wifi")
        assertTrue(gate.shouldReconnectNow("wifi"))
        gate.reset()
        assertTrue(gate.shouldReconnectNow("cell"))
    }
}
