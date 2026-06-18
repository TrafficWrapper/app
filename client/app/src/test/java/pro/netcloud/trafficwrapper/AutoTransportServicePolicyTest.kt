package pro.netcloud.trafficwrapper

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class AutoTransportServicePolicyTest {
    @Test
    fun socksIpv6ConnectIsRejectedWithoutOpeningUpstream() {
        val policy = socksConnectAddressPolicy(SOCKS5_ATYP_IPV6)

        assertFalse(policy.openUpstream)
        assertArrayEquals(
            byteArrayOf(
                SOCKS5_VERSION.toByte(),
                SOCKS5_REP_ADDRESS_TYPE_NOT_SUPPORTED.toByte(),
                0,
                SOCKS5_ATYP_IPV4.toByte(),
                0,
                0,
                0,
                0,
                0,
                0,
            ),
            policy.rejectReply,
        )
    }

    @Test
    fun socksIpv4AndDomainConnectStillOpenUpstream() {
        val ipv4 = socksConnectAddressPolicy(SOCKS5_ATYP_IPV4)
        val domain = socksConnectAddressPolicy(SOCKS5_ATYP_DOMAIN)

        assertTrue(ipv4.openUpstream)
        assertNull(ipv4.rejectReply)
        assertTrue(domain.openUpstream)
        assertNull(domain.rejectReply)
    }

    @Test
    fun healthProbeTimeoutAllowsLongRealityPaths() {
        assertEquals(7_000, HEALTH_PROBE_TIMEOUT_MS)
    }

    @Test
    fun failedRealityProbeRetriesOnceBeforeHealthLost() {
        assertTrue(shouldRetryRealityProbe(attemptIndex = 0))
        assertFalse(shouldRetryRealityProbe(attemptIndex = 1))
    }

    @Test
    fun flappingPriorityRouteDoesNotPromoteBeforeStableDwell() {
        val nowMs = 100_000L

        assertFalse(
            shouldPromoteRecoveredPriorityRoute(
                inactiveHealthySinceMs = nowMs - TCP_PRIORITY_PROMOTE_DWELL_MS + 1,
                lastHealthLostAtMs = 0,
                recentHealthLostCount = 0,
                nowMs = nowMs,
            ),
        )
        assertFalse(
            shouldPromoteRecoveredPriorityRoute(
                inactiveHealthySinceMs = nowMs - TCP_PRIORITY_PROMOTE_DWELL_MS,
                lastHealthLostAtMs = nowMs - 1_000,
                recentHealthLostCount = 1,
                nowMs = nowMs,
            ),
        )
    }

    @Test
    fun stableInactivePriorityRoutePromotesAfterDwell() {
        val nowMs = 100_000L

        assertTrue(
            shouldPromoteRecoveredPriorityRoute(
                inactiveHealthySinceMs = nowMs - TCP_PRIORITY_PROMOTE_DWELL_MS,
                lastHealthLostAtMs = nowMs - TCP_PRIORITY_PROMOTE_DWELL_MS,
                recentHealthLostCount = 1,
                nowMs = nowMs,
            ),
        )
    }

    @Test
    fun repeatedTcpHealthLostAppliesTemporaryDemotion() {
        assertEquals(0, tcpRouteFlapDemotionMs(TCP_ROUTE_FLAP_THRESHOLD - 1))
        assertEquals(TCP_ROUTE_FLAP_DEMOTE_BASE_MS, tcpRouteFlapDemotionMs(TCP_ROUTE_FLAP_THRESHOLD))
        assertTrue(tcpRouteFlapDemotionMs(TCP_ROUTE_FLAP_THRESHOLD + 2) > TCP_ROUTE_FLAP_DEMOTE_BASE_MS)
    }

    @Test
    fun manualRouteGuardDoesNotFallback() {
        assertEquals(
            "AWG_RU",
            selectRouteWithFallbackPolicy(TransportChoice.AWG_RU, "AWG_RU") { "REALITY2" },
        )
        assertEquals(
            "REALITY2",
            selectRouteWithFallbackPolicy(TransportChoice.AUTO, "AWG_RU") { "REALITY2" },
        )
    }

    @Test
    fun reality2UuidChangeRestartsOnlyWhenLiveAndChanged() {
        assertTrue(
            shouldRestartReality2ForUuid(
                appliedUuid = "11111111-0000-0000-0000-000000000000",
                desiredUuid = "4fad2182-1111-2222-3333-444444444444",
                sidecarAlive = true,
            ),
        )
        assertFalse(
            shouldRestartReality2ForUuid(
                appliedUuid = "4FAD2182-1111-2222-3333-444444444444",
                desiredUuid = "4fad2182-1111-2222-3333-444444444444",
                sidecarAlive = true,
            ),
        )
        assertFalse(
            shouldRestartReality2ForUuid(
                appliedUuid = "11111111-0000-0000-0000-000000000000",
                desiredUuid = "4fad2182-1111-2222-3333-444444444444",
                sidecarAlive = false,
            ),
        )
    }

    @Test
    fun realityUuid8ExtractsFirstEightHexCharacters() {
        assertEquals("4fad2182", realityUuid8("4FAD2182-1111-2222-3333-444444444444"))
        assertEquals("", realityUuid8(""))
    }

    @Test
    fun fastFailRequiresRxStallAndFailedActiveE2eProbe() {
        assertTrue(
            shouldFastFailActiveAwg(
                handshakeEstablished = true,
                carrying = false,
                rxStalled = true,
                activeEndToEndProbeFailed = true,
            ),
        )
    }

    @Test
    fun publicAwgCarryRequiresFreshEndToEndProbe() {
        val nowMs = 100_000L
        assertFalse(
            awgCarryingEvidence(
                handshakeEstablished = true,
                nowMs = nowMs,
                lastRxProgressAtMs = nowMs,
                lastEndToEndProbeAtMs = 0,
                allowEndToEndProbe = true,
                requireEndToEndProbe = true,
            ),
        )
        assertTrue(
            awgCarryingEvidence(
                handshakeEstablished = true,
                nowMs = nowMs,
                lastRxProgressAtMs = 0,
                lastEndToEndProbeAtMs = nowMs,
                allowEndToEndProbe = true,
                requireEndToEndProbe = true,
            ),
        )
    }

    @Test
    fun privateAwgCarryStillAcceptsFreshRxProgress() {
        val nowMs = 100_000L
        assertTrue(
            awgCarryingEvidence(
                handshakeEstablished = true,
                nowMs = nowMs,
                lastRxProgressAtMs = nowMs,
                lastEndToEndProbeAtMs = 0,
                allowEndToEndProbe = false,
                requireEndToEndProbe = false,
            ),
        )
    }

    @Test
    fun idleWithSuccessfulE2eProbeDoesNotFastFail() {
        assertFalse(
            shouldFastFailActiveAwg(
                handshakeEstablished = true,
                carrying = true,
                rxStalled = true,
                activeEndToEndProbeFailed = false,
            ),
        )
        assertFalse(
            shouldFastFailActiveAwg(
                handshakeEstablished = true,
                carrying = false,
                rxStalled = true,
                activeEndToEndProbeFailed = false,
            ),
        )
    }

    @Test
    fun allDeadLongBackoffCanReleaseWakeLockOnlyAfterConsecutiveDeadCycles() {
        assertFalse(
            shouldReleaseWakeLockForAllDeadSleep(
                routeHealthy = false,
                hasUsableRoute = false,
                consecutiveAllDeadCycles = ALL_DEAD_WAKELOCK_RELEASE_CYCLES - 1,
                sleepMs = ALL_DEAD_WAKELOCK_MIN_SLEEP_MS,
            ),
        )
        assertTrue(
            shouldReleaseWakeLockForAllDeadSleep(
                routeHealthy = false,
                hasUsableRoute = false,
                consecutiveAllDeadCycles = ALL_DEAD_WAKELOCK_RELEASE_CYCLES,
                sleepMs = ALL_DEAD_WAKELOCK_MIN_SLEEP_MS,
            ),
        )
    }

    @Test
    fun wakeLockStaysHeldForHealthyOrUsableRoute() {
        assertFalse(
            shouldReleaseWakeLockForAllDeadSleep(
                routeHealthy = true,
                hasUsableRoute = false,
                consecutiveAllDeadCycles = ALL_DEAD_WAKELOCK_RELEASE_CYCLES,
                sleepMs = ALL_DEAD_WAKELOCK_MIN_SLEEP_MS,
            ),
        )
        assertFalse(
            shouldReleaseWakeLockForAllDeadSleep(
                routeHealthy = false,
                hasUsableRoute = true,
                consecutiveAllDeadCycles = ALL_DEAD_WAKELOCK_RELEASE_CYCLES,
                sleepMs = ALL_DEAD_WAKELOCK_MIN_SLEEP_MS,
            ),
        )
    }
}
