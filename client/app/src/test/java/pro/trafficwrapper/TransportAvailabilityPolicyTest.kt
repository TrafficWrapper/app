package pro.trafficwrapper

import java.io.ByteArrayInputStream
import java.io.IOException
import java.io.InputStream
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class TransportAvailabilityPolicyTest {
    /**
     * Minimal model of the worker loop for one inactive TCP route: it is probed per
     * [shouldProbeTcpRoute], its probe result stays valid for [healthMaxAgeMs] (the worker's
     * XRAY_READY_PROBE_MAX_AGE_MS), health loss resets the continuous-health timer, and it is
     * usable once healthy and dwelled. Returns the time it became usable, or null.
     */
    private fun timeUntilStandbyUsable(
        activeRouteHealthy: Boolean,
        probeSucceeds: (Long) -> Boolean = { true },
        horizonMs: Long,
        loopStepMs: Long = PROBE_INTERVAL_MS,
        healthMaxAgeMs: Long = 15_000L,
        dwellMs: Long = 30_000L,
    ): Long? {
        var lastProbeAtMs = 0L
        var lastOkAtMs = 0L
        var consecutiveOk = 0
        var healthySinceMs = 0L
        var nowMs = 1_000L
        while (nowMs <= horizonMs) {
            if (shouldProbeTcpRoute(nowMs, lastProbeAtMs, routeIsActive = false, activeRouteHealthy = activeRouteHealthy)) {
                lastProbeAtMs = nowMs
                if (probeSucceeds(nowMs)) {
                    lastOkAtMs = nowMs
                    consecutiveOk++
                } else {
                    lastOkAtMs = 0L
                    consecutiveOk = 0
                }
            }
            val healthy = lastOkAtMs > 0L && nowMs - lastOkAtMs <= healthMaxAgeMs
            if (!healthy) healthySinceMs = 0L else if (healthySinceMs == 0L) healthySinceMs = nowMs
            if (healthy && tcpRouteDwelled(healthySinceMs, consecutiveOk, nowMs, dwellMs)) return nowMs
            nowMs += loopStepMs
        }
        return null
    }

    @Test
    fun deadAwgFailsOverToHealthyRealityQuickly() {
        // Active AWG is dead (UDP blocked, core still "started"); REALITY next to it works.
        val usableAt = timeUntilStandbyUsable(activeRouteHealthy = false, horizonMs = 5 * 60_000L)
        assertNotNull("REALITY must become usable while AWG is dead", usableAt)
        assertTrue("failover target ready within 20 s, was $usableAt", usableAt!! <= 21_000L)
    }

    @Test
    fun realityFailsOverToReality2AndBack() {
        // Same policy for REALITY -> REALITY2 and REALITY2 -> REALITY: the inactive sidecar is
        // kept warm while the active one is unhealthy.
        for (step in listOf(PROBE_INTERVAL_MS, 8_000L)) {
            val usableAt = timeUntilStandbyUsable(activeRouteHealthy = false, horizonMs = 2 * 60_000L, loopStepMs = step)
            assertNotNull("standby TCP route must become usable (loop step $step)", usableAt)
        }
    }

    @Test
    fun standbyProbesAreRareWhileActiveRouteIsHealthyButStillDwell() {
        assertFalse(shouldProbeTcpRoute(100_000L, 50_000L, routeIsActive = false, activeRouteHealthy = true))
        assertTrue(shouldProbeTcpRoute(125_000L, 50_000L, routeIsActive = false, activeRouteHealthy = true))
        // Three good probes in a row complete the dwell even with rare probes.
        val usableAt = timeUntilStandbyUsable(activeRouteHealthy = true, horizonMs = 10 * 60_000L)
        assertNotNull(usableAt)
    }

    @Test
    fun standbyProbeRunsImmediatelyWhenActiveRouteTurnsUnhealthy() {
        // Probed 60 s ago while the active route was healthy: due at once now that it is not.
        assertTrue(shouldProbeTcpRoute(160_000L, 100_000L, routeIsActive = false, activeRouteHealthy = false))
        assertTrue(shouldProbeTcpRoute(10_000L, 0L, routeIsActive = false, activeRouteHealthy = true))
        assertTrue(shouldProbeTcpRoute(102_500L, 100_000L, routeIsActive = true, activeRouteHealthy = true))
    }

    @Test
    fun flappingStandbyNeverDwells() {
        var probes = 0
        val usableAt = timeUntilStandbyUsable(
            activeRouteHealthy = false,
            probeSucceeds = { probes++ % 2 == 0 },
            horizonMs = 5 * 60_000L,
        )
        assertNull("a route failing every other probe must not become a failover target", usableAt)
        assertFalse(tcpRouteDwelled(healthySinceMs = 0L, consecutiveOkProbes = 2, nowMs = 60_000L, dwellMs = 30_000L))
    }

    @Test
    fun oneSilentDestinationDoesNotStallAHealthyRoute() {
        assertFalse(tcpUserSessionsIndicateStall(stalledDestinations = 1, hasRecentUserDownlinkProgress = true))
        assertTrue(tcpUserSessionsIndicateStall(stalledDestinations = 1, hasRecentUserDownlinkProgress = false))
        assertTrue(tcpUserSessionsIndicateStall(stalledDestinations = 2, hasRecentUserDownlinkProgress = true))
        assertFalse(tcpUserSessionsIndicateStall(stalledDestinations = 0, hasRecentUserDownlinkProgress = false))
    }

    @Test
    fun activeRouteIsNotDemotedWhileOtherSessionsReceiveData() {
        assertFalse(shouldDemoteActiveTcpRouteAfterStallGuarded(true, true, hasRecentUserDownlinkProgress = true, stalledDestinations = 1))
        assertTrue(shouldDemoteActiveTcpRouteAfterStallGuarded(true, true, hasRecentUserDownlinkProgress = false, stalledDestinations = 1))
        assertTrue(shouldDemoteActiveTcpRouteAfterStallGuarded(true, true, hasRecentUserDownlinkProgress = true, stalledDestinations = 2))
        assertFalse(shouldDemoteActiveTcpRouteAfterStallGuarded(true, false, hasRecentUserDownlinkProgress = false, stalledDestinations = 3))
    }

    private enum class Ev(val disruptive: Boolean) { LOST(true), AVAILABLE(false), SWITCHED(true), SCREEN_ON(false) }

    @Test
    fun harmlessEventDoesNotHideNetworkSwitch() {
        val pending = PendingLifecycleEvents<Ev> { it.disruptive }
        pending.add(Ev.SWITCHED)
        pending.add(Ev.SCREEN_ON)
        val batch = pending.drain()!!
        assertTrue(batch.marksTunnelDisruption)
        assertEquals(listOf(Ev.SWITCHED, Ev.SCREEN_ON), batch.events)
        assertNull(pending.drain())
        assertFalse(pending.isPending())
    }

    @Test
    fun lostThenAvailableStaysDisruptiveAndKeepsAvailable() {
        val pending = PendingLifecycleEvents<Ev> { it.disruptive }
        pending.add(Ev.LOST)
        pending.add(Ev.AVAILABLE)
        val batch = pending.drain()!!
        assertTrue(batch.marksTunnelDisruption)
        assertTrue(Ev.AVAILABLE in batch.events)
    }

    @Test
    fun pendingBackstopIsNotPushedLater() {
        val interval = 10 * 60_000L
        assertTrue(shouldKeepScheduledBackstop(scheduledAtMs = 500_000L, nowMs = 200_000L, intervalMs = interval))
        assertFalse("fired or never scheduled", shouldKeepScheduledBackstop(0L, 200_000L, interval))
        assertFalse("already due", shouldKeepScheduledBackstop(199_000L, 200_000L, interval))
        assertFalse("implausibly far (clock reset)", shouldKeepScheduledBackstop(10_000_000L, 200_000L, interval))
    }

    @Test
    fun ownProbeTrafficIsNotTunnelActivity() {
        assertEquals(0L, idleSignalRxAtMs(0L, 50_000L, rxAdvanced = true, selfTrafficInCycle = true, userTrafficAtMs = 0L))
        assertEquals(50_000L, idleSignalRxAtMs(0L, 50_000L, rxAdvanced = true, selfTrafficInCycle = false, userTrafficAtMs = 0L))
        assertEquals(42_000L, idleSignalRxAtMs(0L, 50_000L, rxAdvanced = true, selfTrafficInCycle = true, userTrafficAtMs = 42_000L))
        val sleep = probeLoopSleepMs(
            stable = true,
            nowMs = 60_000L,
            lastTunnelRxProgressAtMs = idleSignalRxAtMs(0L, 60_000L, true, true, 0L),
            reconnectBackoffMs = 1_000L,
            screenInteractive = false,
            screenOffStableCycles = 3,
        )
        assertTrue("screen-off idle backoff applies despite own probes, was $sleep", sleep > SCREEN_OFF_ACTIVE_PROBE_INTERVAL_MS)
    }

    @Test
    fun snapshotFreshnessFollowsThePlannedSleep() {
        val fiveMinutes = 5 * 60_000L
        assertFalse(shouldSkipNonDestructiveForegroundResync(true, 1L, snapshotAgeMs = fiveMinutes, trafficAgeMs = 0L))
        assertTrue(
            shouldSkipNonDestructiveForegroundResync(
                true,
                1L,
                snapshotAgeMs = fiveMinutes,
                trafficAgeMs = 0L,
                plannedSleepMs = 8 * 60_000L,
            ),
        )
        assertFalse(
            shouldSkipNonDestructiveForegroundResync(
                true,
                1L,
                snapshotAgeMs = 9 * 60_000L,
                trafficAgeMs = 0L,
                plannedSleepMs = 8 * 60_000L,
            ),
        )
    }

    @Test
    fun stoppedWorkerCannotPublish() {
        assertTrue(shouldPublishWorkerState(publishGeneration = null, currentGeneration = 5, workerActive = false))
        assertTrue(shouldPublishWorkerState(publishGeneration = 5, currentGeneration = 5, workerActive = true))
        assertFalse(shouldPublishWorkerState(publishGeneration = 5, currentGeneration = 5, workerActive = false))
        assertFalse(shouldPublishWorkerState(publishGeneration = 4, currentGeneration = 5, workerActive = true))
    }

    @Test
    fun restartedActiveSidecarBumpsTheUpstreamGeneration() {
        assertEquals(8L, activeUpstreamGenerationAfterRestart(18081, 7L, restartedPort = 18081, restartedGeneration = 8L))
        assertEquals(7L, activeUpstreamGenerationAfterRestart(18081, 7L, restartedPort = 18083, restartedGeneration = 3L))
    }

    private class EndlessStream : InputStream() {
        var served = 0L
        override fun read(): Int {
            served++
            return 'a'.code
        }
        override fun read(b: ByteArray, off: Int, len: Int): Int {
            java.util.Arrays.fill(b, off, off + len, 'a'.code.toByte())
            served += len
            return len
        }
    }

    @Test
    fun configBodyReadIsBounded() {
        val endless = EndlessStream()
        try {
            readBodyWithLimit(endless, 256 * 1024)
            fail("an endless body must be rejected")
        } catch (_: IOException) {
        }
        assertTrue(endless.served < 300 * 1024)
        assertEquals(5, readBodyWithLimit(ByteArrayInputStream("hello".toByteArray()), 16).size)
    }

    @Test
    fun telemetryResponseReadStopsAtLimit() {
        val endless = EndlessStream()
        assertEquals(1024, readAtMostBytes(endless, 1024).size)
        assertTrue(endless.served <= 1024)
        assertEquals(3, readAtMostBytes(ByteArrayInputStream("abc".toByteArray()), 1024).size)
    }
}
