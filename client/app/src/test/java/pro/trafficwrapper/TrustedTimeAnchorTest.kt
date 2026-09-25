package pro.trafficwrapper

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class TrustedTimeAnchorTest {
    private val day = 24 * 60 * 60 * 1000L
    private val now = 1_790_000_000_000L
    private val boot5 = BootIdentity(bootCount = 5, bootWallMs = now - 1_000_000)
    private val boot6 = BootIdentity(bootCount = 6, bootWallMs = now - 500_000)

    @Test
    fun anchorIsExtrapolatedWithinTheSameBoot() {
        val anchor = TrustedTimeAnchor(wallTimeMs = now, elapsedRealtimeMs = 10_000, boot = boot5)
        assertEquals(now + 5_000, anchoredTrustedNowMs(anchor, boot5, 15_000))
        assertNull(anchoredTrustedNowMs(anchor, boot5, 9_000))
    }

    @Test
    fun anchorFromPreviousBootIsNotReusedEvenWithLargerUptime() {
        // APP-M23: the new uptime exceeds the stored one, which the old check could not detect.
        val anchor = TrustedTimeAnchor(wallTimeMs = now - 20 * day, elapsedRealtimeMs = 1_000, boot = boot5)
        assertNull(anchoredTrustedNowMs(anchor, boot6, 50_000))
    }

    @Test
    fun bootWallClockIsUsedWhenTheCounterIsUnavailable() {
        val stored = BootIdentity(bootCount = -1, bootWallMs = now - 1_000_000)
        assertTrue(sameBoot(stored, BootIdentity(-1, now - 1_000_000 + 30_000)))
        assertFalse(sameBoot(stored, BootIdentity(-1, now - 1_000_000 + TRUSTED_TIME_BOOT_WALL_TOLERANCE_MS + 1)))
        assertTrue(sameBoot(boot5, BootIdentity(5, 0)))
        assertFalse(sameBoot(boot5, BootIdentity(6, boot5.bootWallMs)))
    }

    @Test
    fun legacyAnchorWithoutBootIdentityIsIgnored() {
        val legacy = TrustedTimeAnchor(wallTimeMs = now, elapsedRealtimeMs = 10, boot = BootIdentity(-1, 0))
        assertNull(anchoredTrustedNowMs(legacy, boot5, 20))
    }

    @Test
    fun nextAnchorComesFromSignedTimeOnly() {
        // First verified document: the anchor is the signed issued_at, whatever SNTP said.
        val first = nextTrustedTimeAnchor(null, now - day, boot5, 1_000, systemNowMs = now)
        assertEquals(now - day, first.wallTimeMs)
        assertEquals(1_000, first.elapsedRealtimeMs)
        assertEquals(boot5, first.boot)
        // Same boot: the monotonic extrapolation ratchets it; an older signed time cannot rewind it.
        val second = nextTrustedTimeAnchor(first, now - 2 * day, boot5, 61_000, systemNowMs = now)
        assertEquals(now - day + 60_000, second.wallTimeMs)
        // New boot: the old anchor is dropped and the signed time is used again.
        val afterReboot = nextTrustedTimeAnchor(second, now - 3 * day, boot6, 70_000, systemNowMs = now)
        assertEquals(now - 3 * day, afterReboot.wallTimeMs)
        assertEquals(boot6, afterReboot.boot)
    }

    @Test
    fun poisonedAnchorIsCappedNearSystemAndSignedTime() {
        // APP-M6: an anchor pushed far into the future (older versions persisted SNTP time) is
        // pulled back to at most max(system, signed) + lead.
        val poisoned = TrustedTimeAnchor(wallTimeMs = now + 120 * day, elapsedRealtimeMs = 1_000, boot = boot5)
        val next = nextTrustedTimeAnchor(poisoned, now - day, boot5, 2_000, systemNowMs = now)
        assertEquals(now + TRUSTED_TIME_MAX_LEAD_MS, next.wallTimeMs)
    }

    @Test
    fun rendezvousStateDoesNotPersistCallerWallTime() {
        val current = StoredRendezvousState(maxSeenRendezvousSeq = 3, discoverySinks = listOf("a"))
        val next = nextRendezvousState(
            current = current,
            seq = 4,
            issuedAtMs = now - day,
            elapsedRealtimeMs = 5_000,
            boot = boot5,
            systemNowMs = now,
            discoverySinks = emptyList(),
        )
        assertEquals(now - day, next.trustedWallTimeMs)
        assertEquals(5_000, next.trustedElapsedRealtimeMs)
        assertEquals(5, next.trustedBootCount)
        assertEquals(4, next.maxSeenRendezvousSeq)
        assertEquals(now - day, next.lastValidIssuedAtMs)
        assertEquals(listOf("a"), next.discoverySinks)
    }

    @Test
    fun releaseStateRoundTripsTheAnchor() {
        val anchor = TrustedTimeAnchor(now, 1_234, boot5)
        val state = StoredReleaseState(maxSeenVersionCode = 9).withTrustedAnchor(anchor)
        assertEquals(anchor, state.trustedAnchor)
        assertEquals(9, state.maxSeenVersionCode)
        assertNull(StoredReleaseState().trustedAnchor)
    }
}
