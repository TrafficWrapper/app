package pro.trafficwrapper

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class TelemetryClockTest {
    @Test
    fun dedupUsesMonotonicWindowAndSurvivesBackwardsTime() {
        assertTrue(Telemetry.telemetryDedupAccepts(previousAtMs = null, nowMs = 5_000L))
        assertFalse(Telemetry.telemetryDedupAccepts(previousAtMs = 1_000L, nowMs = 20_000L))
        assertTrue(Telemetry.telemetryDedupAccepts(previousAtMs = 1_000L, nowMs = 31_000L))
        // A timestamp from "the future" (wall clock corrected backwards) must not suppress events
        // for the length of the correction (APP-L28).
        assertTrue(Telemetry.telemetryDedupAccepts(previousAtMs = 10_000_000L, nowMs = 5_000L))
    }

    @Test
    fun serverTimeOffsetComesOnlyFromTheHeader() {
        assertEquals(60_000L, Telemetry.telemetryServerTimeOffsetMs(" 1700000060000 ", 1_700_000_000_000L))
        assertEquals(-3_600_000L, Telemetry.telemetryServerTimeOffsetMs("1700000000000", 1_700_003_600_000L))
        assertNull(Telemetry.telemetryServerTimeOffsetMs(null, 1L))
        assertNull(Telemetry.telemetryServerTimeOffsetMs("soon", 1L))
        assertNull(Telemetry.telemetryServerTimeOffsetMs("0", 1L))
    }

    @Test
    fun only422StaleTimestampWithServerTimeIsRetried() {
        assertTrue(Telemetry.telemetryStaleTimestampRetryable(422, true, """{"error":"stale_timestamp"}"""))
        // Old worker (no X-TW-Server-Time): nothing to correct with, 422 stays final.
        assertFalse(Telemetry.telemetryStaleTimestampRetryable(422, false, """{"error":"stale_timestamp"}"""))
        assertFalse(Telemetry.telemetryStaleTimestampRetryable(422, true, """{"error":"replay"}"""))
        assertFalse(Telemetry.telemetryStaleTimestampRetryable(422, true, "telemetry stale_timestamp"))
        assertFalse(Telemetry.telemetryStaleTimestampRetryable(502, true, """{"error":"stale_timestamp"}"""))
        assertEquals(Telemetry.TelemetryFlushDisposition.DROP, Telemetry.telemetryFlushDispositionForHttpCode(422))
    }

    @Test
    fun eventContextIsStoredWithTheQueuedEvent() {
        val context = mapOf<String, Any?>(
            "net" to "cell",
            "metered" to true,
            "route" to "AWG_RU",
            "healthy" to false,
            "last_exch_s" to 42L,
            "unknown_key" to "dropped",
        )
        val parsed = Telemetry.telemetryContextRoundTripForTest(context)
        assertEquals("cell", parsed["net"])
        assertEquals(true, parsed["metered"])
        assertEquals("AWG_RU", parsed["route"])
        assertEquals(false, parsed["healthy"])
        assertEquals(42L, (parsed["last_exch_s"] as Number).toLong())
        assertFalse(parsed.containsKey("unknown_key"))
        // Spool lines written by an older build carry no context.
        assertTrue(Telemetry.telemetryContextOfLineForTest(Telemetry.telemetryQueuedLineForTest()).isEmpty())
    }
}
