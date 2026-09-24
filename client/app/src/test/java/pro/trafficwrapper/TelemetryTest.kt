package pro.trafficwrapper

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class TelemetryTest {
    @Test
    fun telemetryDeviceIDIsStablePublicKeyAlias() {
        val publicKey = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEtrafficwrapper-test-key"

        val first = Telemetry.telemetryDeviceIDForPublicKey(publicKey)
        val second = Telemetry.telemetryDeviceIDForPublicKey(publicKey)

        assertEquals(first, second)
        assertTrue(first.startsWith("twpk_"))
        assertNotEquals("9774d56d682e549c", first)
    }

    @Test
    fun telemetryFlushDispositionDropsPoisonAndShrinksPayloadTooLarge() {
        assertEquals(Telemetry.TelemetryFlushDisposition.SUCCESS, Telemetry.telemetryFlushDispositionForHttpCode(204))
        assertEquals(Telemetry.TelemetryFlushDisposition.DROP, Telemetry.telemetryFlushDispositionForHttpCode(400))
        assertEquals(Telemetry.TelemetryFlushDisposition.DROP, Telemetry.telemetryFlushDispositionForHttpCode(401))
        assertEquals(Telemetry.TelemetryFlushDisposition.DROP, Telemetry.telemetryFlushDispositionForHttpCode(403))
        assertEquals(Telemetry.TelemetryFlushDisposition.DROP, Telemetry.telemetryFlushDispositionForHttpCode(422))
        assertEquals(Telemetry.TelemetryFlushDisposition.SHRINK_RETRY, Telemetry.telemetryFlushDispositionForHttpCode(413))
        assertEquals(Telemetry.TelemetryFlushDisposition.RETRY, Telemetry.telemetryFlushDispositionForHttpCode(500))
    }

    @Test
    fun telemetryBatchLimitShrinksWithinBounds() {
        assertEquals(16 * 1024, Telemetry.telemetryBatchLimitAfterPayloadTooLarge(32 * 1024))
        assertEquals(Telemetry.TELEMETRY_MIN_BATCH_BYTES, Telemetry.telemetryBatchLimitAfterPayloadTooLarge(1))
        assertEquals(Telemetry.TELEMETRY_MAX_BATCH_BYTES, Telemetry.telemetryBatchLimitAfterPayloadTooLarge(128 * 1024))
    }

    @Test
    fun telemetryBatchSelectionHonorsByteLimit() {
        val lines = listOf(
            Telemetry.telemetryQueuedLineForTest(kind = "a", payloadBytes = 256),
            Telemetry.telemetryQueuedLineForTest(kind = "b", payloadBytes = 4096),
            Telemetry.telemetryQueuedLineForTest(kind = "c", payloadBytes = 256),
        )

        val small = Telemetry.telemetryBatchSelectionForTest(lines, maxPayloadBytes = 2 * 1024)
        assertEquals(1, small.events)
        assertEquals(1, small.consumedLines)
        assertTrue(small.payloadBytes <= 2 * 1024)

        val large = Telemetry.telemetryBatchSelectionForTest(lines, maxPayloadBytes = 16 * 1024)
        assertEquals(3, large.events)
        assertEquals(3, large.consumedLines)
    }

    @Test
    fun telemetryBatchesRegularFlushesByInterval() {
        val now = 10_000_000L
        // Just after a successful flush: a single event waits for the min interval.
        assertFalse(
            Telemetry.telemetryShouldFlush(
                force = false,
                nowMs = now,
                pendingEvents = 1,
                nextFlushAtMs = now + Telemetry.FLUSH_MIN_INTERVAL_MS - 1,
                backoffUntilMs = 0L,
                lastAttemptAtMs = now - 1_000L,
            ),
        )
        assertTrue(
            Telemetry.telemetryShouldFlush(
                force = false,
                nowMs = now,
                pendingEvents = 1,
                nextFlushAtMs = now,
                backoffUntilMs = 0L,
                lastAttemptAtMs = now - Telemetry.FLUSH_MIN_INTERVAL_MS,
            ),
        )
        // Enough events accumulated: flush early, but still spaced.
        assertTrue(
            Telemetry.telemetryShouldFlush(
                force = false,
                nowMs = now,
                pendingEvents = Telemetry.FLUSH_EVENT_THRESHOLD,
                nextFlushAtMs = now + 60_000L,
                backoffUntilMs = 0L,
                lastAttemptAtMs = now - Telemetry.FORCE_FLUSH_MIN_INTERVAL_MS,
            ),
        )
        assertFalse(
            Telemetry.telemetryShouldFlush(
                force = false,
                nowMs = now,
                pendingEvents = Telemetry.FLUSH_EVENT_THRESHOLD,
                nextFlushAtMs = now + 60_000L,
                backoffUntilMs = 0L,
                lastAttemptAtMs = now - 1_000L,
            ),
        )
    }

    @Test
    fun telemetryForcedFlushIsRateLimitedAndRespectsBackoff() {
        val now = 10_000_000L
        assertTrue(
            Telemetry.telemetryShouldFlush(
                force = true,
                nowMs = now,
                pendingEvents = 1,
                nextFlushAtMs = now + 60_000L,
                backoffUntilMs = 0L,
                lastAttemptAtMs = 0L,
            ),
        )
        assertFalse(
            Telemetry.telemetryShouldFlush(
                force = true,
                nowMs = now,
                pendingEvents = 1,
                nextFlushAtMs = 0L,
                backoffUntilMs = 0L,
                lastAttemptAtMs = now - 1_000L,
            ),
        )
        assertFalse(
            Telemetry.telemetryShouldFlush(
                force = true,
                nowMs = now,
                pendingEvents = 5,
                nextFlushAtMs = 0L,
                backoffUntilMs = now + 1L,
                lastAttemptAtMs = 0L,
            ),
        )
        assertFalse(
            Telemetry.telemetryShouldFlush(
                force = true,
                nowMs = now,
                pendingEvents = 0,
                nextFlushAtMs = 0L,
                backoffUntilMs = 0L,
                lastAttemptAtMs = 0L,
            ),
        )
    }

    @Test
    fun telemetryBatchSelectionIsLinearAndStopsAtBatchLimit() {
        val lines = List(500) { Telemetry.telemetryQueuedLineForTest(kind = "k$it", payloadBytes = 16) }

        val selection = Telemetry.telemetryBatchSelectionForTest(lines, maxPayloadBytes = Telemetry.TELEMETRY_MAX_BATCH_BYTES)

        assertEquals(20, selection.events)
        assertEquals(20, selection.consumedLines)
        assertTrue(selection.payloadBytes <= Telemetry.TELEMETRY_MAX_BATCH_BYTES)
    }
}
