package pro.trafficwrapper

import org.junit.Assert.assertEquals
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
}
