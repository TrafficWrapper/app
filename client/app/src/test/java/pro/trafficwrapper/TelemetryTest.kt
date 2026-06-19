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
}
