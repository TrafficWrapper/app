package pro.trafficwrapper

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.InetAddress
import java.time.Instant
import kotlin.math.abs

class ClockDiagnosticsTest {
    @Test
    fun validSntpResponseAfter2036ComputesOffsetWithCorrectEra() {
        val expectedAddress = InetAddress.getByName("203.0.113.10")
        val t1 = Instant.parse("2037-02-01T00:00:00Z").toEpochMilli()
        val t4 = t1 + 40
        val requestTransmit = ntpTimestamp(t1)
        val response = validResponse(
            requestTransmit = requestTransmit,
            receiveTimeMs = t1 + 10,
            transmitTimeMs = t1 + 30,
        )

        val offset = ClockDiagnostics.sntpOffsetFromResponse(
            data = response,
            length = response.size,
            responseAddress = expectedAddress,
            expectedAddress = expectedAddress,
            requestTransmitTimestamp = requestTransmit,
            requestUnixTimeMs = t1,
            responseReceivedUnixTimeMs = t4,
        )

        requireNotNull(offset)
        assertTrue(abs(offset) <= 1L)
    }

    @Test
    fun sntpValidationRejectsSpoofedOrMalformedResponses() {
        val expectedAddress = InetAddress.getByName("203.0.113.10")
        val wrongAddress = InetAddress.getByName("203.0.113.11")
        val t1 = Instant.parse("2026-06-18T10:00:00Z").toEpochMilli()
        val requestTransmit = ntpTimestamp(t1)
        val response = validResponse(requestTransmit, t1 + 10, t1 + 20)

        assertNull(offset(response, wrongAddress, expectedAddress, requestTransmit, t1))

        val clientMode = response.copyOf()
        clientMode[0] = 0x23
        assertNull(offset(clientMode, expectedAddress, expectedAddress, requestTransmit, t1))

        val invalidStratum = response.copyOf()
        invalidStratum[1] = 0
        assertNull(offset(invalidStratum, expectedAddress, expectedAddress, requestTransmit, t1))

        val wrongOrigin = response.copyOf()
        wrongOrigin[24] = (wrongOrigin[24].toInt() xor 0x01).toByte()
        assertNull(offset(wrongOrigin, expectedAddress, expectedAddress, requestTransmit, t1))
    }

    private fun offset(
        data: ByteArray,
        responseAddress: InetAddress,
        expectedAddress: InetAddress,
        requestTransmit: ByteArray,
        requestUnixTimeMs: Long,
    ): Long? =
        ClockDiagnostics.sntpOffsetFromResponse(
            data = data,
            length = data.size,
            responseAddress = responseAddress,
            expectedAddress = expectedAddress,
            requestTransmitTimestamp = requestTransmit,
            requestUnixTimeMs = requestUnixTimeMs,
            responseReceivedUnixTimeMs = requestUnixTimeMs + 30,
        )

    private fun validResponse(
        requestTransmit: ByteArray,
        receiveTimeMs: Long,
        transmitTimeMs: Long,
    ): ByteArray =
        ByteArray(NTP_PACKET_SIZE).also { response ->
            response[0] = 0x24
            response[1] = 2
            requestTransmit.copyInto(response, NTP_ORIGINATE_TIME_OFFSET)
            writeNtpTimestamp(response, NTP_RECEIVE_TIME_OFFSET, receiveTimeMs)
            writeNtpTimestamp(response, NTP_TRANSMIT_TIME_OFFSET, transmitTimeMs)
        }

    private fun ntpTimestamp(unixTimeMs: Long): ByteArray =
        ByteArray(NTP_TIMESTAMP_SIZE).also { writeNtpTimestamp(it, 0, unixTimeMs) }

    private fun writeNtpTimestamp(data: ByteArray, offset: Int, unixTimeMs: Long) {
        val seconds = unixTimeMs / 1_000L + NTP_EPOCH_OFFSET_SECONDS
        val fraction = ((unixTimeMs % 1_000L) * UINT32_SCALE) / 1_000L
        writeUint32(data, offset, seconds)
        writeUint32(data, offset + 4, fraction)
    }

    private fun writeUint32(data: ByteArray, offset: Int, value: Long) {
        data[offset] = (value ushr 24).toByte()
        data[offset + 1] = (value ushr 16).toByte()
        data[offset + 2] = (value ushr 8).toByte()
        data[offset + 3] = value.toByte()
    }

    private companion object {
        private const val NTP_PACKET_SIZE = 48
        private const val NTP_TIMESTAMP_SIZE = 8
        private const val NTP_ORIGINATE_TIME_OFFSET = 24
        private const val NTP_RECEIVE_TIME_OFFSET = 32
        private const val NTP_TRANSMIT_TIME_OFFSET = 40
        private const val NTP_EPOCH_OFFSET_SECONDS = 2_208_988_800L
        private const val UINT32_SCALE = 4_294_967_296L
    }
}
