package pro.trafficwrapper

import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import android.os.SystemClock
import kotlin.math.abs
import kotlin.math.roundToLong

data class ClockCheckResult(
    val okForStart: Boolean,
    val statusTextRes: Int,
    val skewSeconds: Long? = null,
)

data class TrustedTimeResult(
    val wallTimeMs: Long,
    val elapsedRealtimeMs: Long,
    val sntpAvailable: Boolean,
)

object ClockDiagnostics {
    fun check(fakeSkewSeconds: Long? = null): ClockCheckResult {
        val offsetMs = if (BuildConfig.DEBUG && fakeSkewSeconds != null) {
            fakeSkewSeconds * 1_000L
        } else {
            querySntpOffsetMs()
        }
        val skewSeconds = (offsetMs / 1_000.0).roundToLong()
        return if (abs(offsetMs) > MAX_CLOCK_SKEW_MS) {
            ClockCheckResult(false, R.string.clock_status_desynced, skewSeconds)
        } else {
            ClockCheckResult(true, R.string.clock_status_synced, skewSeconds)
        }
    }

    fun unavailable(): ClockCheckResult =
        ClockCheckResult(true, R.string.clock_status_unavailable)

    fun trustedTime(): TrustedTimeResult {
        val elapsed = SystemClock.elapsedRealtime()
        val offsetMs = querySntpOffsetMs()
        return TrustedTimeResult(
            wallTimeMs = System.currentTimeMillis() + offsetMs,
            elapsedRealtimeMs = elapsed,
            sntpAvailable = true,
        )
    }

    private fun querySntpOffsetMs(): Long {
        val packet = ByteArray(NTP_PACKET_SIZE)
        packet[0] = NTP_CLIENT_MODE
        val t1 = System.currentTimeMillis()
        writeTimestamp(packet, NTP_TRANSMIT_TIME_OFFSET, t1)
        val requestTransmitTimestamp = packet.copyOfRange(
            NTP_TRANSMIT_TIME_OFFSET,
            NTP_TRANSMIT_TIME_OFFSET + NTP_TIMESTAMP_SIZE,
        )
        DatagramSocket().use { socket ->
            socket.soTimeout = NTP_TIMEOUT_MS
            val address = InetAddress.getByName(NTP_HOST)
            val request = DatagramPacket(packet, packet.size, address, NTP_PORT)
            socket.send(request)

            while (true) {
                val response = DatagramPacket(ByteArray(NTP_PACKET_SIZE), NTP_PACKET_SIZE)
                socket.receive(response)
                val t4 = System.currentTimeMillis()
                val offset = sntpOffsetFromResponse(
                    data = response.data,
                    length = response.length,
                    responseAddress = response.address,
                    expectedAddress = address,
                    requestTransmitTimestamp = requestTransmitTimestamp,
                    requestUnixTimeMs = t1,
                    responseReceivedUnixTimeMs = t4,
                )
                if (offset != null) return offset
            }
        }
    }

    internal fun sntpOffsetFromResponse(
        data: ByteArray,
        length: Int,
        responseAddress: InetAddress?,
        expectedAddress: InetAddress,
        requestTransmitTimestamp: ByteArray,
        requestUnixTimeMs: Long,
        responseReceivedUnixTimeMs: Long,
    ): Long? {
        if (length < NTP_PACKET_SIZE) return null
        if (responseAddress != expectedAddress) return null
        val mode = data[0].toInt() and NTP_MODE_MASK
        if (mode != NTP_SERVER_MODE) return null
        val stratum = data[1].toInt() and BYTE_MASK
        if (stratum !in NTP_VALID_STRATUM) return null
        for (i in 0 until NTP_TIMESTAMP_SIZE) {
            if (data[NTP_ORIGINATE_TIME_OFFSET + i] != requestTransmitTimestamp.getOrNull(i)) {
                return null
            }
        }
        val t2 = readTimestamp(data, NTP_RECEIVE_TIME_OFFSET, responseReceivedUnixTimeMs)
        val t3 = readTimestamp(data, NTP_TRANSMIT_TIME_OFFSET, responseReceivedUnixTimeMs)
        return ((t2 - requestUnixTimeMs) + (t3 - responseReceivedUnixTimeMs)) / 2L
    }

    internal fun readTimestamp(data: ByteArray, offset: Int, referenceUnixTimeMs: Long): Long {
        val seconds = readUint32(data, offset)
        val fraction = readUint32(data, offset + 4)
        val referenceNtpSeconds = referenceUnixTimeMs / 1_000L + NTP_EPOCH_OFFSET_SECONDS
        val referenceEra = Math.floorDiv(referenceNtpSeconds, NTP_ERA_SECONDS)
        var bestSeconds = seconds
        var bestDistance = Long.MAX_VALUE
        for (era in (referenceEra - 1)..(referenceEra + 1)) {
            val candidate = era * NTP_ERA_SECONDS + seconds
            val distance = abs(candidate - referenceNtpSeconds)
            if (distance < bestDistance) {
                bestSeconds = candidate
                bestDistance = distance
            }
        }
        return (bestSeconds - NTP_EPOCH_OFFSET_SECONDS) * 1_000L +
            (fraction * 1_000L) / UINT32_SCALE
    }

    private fun writeTimestamp(data: ByteArray, offset: Int, unixTimeMs: Long) {
        val seconds = unixTimeMs / 1_000L + NTP_EPOCH_OFFSET_SECONDS
        val fraction = ((unixTimeMs % 1_000L) * UINT32_SCALE) / 1_000L
        writeUint32(data, offset, seconds)
        writeUint32(data, offset + 4, fraction)
    }

    private fun readUint32(data: ByteArray, offset: Int): Long =
        ((data[offset].toLong() and 0xffL) shl 24) or
            ((data[offset + 1].toLong() and 0xffL) shl 16) or
            ((data[offset + 2].toLong() and 0xffL) shl 8) or
            (data[offset + 3].toLong() and 0xffL)

    private fun writeUint32(data: ByteArray, offset: Int, value: Long) {
        data[offset] = (value ushr 24).toByte()
        data[offset + 1] = (value ushr 16).toByte()
        data[offset + 2] = (value ushr 8).toByte()
        data[offset + 3] = value.toByte()
    }

    private const val NTP_HOST = "time.cloudflare.com"
    private const val NTP_PORT = 123
    private const val NTP_PACKET_SIZE = 48
    private const val NTP_TIMESTAMP_SIZE = 8
    private const val NTP_TIMEOUT_MS = 4_000
    private const val NTP_CLIENT_MODE = 0x23.toByte()
    private const val NTP_MODE_MASK = 0x07
    private const val NTP_SERVER_MODE = 4
    private const val BYTE_MASK = 0xff
    private val NTP_VALID_STRATUM = 1..15
    private const val NTP_ORIGINATE_TIME_OFFSET = 24
    private const val NTP_RECEIVE_TIME_OFFSET = 32
    private const val NTP_TRANSMIT_TIME_OFFSET = 40
    private const val NTP_EPOCH_OFFSET_SECONDS = 2_208_988_800L
    private const val UINT32_SCALE = 4_294_967_296L
    private const val NTP_ERA_SECONDS = UINT32_SCALE
    private const val MAX_CLOCK_SKEW_MS = 120_000L
}
