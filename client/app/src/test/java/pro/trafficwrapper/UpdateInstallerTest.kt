package pro.trafficwrapper

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.fail
import org.junit.Test

class UpdateInstallerTest {
    private val payload = "apk-bytes".toByteArray()
    private val payloadSha = updateSha256Hex(payload)

    @Test
    fun copyVerifiesHashWhileStreaming() {
        val out = ByteArrayOutputStream()
        val actual = copyAndVerifySha256(ByteArrayInputStream(payload), out, payloadSha.uppercase(), payload.size.toLong())
        assertEquals(payloadSha, actual)
        assertArrayEquals(payload, out.toByteArray())
    }

    @Test
    fun copyRejectsTamperedBytes() {
        val tampered = payload.copyOf().also { it[0] = 'X'.code.toByte() }
        expectMismatch { copyAndVerifySha256(ByteArrayInputStream(tampered), ByteArrayOutputStream(), payloadSha, payload.size.toLong()) }
    }

    @Test
    fun copyRejectsSizeChanges() {
        expectMismatch { copyAndVerifySha256(ByteArrayInputStream(payload + byteArrayOf(1)), ByteArrayOutputStream(), payloadSha, payload.size.toLong()) }
        expectMismatch { copyAndVerifySha256(ByteArrayInputStream(payload.copyOf(3)), ByteArrayOutputStream(), payloadSha, payload.size.toLong()) }
    }

    @Test
    fun copyRejectsMissingExpectedHash() {
        expectMismatch { copyAndVerifySha256(ByteArrayInputStream(payload), ByteArrayOutputStream(), "", payload.size.toLong()) }
    }

    private fun expectMismatch(block: () -> Unit) {
        try {
            block()
            fail("expected ApkHashMismatchException")
        } catch (_: ApkHashMismatchException) {
        }
    }
}
