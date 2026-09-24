package pro.trafficwrapper

import java.io.ByteArrayInputStream
import java.io.EOFException
import java.io.InputStream
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class UpdateHttpTest {
    @Test
    fun parsesStatusAndHeadersAndLeavesBodyInStream() {
        val input = stream("HTTP/1.1 200 OK\r\nContent-Length: 5\r\nETag: \"abc\"\r\nX-Dup: a\r\nX-Dup: b\r\n\r\nhello")
        val head = parseUpdateHttpHead(readUpdateHttpHead(input))
        assertEquals(200, head.code)
        assertEquals("\"abc\"", head.headers["etag"])
        assertEquals("a, b", head.headers["x-dup"])
        val body = updateHttpBodyStream(input, "GET", head, 1024)
        assertEquals("hello", String(readUpdateBodyLimited(body, 1024)))
    }

    @Test
    fun rejectsMalformedStatusLine() {
        expectFailure { parseUpdateHttpHead("SSH-2.0-OpenSSH\r\n\r\n") }
        expectFailure { parseUpdateHttpHead("HTTP/1.1 2000 OK\r\n\r\n") }
        expectFailure { parseUpdateHttpHead("HTTP/1.1 200 OK\r\nbroken header\r\n\r\n") }
    }

    @Test
    fun headerSizeIsLimited() {
        val big = "HTTP/1.1 200 OK\r\nX: " + "a".repeat(200) + "\r\n\r\n"
        expectFailure { readUpdateHttpHead(stream(big), limitBytes = 64) }
    }

    @Test
    fun contentLengthBodyIsReadExactly() {
        val (head, input) = response("HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabcEXTRA")
        val body = updateHttpBodyStream(input, "GET", head, 1024)
        assertEquals("abc", String(readUpdateBodyLimited(body, 1024)))
    }

    @Test
    fun truncatedContentLengthBodyFails() {
        val (head, input) = response("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc")
        val body = updateHttpBodyStream(input, "GET", head, 1024)
        try {
            readUpdateBodyLimited(body, 1024)
            fail("truncated body must fail")
        } catch (_: EOFException) {
        }
    }

    @Test
    fun contentLengthAboveLimitIsRejectedBeforeReading() {
        val (head, input) = response("HTTP/1.1 200 OK\r\nContent-Length: 2000000\r\n\r\n")
        expectFailure { updateHttpBodyStream(input, "GET", head, UPDATE_MANIFEST_MAX_BYTES) }
    }

    @Test
    fun conflictingOrInvalidContentLengthIsRejected() {
        val (head1, input1) = response("HTTP/1.1 200 OK\r\nContent-Length: 3\r\nContent-Length: 4\r\n\r\nabcd")
        expectFailure { updateHttpBodyStream(input1, "GET", head1, 1024) }
        val (head2, input2) = response("HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\n")
        expectFailure { updateHttpBodyStream(input2, "GET", head2, 1024) }
    }

    @Test
    fun chunkedBodyIsDecoded() {
        val raw = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" +
            "5;ext=1\r\nhello\r\n" +
            "7\r\n, world\r\n" +
            "0\r\nX-Trailer: t\r\n\r\n" +
            "GARBAGE"
        val (head, input) = response(raw)
        val body = updateHttpBodyStream(input, "GET", head, 1024)
        assertEquals("hello, world", String(readUpdateBodyLimited(body, 1024)))
    }

    @Test
    fun chunkedBodyReadsByteByByte() {
        val (head, input) = response("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nab\r\n1\r\nc\r\n0\r\n\r\n")
        val body = updateHttpBodyStream(input, "GET", head, 1024)
        val out = StringBuilder()
        while (true) {
            val b = body.read()
            if (b < 0) break
            out.append(b.toChar())
        }
        assertEquals("abc", out.toString())
    }

    @Test
    fun truncatedChunkedBodyFails() {
        val (head, input) = response("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\na\r\nabc")
        val body = updateHttpBodyStream(input, "GET", head, 1024)
        try {
            readUpdateBodyLimited(body, 1024)
            fail("truncated chunked body must fail")
        } catch (_: EOFException) {
        }
    }

    @Test
    fun chunkedBodyWithoutTerminatorFails() {
        val (head, input) = response("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n")
        val body = updateHttpBodyStream(input, "GET", head, 1024)
        try {
            readUpdateBodyLimited(body, 1024)
            fail("missing last-chunk must fail")
        } catch (_: EOFException) {
        }
    }

    @Test
    fun chunkedBodyAboveLimitFails() {
        val (head, input) = response("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n8\r\n12345678\r\n8\r\n12345678\r\n0\r\n\r\n")
        val body = updateHttpBodyStream(input, "GET", head, 10)
        expectFailure { readUpdateBodyLimited(body, 1024) }
    }

    @Test
    fun malformedChunkSizeFails() {
        val (head, input) = response("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\nabc\r\n0\r\n\r\n")
        val body = updateHttpBodyStream(input, "GET", head, 1024)
        expectFailure { readUpdateBodyLimited(body, 1024) }
    }

    @Test
    fun unsupportedTransferEncodingIsRejected() {
        val (head, input) = response("HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n")
        expectFailure { updateHttpBodyStream(input, "GET", head, 1024) }
    }

    @Test
    fun unframedBodyIsLimited() {
        val (head, input) = response("HTTP/1.1 200 OK\r\n\r\n" + "x".repeat(50))
        val body = updateHttpBodyStream(input, "GET", head, 10)
        expectFailure { readUpdateBodyLimited(body, 1024) }
        val (head2, input2) = response("HTTP/1.1 200 OK\r\n\r\nshort")
        assertEquals("short", String(readUpdateBodyLimited(updateHttpBodyStream(input2, "GET", head2, 10), 1024)))
    }

    @Test
    fun headAndNoContentResponsesHaveEmptyBody() {
        val (head, input) = response("HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n")
        assertArrayEquals(ByteArray(0), readUpdateBodyLimited(updateHttpBodyStream(input, "HEAD", head, 0), 0))
        val (head2, input2) = response("HTTP/1.1 204 No Content\r\n\r\n")
        assertArrayEquals(ByteArray(0), readUpdateBodyLimited(updateHttpBodyStream(input2, "GET", head2, 0), 0))
    }

    @Test
    fun readLimitedRejectsOversizedBody() {
        expectFailure { readUpdateBodyLimited(ByteArrayInputStream(ByteArray(11)), 10) }
        assertEquals(10, readUpdateBodyLimited(ByteArrayInputStream(ByteArray(10)), 10).size)
    }

    @Test
    fun contentRangeMustMatchResumeOffsetAndTotal() {
        assertTrue(updateContentRangeMatches("bytes 100-999/1000", 100, 1000))
        assertTrue(updateContentRangeMatches("bytes 100-999/*", 100, 1000))
        assertFalse(updateContentRangeMatches(null, 100, 1000))
        assertFalse(updateContentRangeMatches("bytes 0-999/1000", 100, 1000))
        assertFalse(updateContentRangeMatches("bytes 100-999/2000", 100, 1000))
        assertFalse(updateContentRangeMatches("bytes 100-1000/1000", 100, 1000))
        assertFalse(updateContentRangeMatches("items 100-999/1000", 100, 1000))
    }

    @Test
    fun sha256HelpersProduceLowercaseHex() {
        val expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        assertEquals(expected, updateSha256Hex("abc".toByteArray()))
        assertEquals(expected, updateSha256HexOfStream(ByteArrayInputStream("abc".toByteArray())))
    }

    private fun stream(text: String): InputStream = ByteArrayInputStream(text.toByteArray(Charsets.ISO_8859_1))

    private fun response(raw: String): Pair<UpdateHttpHead, InputStream> {
        val input = stream(raw)
        return parseUpdateHttpHead(readUpdateHttpHead(input)) to input
    }

    private fun expectFailure(block: () -> Unit) {
        try {
            block()
            fail("expected failure")
        } catch (_: java.io.IOException) {
        }
    }
}
