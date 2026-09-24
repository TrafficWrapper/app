package pro.trafficwrapper

import java.io.BufferedInputStream
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.util.Base64
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class LocalHttpProxyTest {
    @Test
    fun connectRequestParsesTargetWithoutInitialBytes() {
        val request = parseHttpProxyRequest(
            "CONNECT api.ipify.org:443 HTTP/1.1\r\nHost: api.ipify.org:443\r\n\r\n"
                .toByteArray(Charsets.ISO_8859_1),
        )

        assertTrue(request.connect)
        assertEquals("CONNECT", request.method)
        assertEquals("api.ipify.org", request.targetHost)
        assertEquals(443, request.targetPort)
        assertEquals(0, request.initialBytesToUpstream.size)
    }

    @Test
    fun plainHttpRequestIsRewrittenToOriginForm() {
        val request = parseHttpProxyRequest(
            (
                "GET http://example.com/path?q=1 HTTP/1.1\r\n" +
                    "Host: example.com\r\n" +
                    "Proxy-Connection: keep-alive\r\n" +
                    "\r\n"
                ).toByteArray(Charsets.ISO_8859_1),
        )

        val rewritten = request.initialBytesToUpstream.toString(Charsets.ISO_8859_1)

        assertFalse(request.connect)
        assertEquals("example.com", request.targetHost)
        assertEquals(80, request.targetPort)
        assertTrue(rewritten.startsWith("GET /path?q=1 HTTP/1.1\r\n"))
        assertTrue(rewritten.contains("Host: example.com\r\n"))
        assertFalse(rewritten.contains("Proxy-Connection:"))
    }

    @Test
    fun proxyAuthorizationIsCapturedAndNeverForwardedUpstream() {
        val token = Base64.getEncoder().encodeToString("tw:secret".toByteArray())
        val request = parseHttpProxyRequest(
            (
                "GET http://example.com/ HTTP/1.1\r\n" +
                    "Host: example.com\r\n" +
                    "Proxy-Authorization: Basic $token\r\n" +
                    "Keep-Alive: timeout=5\r\n" +
                    "Connection: keep-alive\r\n" +
                    "\r\n"
                ).toByteArray(Charsets.ISO_8859_1),
        )

        val rewritten = request.initialBytesToUpstream.toString(Charsets.ISO_8859_1)

        assertEquals("Basic $token", request.proxyAuthorization)
        assertFalse(rewritten.contains("Proxy-Authorization", ignoreCase = true))
        assertFalse(rewritten.contains("Keep-Alive", ignoreCase = true))
        assertTrue(rewritten.endsWith("Connection: close\r\n\r\n"))
        assertFalse(request.toString().contains(token))
    }

    @Test
    fun connectRequestCarriesProxyAuthorization() {
        val request = parseHttpProxyRequest(
            "CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: Basic abc\r\n\r\n"
                .toByteArray(Charsets.ISO_8859_1),
        )

        assertEquals("Basic abc", request.proxyAuthorization)
    }

    @Test
    fun basicProxyAuthorizationMatchesOnlyExactCredentials() {
        val expected = SocksCredentials("tw", "pa:ss")
        fun basic(raw: String) = "Basic " + Base64.getEncoder().encodeToString(raw.toByteArray())

        assertTrue(isHttpProxyAuthorized(basic("tw:pa:ss"), expected))
        assertTrue(isHttpProxyAuthorized("basic " + Base64.getEncoder().encodeToString("tw:pa:ss".toByteArray()), expected))
        assertFalse(isHttpProxyAuthorized(basic("tw:wrong"), expected))
        assertFalse(isHttpProxyAuthorized(basic("other:pa:ss"), expected))
        assertFalse(isHttpProxyAuthorized(basic("twpa:ss"), expected))
        assertFalse(isHttpProxyAuthorized("Bearer abc", expected))
        assertFalse(isHttpProxyAuthorized("Basic !!!notbase64", expected))
        assertFalse(isHttpProxyAuthorized(null, expected))
        assertFalse(isHttpProxyAuthorized("", expected))
    }

    @Test
    fun requestBodyFramingIsParsed() {
        val withLength = parseHttpProxyRequest(
            "POST http://example.com/ HTTP/1.1\r\nContent-Length: 12\r\n\r\n".toByteArray(Charsets.ISO_8859_1),
        )
        val chunked = parseHttpProxyRequest(
            "POST http://example.com/ HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n".toByteArray(Charsets.ISO_8859_1),
        )
        val none = parseHttpProxyRequest(
            "GET http://example.com/ HTTP/1.1\r\n\r\n".toByteArray(Charsets.ISO_8859_1),
        )

        assertEquals(12L, withLength.contentLength)
        assertFalse(withLength.chunked)
        assertTrue(chunked.chunked)
        assertEquals(-1L, none.contentLength)
        assertFalse(none.chunked)
        assertNull(none.proxyAuthorization)
    }

    @Test
    fun headerReaderLeavesBufferedRemainderForRelay() {
        val raw = "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\nEARLYBYTES"
        val input = BufferedInputStream(ByteArrayInputStream(raw.toByteArray(Charsets.ISO_8859_1)), 4)

        val header = readHttpHeaderBlock(input, 64 * 1024)

        assertEquals("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n", header!!.toString(Charsets.ISO_8859_1))
        assertEquals("EARLYBYTES", input.readBytes().toString(Charsets.ISO_8859_1))
    }

    @Test
    fun headerReaderReturnsNullWhenLimitExceeded() {
        val input = ByteArrayInputStream(("GET / HTTP/1.1\r\nX: " + "a".repeat(100)).toByteArray())

        assertNull(readHttpHeaderBlock(input, 32))
    }

    @Test
    fun chunkedBodyIsForwardedVerbatimAndStopsAtMessageEnd() {
        val body = "4\r\nWiki\r\n5;ext=1\r\npedia\r\n0\r\nTrailer: x\r\n\r\n"
        val input = ByteArrayInputStream((body + "GET /next HTTP/1.1\r\n").toByteArray(Charsets.ISO_8859_1))
        val output = ByteArrayOutputStream()

        forwardChunkedBody(input, output)

        assertEquals(body, output.toString("ISO-8859-1"))
        assertEquals("GET /next HTTP/1.1\r\n", input.readBytes().toString(Charsets.ISO_8859_1))
    }

    @Test
    fun contentLengthBodyCopiesExactlyRequestedBytes() {
        val input = ByteArrayInputStream("hello worldNEXT".toByteArray())
        val output = ByteArrayOutputStream()

        copyExactly(input, output, 11)

        assertEquals("hello world", output.toString("UTF-8"))
        assertEquals("NEXT", input.readBytes().toString(Charsets.UTF_8))
    }

    @Test
    fun responseBodyReaderDecodesChunkedAndContentLength() {
        val chunked = readHttpResponseBody(
            ByteArrayInputStream("3\r\n1.2\r\n4\r\n.3.4\r\n0\r\n\r\n".toByteArray()),
            listOf("Transfer-Encoding: chunked"),
            1024,
        )
        val sized = readHttpResponseBody(
            ByteArrayInputStream("203.0.113.9extra".toByteArray()),
            listOf("Content-Length: 11"),
            1024,
        )

        assertEquals("1.2.3.4", chunked.toString(Charsets.UTF_8))
        assertEquals("203.0.113.9", sized.toString(Charsets.UTF_8))
    }
}
