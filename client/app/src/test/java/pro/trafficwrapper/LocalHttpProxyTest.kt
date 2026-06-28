package pro.trafficwrapper

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
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
}
