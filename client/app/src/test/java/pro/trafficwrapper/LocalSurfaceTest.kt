package pro.trafficwrapper

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.EOFException
import java.io.InputStream
import java.io.OutputStream
import java.io.PipedInputStream
import java.io.PipedOutputStream
import java.util.Base64
import kotlin.concurrent.thread
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/** Local attack surface of the loopback router (18080) and HTTP proxy (18090). */
class LocalSurfaceTest {
    private val internal = SocksCredentials("twi", "0123456789abcdef0123456789abcdef")
    private val frontEnd = SocksCredentials("tw", "front-pass")

    init {
        LocalSocksAuth.overrideInternalForTest(internal)
    }

    private class Duplex {
        private val clientToServer = PipedOutputStream()
        val serverIn = PipedInputStream(clientToServer, 4096)
        private val serverToClient = PipedOutputStream()
        val clientIn = PipedInputStream(serverToClient, 4096)
        val clientOut: OutputStream = clientToServer
        val serverOut: OutputStream = serverToClient
    }

    private fun hex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it.toInt() and 0xff) }

    @Test
    fun routerProofMacMatchesGoCoreVector() {
        // Same vector as core/transport/socks_router_proof_test.go TestRouterProofVector.
        val mac = Socks5Auth.routerProofMac(
            "secret",
            "tw-router-server-v1",
            ByteArray(32) { 0x11 },
            ByteArray(32) { 0x22 },
        )
        assertEquals("faf99d5f76e82e76ab65ae9b978c5e722c5308c0b55a88db38e9eff53717c38d", hex(mac))
    }

    @Test
    fun routerAcceptsRouterProofFromInProcessClient() {
        val pipes = Duplex()
        var serverResult: Result<SocksCredentials?> = Result.failure(IllegalStateException("not run"))
        val server = thread {
            serverResult = runCatching {
                negotiateLocalSocksServerAuth(pipes.serverIn, pipes.serverOut, internal, frontEnd = null, allowNoAuth = false)
            }
        }
        Socks5Auth.negotiateClient(pipes.clientIn, pipes.clientOut, internal, peerPort = LOCAL_ROUTER_PORT)
        server.join(5_000)
        assertSame(internal, serverResult.getOrThrow())
    }

    @Test
    fun routerRejectsRouterProofWithWrongKey() {
        val pipes = Duplex()
        var serverResult: Result<SocksCredentials?> = Result.success(null)
        val server = thread {
            serverResult = runCatching {
                negotiateLocalSocksServerAuth(pipes.serverIn, pipes.serverOut, internal, frontEnd = null)
            }
        }
        // A client that does not know the password cannot finish the proof: here it answers the
        // server with a proof computed under a guessed key.
        val guessed = SocksCredentials("twi", "guess")
        val clientResult = runCatching { Socks5Auth.negotiateRouterProofClient(pipes.clientIn, pipes.clientOut, guessed) }
        pipes.clientOut.close()
        server.join(5_000)
        assertTrue(clientResult.isFailure)
        assertTrue(serverResult.isFailure)
    }

    /** A foreign listener on 18080 that asks for RFC 1929 credentials. */
    @Test
    fun inProcessClientNeverSendsCredentialsToForeignUserPassListener() {
        val pipes = Duplex()
        val received = ByteArrayOutputStream()
        val listener = thread {
            val greeting = ByteArray(3)
            readFully(pipes.serverIn, greeting)
            received.write(greeting)
            pipes.serverOut.write(byteArrayOf(0x05, 0x02))
            pipes.serverOut.flush()
            drain(pipes.serverIn, received)
        }
        try {
            Socks5Auth.negotiateClient(pipes.clientIn, pipes.clientOut, internal, peerPort = LOCAL_ROUTER_PORT)
            fail("a foreign listener must not be accepted")
        } catch (_: UntrustedSocksRouterException) {
        }
        pipes.clientOut.close()
        listener.join(5_000)
        assertFalse(String(received.toByteArray(), Charsets.ISO_8859_1).contains(internal.password))
    }

    /** A foreign listener on 18080 that selects the private method and fakes the proof. */
    @Test
    fun inProcessClientRejectsForeignListenerFakingTheProof() {
        val pipes = Duplex()
        val received = ByteArrayOutputStream()
        val listener = thread {
            val greeting = ByteArray(3)
            readFully(pipes.serverIn, greeting)
            pipes.serverOut.write(byteArrayOf(0x05, Socks5Auth.METHOD_ROUTER_PROOF.toByte()))
            val request = ByteArray(1 + Socks5Auth.ROUTER_NONCE_BYTES)
            readFully(pipes.serverIn, request)
            pipes.serverOut.write(byteArrayOf(0x01) + ByteArray(64) { 0x5a })
            pipes.serverOut.flush()
            drain(pipes.serverIn, received)
        }
        try {
            Socks5Auth.negotiateClient(pipes.clientIn, pipes.clientOut, internal, peerPort = LOCAL_ROUTER_PORT)
            fail("a fake proof must not be accepted")
        } catch (_: UntrustedSocksRouterException) {
        }
        pipes.clientOut.close()
        listener.join(5_000)
        assertEquals("the client must not answer a bad proof", 0, received.size())
    }

    @Test
    fun internalCredentialsStillUseUserPassTowardsUpstreamPorts() {
        val out = ByteArrayOutputStream()
        runCatching {
            Socks5Auth.negotiateClient(ByteArrayInputStream(byteArrayOf(0x05, 0x02, 0x01, 0x00)), out, internal, peerPort = 18081)
        }.getOrThrow()
        assertArrayEquals(byteArrayOf(0x05, 0x01, 0x02), out.toByteArray().copyOfRange(0, 3))
    }

    @Test
    fun vpnModeRejectsNoAuthWithoutReply() {
        val policy = localProxyAuthPolicy(vpnMode = true, frontEnd = null)
        assertFalse(policy.allowNoAuth)
        val out = ByteArrayOutputStream()
        try {
            negotiateLocalSocksServerAuth(
                ByteArrayInputStream(byteArrayOf(0x05, 0x01, 0x00)),
                out,
                internal,
                policy.frontEnd,
                policy.allowNoAuth,
            )
            fail("no-auth must be rejected in VPN mode")
        } catch (_: SocksAuthRejectedException) {
        }
        assertEquals(0, out.size())
    }

    @Test
    fun socksOnlyModeFollowsThePasswordSwitch() {
        assertTrue(localProxyAuthPolicy(vpnMode = false, frontEnd = null).allowNoAuth)
        val protected = localProxyAuthPolicy(vpnMode = false, frontEnd = frontEnd)
        assertFalse(protected.allowNoAuth)
        assertEquals(frontEnd, protected.frontEnd)
        assertEquals(frontEnd, localProxyAuthPolicy(vpnMode = true, frontEnd = frontEnd).frontEnd)
    }

    @Test
    fun newInstallsDefaultToPasswordAndUpgradesKeepTheirSetting() {
        assertTrue(frontEndAuthDefault(stored = null, existingInstall = false))
        assertFalse(frontEndAuthDefault(stored = null, existingInstall = true))
        assertFalse(frontEndAuthDefault(stored = false, existingInstall = false))
        assertTrue(frontEndAuthDefault(stored = true, existingInstall = true))
    }

    @Test
    fun policyFingerprintChangesWithPasswordAndMode() {
        val open = localProxyAuthPolicy(vpnMode = false, frontEnd = null).fingerprint
        val vpn = localProxyAuthPolicy(vpnMode = true, frontEnd = null).fingerprint
        val pw1 = localProxyAuthPolicy(vpnMode = false, frontEnd = frontEnd).fingerprint
        val pw2 = localProxyAuthPolicy(vpnMode = false, frontEnd = frontEnd.copy(password = "other")).fingerprint
        assertEquals(4, setOf(open, vpn, pw1, pw2).size)
        assertFalse(pw1.contains(frontEnd.password))
        assertEquals(pw1, localProxyAuthPolicy(vpnMode = true, frontEnd = frontEnd).fingerprint)
    }

    @Test
    fun httpProxyAdmitsOnlyAuthorizedRequests() {
        val header = "Basic " + Base64.getEncoder().encodeToString("tw:front-pass".toByteArray())
        val protected = localProxyAuthPolicy(vpnMode = false, frontEnd = frontEnd)
        assertTrue(isHttpProxyRequestAllowed(protected, header))
        assertFalse(isHttpProxyRequestAllowed(protected, null))
        assertFalse(isHttpProxyRequestAllowed(protected, "Basic " + Base64.getEncoder().encodeToString("tw:x".toByteArray())))
        assertTrue(isHttpProxyRequestAllowed(localProxyAuthPolicy(vpnMode = false, frontEnd = null), null))
        assertFalse(isHttpProxyRequestAllowed(localProxyAuthPolicy(vpnMode = true, frontEnd = null), null))
    }

    @Test
    fun routerAdmissionEvictsOldestPendingHandshake() {
        val admission = RouterAdmission<String>(maxPendingHandshakes = 2, maxInternalSessions = 1, maxExternalSessions = 1)
        assertNull(admission.admitHandshake("slow-1"))
        assertNull(admission.admitHandshake("slow-2"))
        assertEquals("slow-1", admission.admitHandshake("internal"))
        assertFalse(admission.finishHandshake("slow-1"))
        assertTrue(admission.finishHandshake("internal"))
        assertEquals(1, admission.pendingCount())
    }

    @Test
    fun routerAdmissionKeepsSeparateBudgetsForInternalClients() {
        val admission = RouterAdmission<String>(maxPendingHandshakes = 4, maxInternalSessions = 2, maxExternalSessions = 1)
        assertTrue(admission.tryAcquireSession(internal = false))
        assertFalse("other apps are capped", admission.tryAcquireSession(internal = false))
        assertTrue("in-process clients keep their slots", admission.tryAcquireSession(internal = true))
        assertTrue(admission.tryAcquireSession(internal = true))
        assertFalse(admission.tryAcquireSession(internal = true))
        admission.releaseSession(internal = false)
        assertTrue(admission.tryAcquireSession(internal = false))
    }

    @Test
    fun routerBindRetryBacksOff() {
        assertEquals(0L, routerBindRetryDelayMs(0))
        assertEquals(ROUTER_BIND_RETRY_BASE_MS, routerBindRetryDelayMs(1))
        assertEquals(ROUTER_BIND_RETRY_BASE_MS * 2, routerBindRetryDelayMs(2))
        assertEquals(ROUTER_BIND_RETRY_MAX_MS, routerBindRetryDelayMs(50))
        assertNotEquals(routerBindRetryDelayMs(1), routerBindRetryDelayMs(3))
    }

    private fun readFully(input: InputStream, buffer: ByteArray) {
        var offset = 0
        while (offset < buffer.size) {
            val read = input.read(buffer, offset, buffer.size - offset)
            if (read < 0) throw EOFException()
            offset += read
        }
    }

    private fun drain(input: InputStream, into: ByteArrayOutputStream) {
        runCatching {
            val buffer = ByteArray(256)
            while (true) {
                val read = input.read(buffer)
                if (read < 0) break
                into.write(buffer, 0, read)
            }
        }
    }
}
