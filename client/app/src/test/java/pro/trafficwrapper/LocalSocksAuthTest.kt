package pro.trafficwrapper

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.EOFException
import java.io.PipedInputStream
import java.io.PipedOutputStream
import kotlin.concurrent.thread
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class LocalSocksAuthTest {
    private val creds = SocksCredentials("tw", "secret")

    @Test
    fun clientAndServerNegotiateUserPass() {
        val matched = negotiate(client = creds, accepted = listOf(SocksCredentials("other", "x"), creds))
        assertEquals(creds, matched.getOrThrow())
    }

    @Test
    fun serverRejectsWrongPassword() {
        val result = negotiate(client = SocksCredentials("tw", "wrong"), accepted = listOf(creds))
        assertTrue(result.isFailure)
    }

    @Test
    fun serverRejectsNoAuthWhenCredentialsRequired() {
        val output = ByteArrayOutputStream()
        try {
            Socks5Auth.negotiateServer(ByteArrayInputStream(byteArrayOf(5, 1, 0)), output, listOf(creds))
            fail("expected rejection")
        } catch (_: EOFException) {
        }
        assertEquals(listOf<Byte>(5, 0xff.toByte()), output.toByteArray().toList())
    }

    @Test
    fun serverAcceptsNoAuthWhenNothingRequired() {
        val output = ByteArrayOutputStream()
        val matched = Socks5Auth.negotiateServer(ByteArrayInputStream(byteArrayOf(5, 1, 0)), output, emptyList())
        assertNull(matched)
        assertEquals(listOf<Byte>(5, 0), output.toByteArray().toList())
    }

    @Test
    fun parsesCoreCredentialsJson() {
        assertEquals(creds, parseCredentialsJson("""{"username":"tw","password":"secret"}"""))
    }

    @Test
    fun credentialsToStringHidesPassword() {
        assertTrue("secret" !in creds.toString())
    }

    private fun negotiate(client: SocksCredentials?, accepted: List<SocksCredentials>): Result<SocksCredentials?> {
        val clientToServer = PipedOutputStream()
        val serverIn = PipedInputStream(clientToServer)
        val serverToClient = PipedOutputStream()
        val clientIn = PipedInputStream(serverToClient)
        var serverResult: Result<SocksCredentials?> = Result.failure(IllegalStateException("not run"))
        val server = thread {
            serverResult = runCatching { Socks5Auth.negotiateServer(serverIn, serverToClient, accepted) }
        }
        val clientResult = runCatching { Socks5Auth.negotiateClient(clientIn, clientToServer, client) }
        server.join(5_000)
        return if (clientResult.isFailure) Result.failure(clientResult.exceptionOrNull()!!) else serverResult
    }
}
