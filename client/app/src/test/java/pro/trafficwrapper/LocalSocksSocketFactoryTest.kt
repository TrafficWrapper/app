package pro.trafficwrapper

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.EOFException
import java.io.IOException
import java.net.InetSocketAddress
import java.net.ServerSocket
import kotlin.concurrent.thread
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.fail
import org.junit.Test

class LocalSocksSocketFactoryTest {
    private val creds = SocksCredentials("user", "pass")

    @Test
    fun socks5ConnectAuthenticatesAndSendsDomainTarget() {
        val serverReplies = byteArrayOf(
            0x05, 0x02, // method: user/pass
            0x01, 0x00, // auth ok
            0x05, 0x00, 0x00, 0x01, 10, 0, 0, 1, 0x1f, 0x90.toByte(), // connect ok, bind 10.0.0.1:8080
            'X'.code.toByte(), // first tunnel byte must stay unread
        )
        val input = ByteArrayInputStream(serverReplies)
        val output = ByteArrayOutputStream()

        socks5Connect(input, output, "awg-gw", 8080, creds)

        val expected = byteArrayOf(0x05, 0x01, 0x02) +
            byteArrayOf(0x01, 4) + "user".toByteArray() + byteArrayOf(4) + "pass".toByteArray() +
            byteArrayOf(0x05, 0x01, 0x00, 0x03, 6) + "awg-gw".toByteArray() + byteArrayOf(0x1f, 0x90.toByte())
        assertArrayEquals(expected, output.toByteArray())
        assertEquals('X'.code, input.read())
    }

    @Test
    fun socks5ConnectFailsOnRejectedAuth() {
        val input = ByteArrayInputStream(byteArrayOf(0x05, 0x02, 0x01, 0x01))
        try {
            socks5Connect(input, ByteArrayOutputStream(), "host", 80, creds)
            fail("rejected auth must fail")
        } catch (_: EOFException) {
        }
    }

    @Test
    fun socks5ConnectFailsOnConnectError() {
        val input = ByteArrayInputStream(byteArrayOf(0x05, 0x02, 0x01, 0x00, 0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
        try {
            socks5Connect(input, ByteArrayOutputStream(), "host", 80, creds)
            fail("connect error must fail")
        } catch (_: IOException) {
        }
    }

    @Test
    fun placeholderDnsKeepsHostName() {
        val address = PlaceholderDns.lookup("awg-gw").single()
        assertEquals("awg-gw", InetSocketAddress(address, 80).hostString)
    }

    @Test
    fun factorySocketTunnelsThroughLocalSocksWithCredentials() {
        ServerSocket(0).use { server ->
            var seenHost = ""
            var seenPort = 0
            val proxy = thread {
                server.accept().use { client ->
                    val input = client.getInputStream()
                    val output = client.getOutputStream()
                    Socks5Auth.negotiateServer(input, output, listOf(creds))
                    val header = ByteArray(5).also { readFully(input, it) }
                    val host = ByteArray(header[4].toInt()).also { readFully(input, it) }
                    val port = ByteArray(2).also { readFully(input, it) }
                    seenHost = String(host)
                    seenPort = ((port[0].toInt() and 0xff) shl 8) or (port[1].toInt() and 0xff)
                    output.write(byteArrayOf(0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
                    output.write("pong".toByteArray())
                    output.flush()
                }
            }
            val factory = LocalSocksSocketFactory("127.0.0.1", server.localPort) { creds }
            factory.createSocket().use { socket ->
                val target = InetSocketAddress(PlaceholderDns.lookup("example.test").single(), 443)
                socket.connect(target, 5_000)
                val buffer = ByteArray(4)
                readFully(socket.getInputStream(), buffer)
                assertEquals("pong", String(buffer))
            }
            proxy.join(5_000)
            assertEquals("example.test", seenHost)
            assertEquals(443, seenPort)
        }
    }

    private fun readFully(input: java.io.InputStream, buffer: ByteArray) {
        var offset = 0
        while (offset < buffer.size) {
            val read = input.read(buffer, offset, buffer.size - offset)
            if (read < 0) throw EOFException()
            offset += read
        }
    }
}
