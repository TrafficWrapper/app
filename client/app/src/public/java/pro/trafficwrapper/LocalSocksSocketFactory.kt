package pro.trafficwrapper

import java.io.EOFException
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketAddress
import javax.net.SocketFactory
import okhttp3.Dns

/**
 * OkHttp plumbing for the loopback SOCKS5 listeners, which require RFC 1929 authentication with
 * [LocalSocksAuth.internal]. java.net's SOCKS proxy support can only authenticate through the
 * process-global [java.net.Authenticator], so instead:
 *
 *  - [PlaceholderDns] "resolves" every host name to an unroutable placeholder address that keeps
 *    the original host name attached (no real DNS query leaves the device);
 *  - [LocalSocksSocketFactory] creates sockets whose `connect()` goes to the local SOCKS listener,
 *    authenticates and issues `CONNECT <hostname>:<port>` (the tunnel resolves the name).
 *
 * The OkHttp client must use `Proxy.NO_PROXY` so OkHttp calls `socket.connect(target)` on a socket
 * obtained from this factory. TLS (if any) is layered by OkHttp on top of the connected socket
 * with SNI/hostname verification against the URL host, so nothing changes for HTTPS.
 */
internal class LocalSocksSocketFactory(
    private val proxyHost: String,
    private val proxyPort: Int,
    private val credentials: () -> SocksCredentials? = { LocalSocksAuth.internal },
) : SocketFactory() {
    override fun createSocket(): Socket = LocalSocksSocket(proxyHost, proxyPort, credentials)

    override fun createSocket(host: String, port: Int): Socket =
        createSocket().apply { connect(InetSocketAddress.createUnresolved(host, port)) }

    override fun createSocket(host: String, port: Int, localHost: InetAddress?, localPort: Int): Socket =
        createSocket(host, port)

    override fun createSocket(host: InetAddress, port: Int): Socket =
        createSocket().apply { connect(InetSocketAddress(host, port)) }

    override fun createSocket(address: InetAddress, port: Int, localAddress: InetAddress?, localPort: Int): Socket =
        createSocket(address, port)

    companion object {
        fun forListen(socksListen: String): LocalSocksSocketFactory {
            val host = socksListen.substringBeforeLast(":", DEFAULT_HOST).ifBlank { DEFAULT_HOST }
            val port = socksListen.substringAfterLast(":", "").toIntOrNull() ?: DEFAULT_PORT
            return LocalSocksSocketFactory(host, port)
        }

        private const val DEFAULT_HOST = "127.0.0.1"
        private const val DEFAULT_PORT = 18080
    }
}

/** Keeps host names intact for [LocalSocksSocketFactory]; never performs a real lookup. */
internal object PlaceholderDns : Dns {
    // TEST-NET-1 (RFC 5737): if a socket ever bypassed the SOCKS factory it would fail closed.
    private val PLACEHOLDER = byteArrayOf(192.toByte(), 0, 2, 1)

    override fun lookup(hostname: String): List<InetAddress> =
        listOf(InetAddress.getByAddress(hostname, PLACEHOLDER))
}

private class LocalSocksSocket(
    private val proxyHost: String,
    private val proxyPort: Int,
    private val credentials: () -> SocksCredentials?,
) : Socket() {
    override fun connect(endpoint: SocketAddress) {
        connect(endpoint, 0)
    }

    override fun connect(endpoint: SocketAddress, timeout: Int) {
        val target = endpoint as? InetSocketAddress
            ?: throw IllegalArgumentException("unsupported address type: ${endpoint.javaClass.name}")
        // hostString never triggers a reverse lookup; for PlaceholderDns addresses it is the URL host.
        val targetHost = target.hostString
        super.connect(InetSocketAddress(proxyHost, proxyPort), timeout)
        val previousTimeout = soTimeout
        try {
            if (timeout > 0) soTimeout = timeout
            socks5Connect(super.getInputStream(), super.getOutputStream(), targetHost, target.port, credentials())
        } catch (error: Throwable) {
            runCatching { close() }
            throw error
        } finally {
            if (!isClosed) runCatching { soTimeout = previousTimeout }
        }
    }
}

/**
 * Client side of a SOCKS5 CONNECT with a domain-name target, authenticating with [credentials]
 * (RFC 1929) when set. Consumes exactly the reply, leaving the stream positioned at tunnel data.
 */
internal fun socks5Connect(
    input: InputStream,
    output: OutputStream,
    host: String,
    port: Int,
    credentials: SocksCredentials?,
) {
    require(port in 1..65535) { "invalid port $port" }
    val hostBytes = host.toByteArray(Charsets.UTF_8)
    require(hostBytes.size in 1..255) { "invalid host length" }
    Socks5Auth.negotiateClient(input, output, credentials)
    output.write(byteArrayOf(Socks5Auth.VERSION.toByte(), SOCKS_CMD_CONNECT, 0x00, SOCKS_ATYP_DOMAIN, hostBytes.size.toByte()))
    output.write(hostBytes)
    output.write(byteArrayOf(((port ushr 8) and 0xff).toByte(), (port and 0xff).toByte()))
    output.flush()
    if (readSocksByte(input) != Socks5Auth.VERSION) throw IOException("bad socks reply version")
    val reply = readSocksByte(input)
    readSocksByte(input)
    val atyp = readSocksByte(input)
    if (reply != 0) throw IOException("socks connect failed: $reply")
    val bindLength = when (atyp) {
        0x01 -> 4
        0x03 -> readSocksByte(input)
        0x04 -> 16
        else -> throw IOException("bad socks bind address type $atyp")
    }
    repeat(bindLength + 2) { readSocksByte(input) }
}

private const val SOCKS_CMD_CONNECT: Byte = 0x01
private const val SOCKS_ATYP_DOMAIN: Byte = 0x03

private fun readSocksByte(input: InputStream): Int {
    val value = input.read()
    if (value < 0) throw EOFException("unexpected EOF in socks handshake")
    return value
}
