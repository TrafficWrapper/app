package pro.trafficwrapper

import android.util.Log
import java.io.BufferedInputStream
import java.io.ByteArrayOutputStream
import java.io.EOFException
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.URI
import java.util.Base64
import java.util.Collections
import java.util.Locale
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLPeerUnverifiedException
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

internal const val LOCAL_HTTP_PROXY_HOST = "127.0.0.1"
internal const val LOCAL_HTTP_PROXY_PORT = 18090
internal const val LOCAL_HTTP_PROXY_LISTEN = "$LOCAL_HTTP_PROXY_HOST:$LOCAL_HTTP_PROXY_PORT"

/**
 * Loopback HTTP proxy (CONNECT + absolute-form requests) in front of the SOCKS router.
 *
 * [authPolicy] decides which clients are accepted: with front-end credentials clients must present
 * `Proxy-Authorization: Basic ...`; without them unauthenticated clients are accepted only when the
 * policy allows it. Requests that are not accepted are closed without a reply (no 407 challenge),
 * so the port does not advertise a password-protected proxy. [upstreamCredentials] are the
 * credentials used towards the SOCKS router (the process-internal ones).
 */
internal class LocalHttpProxy(
    private val host: String,
    private val port: Int,
    private val socksHost: String,
    private val socksPort: Int,
    private val authPolicy: () -> LocalProxyAuthPolicy,
    private val upstreamCredentials: () -> SocksCredentials?,
) {
    private val active = AtomicBoolean(false)
    private val ioPool = Executors.newCachedThreadPool()
    private val sessions = Collections.synchronizedSet(mutableSetOf<Socket>())
    /** Client socket -> fingerprint of the auth policy it was admitted under. */
    private val admittedUnder = java.util.concurrent.ConcurrentHashMap<Socket, String>()
    private val nextSessionID = AtomicLong(1)
    private val activeSessionCount = AtomicInteger(0)

    @Volatile
    private var serverSocket: ServerSocket? = null

    val isRunning: Boolean
        get() = active.get()

    fun start() {
        if (!active.compareAndSet(false, true)) return
        val server = try {
            ServerSocket().apply {
                reuseAddress = true
                bind(InetSocketAddress(InetAddress.getByName(host), port))
            }
        } catch (error: Throwable) {
            active.set(false)
            ioPool.shutdownNow()
            throw error
        }
        serverSocket = server
        ioPool.execute {
            while (active.get()) {
                try {
                    val client = server.accept()
                    if (activeSessionCount.incrementAndGet() > HTTP_PROXY_MAX_SESSIONS) {
                        activeSessionCount.decrementAndGet()
                        runCatching { client.close() }
                        continue
                    }
                    try {
                        ioPool.execute {
                            try {
                                handleClient(client)
                            } finally {
                                activeSessionCount.decrementAndGet()
                            }
                        }
                    } catch (rejected: Throwable) {
                        activeSessionCount.decrementAndGet()
                        runCatching { client.close() }
                    }
                } catch (_: Throwable) {
                    if (!active.get()) break
                    try {
                        Thread.sleep(ACCEPT_RETRY_DELAY_MS)
                    } catch (_: InterruptedException) {
                        Thread.currentThread().interrupt()
                        break
                    }
                }
            }
        }
    }

    /** Non-blocking: stops accepting and releases the listening port. Follow with [stop]. */
    fun closeListener() {
        active.set(false)
        runCatching { serverSocket?.close() }
    }

    /**
     * Closes client sessions admitted under an auth policy other than [fingerprint], for example
     * after the proxy password was enabled or regenerated. Returns the number of closed sessions.
     */
    fun closeSessionsNotAdmittedUnder(fingerprint: String): Int {
        val stale = admittedUnder.filterValues { it != fingerprint }.keys
        var closed = 0
        stale.forEach { socket ->
            if (runCatching { socket.close() }.isSuccess) closed++
        }
        return closed
    }

    /** Blocking (up to [HTTP_PROXY_STOP_DRAIN_TIMEOUT_MS]); never call on the main thread. */
    fun stop() {
        active.set(false)
        runCatching { serverSocket?.close() }
        synchronized(sessions) {
            sessions.toList()
        }.forEach { runCatching { it.close() } }
        ioPool.shutdownNow()
        runCatching { ioPool.awaitTermination(HTTP_PROXY_STOP_DRAIN_TIMEOUT_MS, TimeUnit.MILLISECONDS) }
    }

    private fun handleClient(client: Socket) {
        val sessionID = nextSessionID.getAndIncrement()
        var upstream: Socket? = null
        sessions.add(client)
        try {
            // The client socket is closed in finally, after an error response had a chance to be
            // written (closing it inside use {} would drop 4xx/502 replies).
            run {
                val clientSocket = client
                tuneSocket(clientSocket)
                clientSocket.soTimeout = HTTP_PROXY_HEADER_TIMEOUT_MS
                // Buffered: bytes that arrive after the header (request body, an early TLS
                // ClientHello after CONNECT) stay in this stream and are relayed from it.
                val input = BufferedInputStream(clientSocket.getInputStream(), HTTP_PROXY_BUFFER_BYTES)
                val output = clientSocket.getOutputStream()
                val policy = authPolicy()
                val request = try {
                    parseHttpProxyRequest(readHttpHeader(input))
                } catch (rejected: HttpProxyRequestException) {
                    // Before authentication nothing is answered unless the proxy is open.
                    if (!policy.allowNoAuth) throw HttpProxySilentCloseException()
                    throw rejected
                }
                if (!isHttpProxyRequestAllowed(policy, request.proxyAuthorization)) {
                    throw HttpProxySilentCloseException()
                }
                admittedUnder[clientSocket] = policy.fingerprint
                if (BuildConfig.DEBUG) {
                    Log.d(LOG_TAG, "http_proxy session=$sessionID connect target=${request.targetHost}:${request.targetPort}")
                }
                val upstreamSocket = openLocalSocks5Connection(
                    proxyHost = socksHost,
                    proxyPort = socksPort,
                    targetHost = request.targetHost,
                    targetPort = request.targetPort,
                    timeoutMs = HTTP_PROXY_CONNECT_TIMEOUT_MS,
                    credentials = upstreamCredentials(),
                    configure = this::tuneSocket,
                )
                upstream = upstreamSocket
                sessions.add(upstreamSocket)
                upstreamSocket.use { socksSocket ->
                    clientSocket.soTimeout = HTTP_PROXY_IDLE_TIMEOUT_MS
                    socksSocket.soTimeout = HTTP_PROXY_IDLE_TIMEOUT_MS
                    if (request.connect) {
                        output.write(HTTP_CONNECT_OK)
                        output.flush()
                        relayTunnel(sessionID, clientSocket, input, socksSocket)
                    } else {
                        socksSocket.getOutputStream().write(request.initialBytesToUpstream)
                        socksSocket.getOutputStream().flush()
                        relaySingleRequest(sessionID, clientSocket, input, socksSocket, request)
                    }
                }
            }
        } catch (_: HttpProxySilentCloseException) {
            Log.i(LOG_TAG, "http_proxy session=$sessionID closed: not authorized")
        } catch (rejected: HttpProxyRequestException) {
            Log.i(LOG_TAG, "http_proxy session=$sessionID rejected: ${rejected.statusCode}")
            runCatching { writeHttpError(client.getOutputStream(), rejected.statusCode, rejected.statusText) }
        } catch (error: Throwable) {
            if (active.get()) {
                Log.w(LOG_TAG, "http_proxy session=$sessionID failed: ${error.javaClass.simpleName}")
            }
            if (upstream == null) {
                runCatching { writeHttpError(client.getOutputStream(), 502, "Bad Gateway") }
            }
        } finally {
            upstream?.let {
                sessions.remove(it)
                runCatching { it.close() }
            }
            runCatching { client.close() }
            sessions.remove(client)
            admittedUnder.remove(client)
        }
    }

    /** CONNECT tunnel: bidirectional relay with half-close on EOF. */
    private fun relayTunnel(sessionID: Long, client: Socket, clientInput: InputStream, upstream: Socket) {
        val closed = AtomicBoolean(false)
        val done = CountDownLatch(2)
        fun closeBoth() {
            if (closed.compareAndSet(false, true)) {
                runCatching { client.close() }
                runCatching { upstream.close() }
            }
        }
        val up = Thread {
            try {
                if (pipe(sessionID, clientInput, upstream.getOutputStream(), "up")) {
                    shutdownOutput(sessionID, upstream, "up")
                } else {
                    closeBoth()
                }
            } catch (_: Throwable) {
                closeBoth()
            } finally {
                done.countDown()
            }
        }
        up.isDaemon = true
        up.start()
        try {
            if (pipe(sessionID, upstream.getInputStream(), client.getOutputStream(), "down")) {
                shutdownOutput(sessionID, client, "down")
            } else {
                closeBoth()
            }
        } catch (_: Throwable) {
            closeBoth()
        } finally {
            done.countDown()
        }
        try {
            done.await()
        } catch (error: InterruptedException) {
            closeBoth()
            Thread.currentThread().interrupt()
        }
        closeBoth()
    }

    /**
     * Plain HTTP request: exactly one request is relayed (its body is framed by Content-Length or
     * chunked encoding), the upstream is asked for `Connection: close`, and the client connection
     * is closed after the response. Pipelined follow-up requests are therefore never sent to the
     * first request's host.
     */
    private fun relaySingleRequest(
        sessionID: Long,
        client: Socket,
        clientInput: InputStream,
        upstream: Socket,
        request: HttpProxyRequest,
    ) {
        val closed = AtomicBoolean(false)
        fun closeBoth() {
            if (closed.compareAndSet(false, true)) {
                runCatching { client.close() }
                runCatching { upstream.close() }
            }
        }
        val body = if (request.chunked || request.contentLength > 0L) {
            Thread {
                try {
                    val upstreamOut = upstream.getOutputStream()
                    if (request.chunked) {
                        forwardChunkedBody(clientInput, upstreamOut)
                    } else {
                        copyExactly(clientInput, upstreamOut, request.contentLength)
                    }
                    upstreamOut.flush()
                } catch (error: Throwable) {
                    if (active.get()) {
                        Log.d(LOG_TAG, "http_proxy session=$sessionID body relay closed: ${error.javaClass.simpleName}")
                    }
                    closeBoth()
                }
            }.apply {
                isDaemon = true
                start()
            }
        } else {
            null
        }
        try {
            pipe(sessionID, upstream.getInputStream(), client.getOutputStream(), "down")
        } finally {
            closeBoth()
            if (body != null) {
                try {
                    body.join(HTTP_PROXY_BODY_JOIN_TIMEOUT_MS)
                } catch (_: InterruptedException) {
                    Thread.currentThread().interrupt()
                }
            }
        }
    }

    private fun pipe(sessionID: Long, input: InputStream, output: OutputStream, direction: String): Boolean =
        try {
            val buffer = ByteArray(HTTP_PROXY_BUFFER_BYTES)
            while (active.get()) {
                val read = input.read(buffer)
                if (read < 0) break
                output.write(buffer, 0, read)
            }
            output.flush()
            true
        } catch (error: Throwable) {
            if (active.get()) {
                Log.d(LOG_TAG, "http_proxy session=$sessionID pipe=$direction closed: ${error.javaClass.simpleName}")
            }
            false
        }

    private fun shutdownOutput(sessionID: Long, socket: Socket, direction: String) {
        runCatching {
            if (!socket.isClosed && !socket.isOutputShutdown) {
                socket.shutdownOutput()
            }
        }.onFailure { error ->
            if (active.get()) {
                Log.d(LOG_TAG, "http_proxy session=$sessionID pipe=$direction half-close failed: ${error.javaClass.simpleName}")
            }
        }
    }

    private fun tuneSocket(socket: Socket) {
        runCatching { socket.tcpNoDelay = true }
        runCatching { socket.receiveBufferSize = HTTP_PROXY_BUFFER_BYTES }
        runCatching { socket.sendBufferSize = HTTP_PROXY_BUFFER_BYTES }
    }

    private fun readHttpHeader(input: InputStream): ByteArray =
        readHttpHeaderBlock(input, HTTP_PROXY_HEADER_LIMIT_BYTES)
            ?: throw HttpProxyRequestException(431, "Request Header Fields Too Large", "header too large")

    private fun writeHttpError(output: OutputStream, code: Int, status: String) {
        val body = "$code $status\n"
        output.write(
            (
                "HTTP/1.1 $code $status\r\n" +
                    "Connection: close\r\nContent-Length: ${body.length}\r\n\r\n$body"
                ).toByteArray(Charsets.US_ASCII),
        )
        output.flush()
    }

    private companion object {
        private const val LOG_TAG = "TWHttpProxy"
        private const val HTTP_PROXY_BUFFER_BYTES = 64 * 1024
        private const val HTTP_PROXY_HEADER_LIMIT_BYTES = 64 * 1024
        private const val HTTP_PROXY_CONNECT_TIMEOUT_MS = 30_000
        private const val HTTP_PROXY_HEADER_TIMEOUT_MS = 45_000
        private const val HTTP_PROXY_IDLE_TIMEOUT_MS = 3 * 60 * 1000
        private const val HTTP_PROXY_STOP_DRAIN_TIMEOUT_MS = 2_000L
        private const val HTTP_PROXY_BODY_JOIN_TIMEOUT_MS = 1_000L
        private const val HTTP_PROXY_MAX_SESSIONS = 128
        private const val ACCEPT_RETRY_DELAY_MS = 100L
        private val HTTP_CONNECT_OK = "HTTP/1.1 200 Connection Established\r\n\r\n".toByteArray(Charsets.US_ASCII)
    }
}

/** Unauthorized request: the connection is closed without a reply. */
internal class HttpProxySilentCloseException : Exception("not authorized")

/** Whether a request carrying [proxyAuthorization] may use the proxy under [policy]. */
internal fun isHttpProxyRequestAllowed(policy: LocalProxyAuthPolicy, proxyAuthorization: String?): Boolean {
    val required = policy.frontEnd ?: return policy.allowNoAuth
    return isHttpProxyAuthorized(proxyAuthorization, required)
}

internal data class HttpProxyRequest(
    val connect: Boolean,
    val method: String,
    val targetHost: String,
    val targetPort: Int,
    val initialBytesToUpstream: ByteArray,
    val proxyAuthorization: String? = null,
    /** Request body length from Content-Length, or -1 when absent. */
    val contentLength: Long = -1L,
    val chunked: Boolean = false,
) {
    override fun toString(): String =
        "HttpProxyRequest(connect=$connect, method=$method, targetPort=$targetPort)"
}

internal fun parseHttpProxyRequest(headerBytes: ByteArray): HttpProxyRequest {
    val headerText = headerBytes.toString(Charsets.ISO_8859_1)
    val headerEnd = headerText.indexOf("\r\n\r\n")
    if (headerEnd <= 0) {
        throw HttpProxyRequestException(400, "Bad Request", "missing header terminator")
    }
    val lines = headerText.substring(0, headerEnd).split("\r\n")
    val requestLine = lines.firstOrNull().orEmpty()
    val parts = requestLine.split(' ', limit = 3)
    if (parts.size != 3) {
        throw HttpProxyRequestException(400, "Bad Request", "bad request line")
    }
    val method = parts[0].uppercase(Locale.ROOT)
    val target = parts[1]
    val version = parts[2].ifBlank { "HTTP/1.1" }
    val headers = lines.drop(1)
    val proxyAuthorization = headerValue(headers, "Proxy-Authorization")
    if (method == "CONNECT") {
        val hostPort = parseHostPort(target, defaultPort = 443)
        return HttpProxyRequest(
            connect = true,
            method = method,
            targetHost = hostPort.host,
            targetPort = hostPort.port,
            initialBytesToUpstream = ByteArray(0),
            proxyAuthorization = proxyAuthorization,
        )
    }
    if (!HTTP_METHODS_WITH_REQUEST_TARGET.contains(method)) {
        throw HttpProxyRequestException(501, "Not Implemented", "unsupported method")
    }
    val targetUri = runCatching { URI(target) }.getOrNull()
    val hostPort: HostPort
    val originTarget: String
    if (targetUri?.scheme?.equals("http", ignoreCase = true) == true) {
        val host = targetUri.host
            ?: throw HttpProxyRequestException(400, "Bad Request", "target host is empty")
        val port = if (targetUri.port > 0) targetUri.port else 80
        hostPort = HostPort(host, port)
        val path = targetUri.rawPath?.ifBlank { "/" } ?: "/"
        originTarget = path + targetUri.rawQuery?.let { "?$it" }.orEmpty()
    } else if (target.startsWith("/")) {
        val hostHeader = headerValue(headers, "Host")
            ?: throw HttpProxyRequestException(400, "Bad Request", "missing host header")
        hostPort = parseHostPort(hostHeader, defaultPort = 80)
        originTarget = target
    } else {
        throw HttpProxyRequestException(400, "Bad Request", "unsupported request target")
    }
    val transferEncoding = headerValue(headers, "Transfer-Encoding").orEmpty()
    val chunked = transferEncoding.split(',').any { it.trim().equals("chunked", ignoreCase = true) }
    val contentLength = if (chunked) {
        -1L
    } else {
        headerValue(headers, "Content-Length")?.let { raw ->
            raw.trim().toLongOrNull()?.takeIf { it >= 0L }
                ?: throw HttpProxyRequestException(400, "Bad Request", "bad content length")
        } ?: -1L
    }
    if (!chunked && transferEncoding.isNotBlank()) {
        throw HttpProxyRequestException(501, "Not Implemented", "unsupported transfer encoding")
    }
    return HttpProxyRequest(
        connect = false,
        method = method,
        targetHost = hostPort.host,
        targetPort = hostPort.port,
        initialBytesToUpstream = buildOriginFormRequest(method, originTarget, version, headers),
        proxyAuthorization = proxyAuthorization,
        contentLength = contentLength,
        chunked = chunked,
    )
}

/** Validates `Proxy-Authorization: Basic base64(user:pass)` against [expected] in constant time. */
internal fun isHttpProxyAuthorized(headerValue: String?, expected: SocksCredentials): Boolean {
    val value = headerValue?.trim().orEmpty()
    if (value.isEmpty()) return false
    val scheme = value.substringBefore(' ')
    if (!scheme.equals("Basic", ignoreCase = true)) return false
    val encoded = value.substringAfter(' ', "").trim()
    if (encoded.isEmpty()) return false
    val decoded = runCatching {
        String(Base64.getDecoder().decode(encoded), Charsets.UTF_8)
    }.getOrNull() ?: return false
    val separator = decoded.indexOf(':')
    if (separator < 0) return false
    val user = decoded.substring(0, separator)
    val pass = decoded.substring(separator + 1)
    return constantTimeEquals(user, expected.username) and constantTimeEquals(pass, expected.password)
}

private fun headerValue(headers: List<String>, name: String): String? =
    headers.firstOrNull { it.length > name.length && it[name.length] == ':' && it.startsWith(name, ignoreCase = true) }
        ?.substring(name.length + 1)
        ?.trim()

private fun buildOriginFormRequest(method: String, target: String, version: String, headers: List<String>): ByteArray {
    val out = StringBuilder()
    out.append(method).append(' ').append(target.ifBlank { "/" }).append(' ').append(version).append("\r\n")
    headers.forEach { header ->
        if (HOP_BY_HOP_REQUEST_HEADERS.none { header.startsWith("$it:", ignoreCase = true) }) {
            out.append(header).append("\r\n")
        }
    }
    out.append("Connection: close\r\n\r\n")
    return out.toString().toByteArray(Charsets.ISO_8859_1)
}

private val HOP_BY_HOP_REQUEST_HEADERS = listOf(
    "Proxy-Connection",
    "Proxy-Authorization",
    "Connection",
    "Keep-Alive",
)

private fun parseHostPort(value: String, defaultPort: Int): HostPort {
    val trimmed = value.trim()
    if (trimmed.isBlank()) {
        throw HttpProxyRequestException(400, "Bad Request", "target host is empty")
    }
    if (trimmed.startsWith("[")) {
        val end = trimmed.indexOf(']')
        if (end <= 1) throw HttpProxyRequestException(400, "Bad Request", "bad bracket host")
        val host = trimmed.substring(1, end)
        val port = if (trimmed.length > end + 1) {
            if (trimmed[end + 1] != ':') throw HttpProxyRequestException(400, "Bad Request", "bad host port")
            parsePort(trimmed.substring(end + 2), defaultPort)
        } else {
            defaultPort
        }
        return HostPort(host, port)
    }
    val colon = trimmed.lastIndexOf(':')
    if (colon > 0 && trimmed.indexOf(':') == colon) {
        return HostPort(trimmed.substring(0, colon), parsePort(trimmed.substring(colon + 1), defaultPort))
    }
    return HostPort(trimmed, defaultPort)
}

private fun parsePort(value: String, defaultPort: Int): Int {
    if (value.isBlank()) return defaultPort
    val port = value.toIntOrNull()
        ?: throw HttpProxyRequestException(400, "Bad Request", "bad port")
    if (port !in 1..65535) {
        throw HttpProxyRequestException(400, "Bad Request", "bad port")
    }
    return port
}

private data class HostPort(val host: String, val port: Int)

internal class HttpProxyRequestException(
    val statusCode: Int,
    val statusText: String,
    message: String,
) : Exception(message)

private val HTTP_METHODS_WITH_REQUEST_TARGET = setOf(
    "GET",
    "HEAD",
    "POST",
    "PUT",
    "DELETE",
    "PATCH",
    "OPTIONS",
)

/**
 * Reads an HTTP header block (up to and including the empty line) from [input]. The stream should
 * be buffered; bytes after the header remain unread in it. Returns null when [limitBytes] is hit.
 */
internal fun readHttpHeaderBlock(input: InputStream, limitBytes: Int): ByteArray? {
    val out = ByteArrayOutputStream(1024)
    var state = 0
    while (out.size() < limitBytes) {
        val value = input.read()
        if (value < 0) throw EOFException()
        out.write(value)
        state = when {
            state == 0 && value == '\r'.code -> 1
            state == 1 && value == '\n'.code -> 2
            state == 2 && value == '\r'.code -> 3
            state == 3 && value == '\n'.code -> return out.toByteArray()
            value == '\r'.code -> 1
            else -> 0
        }
    }
    return null
}

/** Copies exactly [length] bytes from [input] to [output]. */
internal fun copyExactly(input: InputStream, output: OutputStream, length: Long) {
    var remaining = length
    val buffer = ByteArray(minOf(length, COPY_BUFFER_BYTES.toLong()).toInt().coerceAtLeast(1))
    while (remaining > 0L) {
        val read = input.read(buffer, 0, minOf(remaining, buffer.size.toLong()).toInt())
        if (read < 0) throw EOFException("body truncated")
        output.write(buffer, 0, read)
        remaining -= read
    }
}

/**
 * Forwards one chunked-encoded message body (chunks, last chunk and trailers) from [input] to
 * [output] verbatim and stops right after it, leaving any following bytes unread.
 */
internal fun forwardChunkedBody(input: InputStream, output: OutputStream) {
    while (true) {
        val sizeLine = readCrlfLine(input, CHUNK_LINE_LIMIT_BYTES)
        output.write(sizeLine)
        val sizeText = sizeLine.toString(Charsets.ISO_8859_1).trimEnd('\r', '\n').substringBefore(';').trim()
        val size = sizeText.toLongOrNull(16)
        if (size == null || size < 0L) throw IOException("bad chunk size")
        if (size == 0L) {
            while (true) {
                val trailer = readCrlfLine(input, CHUNK_LINE_LIMIT_BYTES)
                output.write(trailer)
                if (trailer.size <= 2) return
            }
        }
        copyExactly(input, output, size)
        val terminator = readCrlfLine(input, CHUNK_LINE_LIMIT_BYTES)
        if (terminator.size != 2) throw IOException("bad chunk terminator")
        output.write(terminator)
    }
}

private fun readCrlfLine(input: InputStream, limitBytes: Int): ByteArray {
    val out = ByteArrayOutputStream(32)
    var previous = -1
    while (out.size() < limitBytes) {
        val value = input.read()
        if (value < 0) throw EOFException("chunked body truncated")
        out.write(value)
        if (previous == '\r'.code && value == '\n'.code) return out.toByteArray()
        previous = value
    }
    throw IOException("chunk line too long")
}

/**
 * Opens a TCP connection to the loopback SOCKS5 listener at [proxyHost]:[proxyPort] and issues a
 * CONNECT to [targetHost]:[targetPort] (always as a domain name). Authenticates with
 * [credentials] (RFC 1929) when they are set. The returned socket has soTimeout = [timeoutMs].
 */
internal fun openLocalSocks5Connection(
    proxyHost: String,
    proxyPort: Int,
    targetHost: String,
    targetPort: Int,
    timeoutMs: Int,
    credentials: SocksCredentials?,
    configure: (Socket) -> Unit = {},
): Socket {
    val socket = Socket()
    try {
        configure(socket)
        socket.soTimeout = timeoutMs
        socket.connect(InetSocketAddress(proxyHost, proxyPort), timeoutMs)
        // Unbuffered on purpose: bytes the target sends right after the SOCKS reply (for example a
        // server-first banner) must stay in the socket for the caller.
        val input = socket.getInputStream()
        val output = socket.getOutputStream()
        Socks5Auth.negotiateClient(input, output, credentials, peerPort = proxyPort)
        socks5ConnectDomain(input, output, targetHost, targetPort)
        return socket
    } catch (error: Throwable) {
        runCatching { socket.close() }
        throw error
    }
}

/** Sends a SOCKS5 CONNECT (ATYP=domain) and consumes the reply. Throws when it is not a success. */
internal fun socks5ConnectDomain(input: InputStream, output: OutputStream, targetHost: String, targetPort: Int) {
    val hostBytes = targetHost.toByteArray(Charsets.UTF_8)
    if (hostBytes.isEmpty() || hostBytes.size > BYTE_MASK) {
        throw EOFException("target host length is invalid")
    }
    if (targetPort !in 1..65535) throw EOFException("target port is invalid")
    output.write(
        byteArrayOf(
            SOCKS_VERSION.toByte(),
            SOCKS_CONNECT.toByte(),
            0,
            SOCKS_ATYP_DOMAIN.toByte(),
            hostBytes.size.toByte(),
        ) + hostBytes + byteArrayOf(((targetPort ushr 8) and BYTE_MASK).toByte(), (targetPort and BYTE_MASK).toByte()),
    )
    output.flush()
    val response = readExactBytes(input, 4)
    if ((response[0].toInt() and BYTE_MASK) != SOCKS_VERSION) {
        throw EOFException("bad socks response version")
    }
    val reply = response[1].toInt() and BYTE_MASK
    if (reply != 0) {
        throw EOFException("socks connect failed rep=$reply")
    }
    val bindLength = when (response[3].toInt() and BYTE_MASK) {
        SOCKS_ATYP_IPV4 -> 4
        SOCKS_ATYP_DOMAIN -> readExactBytes(input, 1)[0].toInt() and BYTE_MASK
        SOCKS_ATYP_IPV6 -> 16
        else -> throw EOFException("bad socks bind atyp")
    }
    readExactBytes(input, bindLength + 2)
}

/**
 * Performs a single GET of [url] (http or https) through the loopback SOCKS listener and returns
 * the response body. Used by health probes; certificate and hostname are verified for https.
 */
internal fun httpGetViaLocalSocks(
    proxyHost: String,
    proxyPort: Int,
    url: String,
    timeoutMs: Int,
    credentials: SocksCredentials?,
    maxBodyBytes: Int = HTTP_GET_MAX_BODY_BYTES,
): String {
    val uri = URI(url)
    val scheme = (uri.scheme ?: "").lowercase(Locale.ROOT)
    val host = uri.host ?: throw IOException("url host is empty")
    val secure = when (scheme) {
        "https" -> true
        "http" -> false
        else -> throw IOException("unsupported url scheme")
    }
    val port = if (uri.port > 0) uri.port else if (secure) 443 else 80
    val raw = openLocalSocks5Connection(proxyHost, proxyPort, host, port, timeoutMs, credentials) {
        runCatching { it.tcpNoDelay = true }
    }
    var socket: Socket = raw
    try {
        if (secure) {
            val factory = SSLSocketFactory.getDefault() as SSLSocketFactory
            val ssl = factory.createSocket(raw, host, port, true) as SSLSocket
            socket = ssl
            ssl.soTimeout = timeoutMs
            ssl.startHandshake()
            if (!HttpsURLConnection.getDefaultHostnameVerifier().verify(host, ssl.session)) {
                throw SSLPeerUnverifiedException("hostname verification failed")
            }
        }
        val path = (uri.rawPath?.ifBlank { "/" } ?: "/") + uri.rawQuery?.let { "?$it" }.orEmpty()
        val hostHeader = if (uri.port > 0) "$host:${uri.port}" else host
        val request = "GET $path HTTP/1.1\r\nHost: $hostHeader\r\nUser-Agent: TrafficWrapper\r\n" +
            "Accept: */*\r\nConnection: close\r\n\r\n"
        val output = socket.getOutputStream()
        output.write(request.toByteArray(Charsets.ISO_8859_1))
        output.flush()
        val input = BufferedInputStream(socket.getInputStream(), HTTP_GET_READ_BUFFER_BYTES)
        val header = readHttpHeaderBlock(input, HTTP_GET_HEADER_LIMIT_BYTES)
            ?.toString(Charsets.ISO_8859_1)
            ?: throw IOException("http header too large")
        val headerLines = header.split("\r\n")
        val status = headerLines.firstOrNull().orEmpty().split(' ').getOrNull(1)?.toIntOrNull() ?: 0
        if (status !in 200..299) throw IOException("http status $status")
        val body = readHttpResponseBody(input, headerLines.drop(1), maxBodyBytes)
        return body.toString(Charsets.UTF_8)
    } finally {
        runCatching { socket.close() }
        runCatching { raw.close() }
    }
}

/** Reads a response body framed by chunked encoding, Content-Length or connection close. */
internal fun readHttpResponseBody(input: InputStream, headerLines: List<String>, maxBodyBytes: Int): ByteArray {
    val transferEncoding = headerValue(headerLines, "Transfer-Encoding").orEmpty()
    val out = ByteArrayOutputStream()
    if (transferEncoding.split(',').any { it.trim().equals("chunked", ignoreCase = true) }) {
        while (true) {
            val sizeLine = readCrlfLine(input, CHUNK_LINE_LIMIT_BYTES).toString(Charsets.ISO_8859_1)
            val size = sizeLine.trimEnd('\r', '\n').substringBefore(';').trim().toLongOrNull(16)
                ?: throw IOException("bad chunk size")
            if (size == 0L) break
            if (out.size() + size > maxBodyBytes) throw IOException("http body too large")
            copyExactly(input, out, size)
            readCrlfLine(input, CHUNK_LINE_LIMIT_BYTES)
        }
        return out.toByteArray()
    }
    val contentLength = headerValue(headerLines, "Content-Length")?.toLongOrNull()
    if (contentLength != null) {
        if (contentLength > maxBodyBytes) throw IOException("http body too large")
        copyExactly(input, out, contentLength)
        return out.toByteArray()
    }
    val buffer = ByteArray(COPY_BUFFER_BYTES)
    while (true) {
        val read = input.read(buffer)
        if (read < 0) break
        if (out.size() + read > maxBodyBytes) throw IOException("http body too large")
        out.write(buffer, 0, read)
    }
    return out.toByteArray()
}

private fun readExactBytes(input: InputStream, size: Int): ByteArray {
    val out = ByteArray(size)
    var offset = 0
    while (offset < size) {
        val read = input.read(out, offset, size - offset)
        if (read < 0) throw EOFException()
        offset += read
    }
    return out
}

private const val SOCKS_VERSION = 5
private const val SOCKS_CONNECT = 1
private const val SOCKS_ATYP_IPV4 = 1
private const val SOCKS_ATYP_DOMAIN = 3
private const val SOCKS_ATYP_IPV6 = 4
private const val BYTE_MASK = 0xff
private const val HTTP_GET_READ_BUFFER_BYTES = 8 * 1024
private const val COPY_BUFFER_BYTES = 32 * 1024
private const val CHUNK_LINE_LIMIT_BYTES = 8 * 1024
private const val HTTP_GET_HEADER_LIMIT_BYTES = 64 * 1024
private const val HTTP_GET_MAX_BODY_BYTES = 256 * 1024
