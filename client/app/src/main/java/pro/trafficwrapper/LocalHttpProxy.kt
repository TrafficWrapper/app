package pro.trafficwrapper

import android.util.Log
import java.io.EOFException
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.URI
import java.util.Collections
import java.util.Locale
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

internal const val LOCAL_HTTP_PROXY_HOST = "127.0.0.1"
internal const val LOCAL_HTTP_PROXY_PORT = 18090
internal const val LOCAL_HTTP_PROXY_LISTEN = "$LOCAL_HTTP_PROXY_HOST:$LOCAL_HTTP_PROXY_PORT"

internal class LocalHttpProxy(
    private val host: String,
    private val port: Int,
    private val socksHost: String,
    private val socksPort: Int,
) {
    private val active = AtomicBoolean(false)
    private val ioPool = Executors.newCachedThreadPool()
    private val sessions = Collections.synchronizedSet(mutableSetOf<Socket>())
    private val nextSessionID = AtomicLong(1)

    @Volatile
    private var serverSocket: ServerSocket? = null

    val isRunning: Boolean
        get() = active.get()

    fun start() {
        if (!active.compareAndSet(false, true)) return
        val server = ServerSocket().apply {
            reuseAddress = true
            bind(InetSocketAddress(InetAddress.getByName(host), port))
        }
        serverSocket = server
        ioPool.execute {
            while (active.get()) {
                try {
                    val client = server.accept()
                    ioPool.execute { handleClient(client) }
                } catch (_: Throwable) {
                    if (active.get()) {
                        runCatching { Thread.sleep(100) }
                    }
                }
            }
        }
    }

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
            client.use { clientSocket ->
                tuneSocket(clientSocket)
                clientSocket.soTimeout = HTTP_PROXY_HEADER_TIMEOUT_MS
                val input = clientSocket.getInputStream()
                val output = clientSocket.getOutputStream()
                val request = parseHttpProxyRequest(readHttpHeader(input))
                Log.d(LOG_TAG, "http_proxy session=$sessionID connect target=${request.targetHost}:${request.targetPort}")
                val upstreamSocket = openSocks5Socket(request.targetHost, request.targetPort)
                upstream = upstreamSocket
                sessions.add(upstreamSocket)
                upstreamSocket.use { socksSocket ->
                    clientSocket.soTimeout = HTTP_PROXY_IDLE_TIMEOUT_MS
                    socksSocket.soTimeout = HTTP_PROXY_IDLE_TIMEOUT_MS
                    if (request.connect) {
                        output.write(HTTP_CONNECT_OK)
                        output.flush()
                    } else {
                        socksSocket.getOutputStream().write(request.initialBytesToUpstream)
                        socksSocket.getOutputStream().flush()
                    }
                    proxy(sessionID, clientSocket, socksSocket)
                }
            }
        } catch (rejected: HttpProxyRequestException) {
            Log.i(LOG_TAG, "http_proxy session=$sessionID rejected: ${rejected.message}")
            runCatching { writeHttpError(client.getOutputStream(), rejected.statusCode, rejected.statusText) }
        } catch (error: Throwable) {
            if (active.get()) {
                Log.w(LOG_TAG, "http_proxy session=$sessionID failed: ${error.message}")
            }
            runCatching { writeHttpError(client.getOutputStream(), 502, "Bad Gateway") }
        } finally {
            upstream?.let {
                sessions.remove(it)
                runCatching { it.close() }
            }
            sessions.remove(client)
        }
    }

    private fun openSocks5Socket(targetHost: String, targetPort: Int): Socket {
        val socket = Socket()
        try {
            tuneSocket(socket)
            socket.soTimeout = HTTP_PROXY_CONNECT_TIMEOUT_MS
            socket.connect(InetSocketAddress(socksHost, socksPort), HTTP_PROXY_CONNECT_TIMEOUT_MS)
            val input = socket.getInputStream()
            val output = socket.getOutputStream()
            output.write(byteArrayOf(SOCKS_VERSION.toByte(), 1, SOCKS_NO_AUTH.toByte()))
            output.flush()
            val greeting = input.readExact(2)
            if ((greeting[0].toInt() and BYTE_MASK) != SOCKS_VERSION ||
                (greeting[1].toInt() and BYTE_MASK) != SOCKS_NO_AUTH
            ) {
                throw EOFException("bad socks greeting")
            }
            val hostBytes = targetHost.toByteArray(Charsets.UTF_8)
            if (hostBytes.isEmpty() || hostBytes.size > BYTE_MASK) {
                throw EOFException("target host length is invalid")
            }
            output.write(
                byteArrayOf(
                    SOCKS_VERSION.toByte(),
                    SOCKS_CONNECT.toByte(),
                    0,
                    SOCKS_ATYP_DOMAIN.toByte(),
                    hostBytes.size.toByte(),
                ),
            )
            output.write(hostBytes)
            output.write(byteArrayOf(((targetPort ushr 8) and BYTE_MASK).toByte(), (targetPort and BYTE_MASK).toByte()))
            output.flush()
            val response = input.readExact(4)
            if ((response[0].toInt() and BYTE_MASK) != SOCKS_VERSION ||
                (response[1].toInt() and BYTE_MASK) != 0
            ) {
                throw EOFException("socks connect failed")
            }
            val bindLength = when (response[3].toInt() and BYTE_MASK) {
                SOCKS_ATYP_IPV4 -> 4
                SOCKS_ATYP_DOMAIN -> input.readByteOrThrow()
                SOCKS_ATYP_IPV6 -> 16
                else -> throw EOFException("bad socks bind atyp")
            }
            input.readExact(bindLength + 2)
            return socket
        } catch (error: Throwable) {
            runCatching { socket.close() }
            throw error
        }
    }

    private fun proxy(sessionID: Long, client: Socket, upstream: Socket) {
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
                if (pipe(sessionID, client.getInputStream(), upstream.getOutputStream(), "up")) {
                    shutdownOutput(sessionID, upstream, "up")
                } else {
                    closeBoth()
                }
            } finally {
                done.countDown()
            }
        }
        val down = Thread {
            try {
                if (pipe(sessionID, upstream.getInputStream(), client.getOutputStream(), "down")) {
                    shutdownOutput(sessionID, client, "down")
                } else {
                    closeBoth()
                }
            } finally {
                done.countDown()
            }
        }
        up.isDaemon = true
        down.isDaemon = true
        up.start()
        down.start()
        try {
            done.await()
        } catch (error: InterruptedException) {
            closeBoth()
            Thread.currentThread().interrupt()
        }
        closeBoth()
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
                Log.d(LOG_TAG, "http_proxy session=$sessionID pipe=$direction closed: ${error.message}")
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
                Log.d(LOG_TAG, "http_proxy session=$sessionID pipe=$direction half-close failed: ${error.message}")
            }
        }
    }

    private fun tuneSocket(socket: Socket) {
        runCatching { socket.tcpNoDelay = true }
        runCatching { socket.receiveBufferSize = HTTP_PROXY_BUFFER_BYTES }
        runCatching { socket.sendBufferSize = HTTP_PROXY_BUFFER_BYTES }
    }

    private fun readHttpHeader(input: InputStream): ByteArray {
        val out = ArrayList<Byte>(1024)
        var state = 0
        while (out.size < HTTP_PROXY_HEADER_LIMIT_BYTES) {
            val value = input.read()
            if (value < 0) throw EOFException()
            out.add(value.toByte())
            state = when {
                state == 0 && value == '\r'.code -> 1
                state == 1 && value == '\n'.code -> 2
                state == 2 && value == '\r'.code -> 3
                state == 3 && value == '\n'.code -> return out.toByteArray()
                value == '\r'.code -> 1
                else -> 0
            }
        }
        throw HttpProxyRequestException(431, "Request Header Fields Too Large", "header too large")
    }

    private fun InputStream.readByteOrThrow(): Int {
        val value = read()
        if (value < 0) throw EOFException()
        return value
    }

    private fun InputStream.readExact(size: Int): ByteArray {
        val out = ByteArray(size)
        var offset = 0
        while (offset < size) {
            val read = read(out, offset, size - offset)
            if (read < 0) throw EOFException()
            offset += read
        }
        return out
    }

    private fun writeHttpError(output: OutputStream, code: Int, status: String) {
        val body = "$code $status\n"
        output.write(
            "HTTP/1.1 $code $status\r\nConnection: close\r\nContent-Length: ${body.length}\r\n\r\n$body"
                .toByteArray(Charsets.US_ASCII),
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
        private val HTTP_CONNECT_OK = "HTTP/1.1 200 Connection Established\r\n\r\n".toByteArray(Charsets.US_ASCII)
    }
}

internal data class HttpProxyRequest(
    val connect: Boolean,
    val method: String,
    val targetHost: String,
    val targetPort: Int,
    val initialBytesToUpstream: ByteArray,
)

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
    if (method == "CONNECT") {
        val hostPort = parseHostPort(target, defaultPort = 443)
        return HttpProxyRequest(
            connect = true,
            method = method,
            targetHost = hostPort.host,
            targetPort = hostPort.port,
            initialBytesToUpstream = ByteArray(0),
        )
    }
    if (!HTTP_METHODS_WITH_REQUEST_TARGET.contains(method)) {
        throw HttpProxyRequestException(501, "Not Implemented", "unsupported method $method")
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
        val hostHeader = lines.drop(1)
            .firstOrNull { it.startsWith("Host:", ignoreCase = true) }
            ?.substringAfter(':')
            ?.trim()
            ?: throw HttpProxyRequestException(400, "Bad Request", "missing host header")
        hostPort = parseHostPort(hostHeader, defaultPort = 80)
        originTarget = target
    } else {
        throw HttpProxyRequestException(400, "Bad Request", "unsupported request target")
    }
    return HttpProxyRequest(
        connect = false,
        method = method,
        targetHost = hostPort.host,
        targetPort = hostPort.port,
        initialBytesToUpstream = buildOriginFormRequest(method, originTarget, version, lines.drop(1)),
    )
}

private fun buildOriginFormRequest(method: String, target: String, version: String, headers: List<String>): ByteArray {
    val out = StringBuilder()
    out.append(method).append(' ').append(target.ifBlank { "/" }).append(' ').append(version).append("\r\n")
    headers.forEach { header ->
        if (!header.startsWith("Proxy-Connection:", ignoreCase = true) &&
            !header.startsWith("Connection:", ignoreCase = true)
        ) {
            out.append(header).append("\r\n")
        }
    }
    out.append("Connection: close\r\n\r\n")
    return out.toString().toByteArray(Charsets.ISO_8859_1)
}

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

private const val SOCKS_VERSION = 5
private const val SOCKS_NO_AUTH = 0
private const val SOCKS_CONNECT = 1
private const val SOCKS_ATYP_IPV4 = 1
private const val SOCKS_ATYP_DOMAIN = 3
private const val SOCKS_ATYP_IPV6 = 4
private const val BYTE_MASK = 0xff
