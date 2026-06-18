package pro.netcloud.trafficwrapper

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build
import android.os.PowerManager
import android.os.SystemClock
import android.util.Base64
import android.util.Log
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.io.EOFException
import java.io.InputStream
import java.net.InetSocketAddress
import java.net.ConnectException
import java.net.NoRouteToHostException
import java.net.Proxy
import java.net.Socket
import java.net.SocketTimeoutException
import java.net.URL
import java.net.UnknownHostException
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Locale
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicLong
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLException

object Telemetry {
    private val io = Executors.newSingleThreadExecutor { task ->
        Thread(task, "TWTelemetry").apply { isDaemon = true }
    }
    private val queue = ConcurrentLinkedQueue<QueuedEvent>()
    private val lastDedupKeyAtMs = ConcurrentHashMap<String, Long>()
    private val secureRandom = SecureRandom()
    private val bootID = UUID.randomUUID().toString()
    private val nextFlushAtElapsedMs = AtomicLong(0)
    private val backoffMs = AtomicLong(BACKOFF_MIN_MS)
    private val seq = AtomicLong(SEQ_UNINITIALIZED)
    private val seqLock = Any()

    fun event(context: Context, kind: String, vararg fields: Pair<String, Any?>) {
        if (!enabled(context)) return
        runCatching {
            val safeKind = sanitizeToken(kind, MAX_KIND_CHARS).ifBlank { "unknown" }
            val safeFields = sanitizeFields(fields)
            val dedupKey = safeFields.stringValue("rsn").ifBlank { safeFields.stringValue("action") }
                .takeIf { it.isNotBlank() }
                ?.let { "$safeKind:$it" }
                ?: safeKind
            val nowMs = System.currentTimeMillis()
            val accept = lastDedupKeyAtMs.compute(dedupKey) { _, previousAt ->
                if (previousAt != null && nowMs - previousAt < DEDUP_WINDOW_MS) previousAt else nowMs
            } == nowMs
            if (!accept) return
            enqueue(
                QueuedEvent(
                    kind = safeKind,
                    wallTimeMs = nowMs,
                    monoMs = SystemClock.elapsedRealtime(),
                    fields = safeFields,
                ),
            )
            Log.i(LOG_TAG, "telemetry queued kind=$safeKind")
            io.execute { maybeFlush(context.applicationContext, force = false) }
        }.onFailure { error ->
            Log.w(LOG_TAG, "telemetry enqueue failed: ${safeErrorMessage(error)}")
        }
    }

    fun flush(context: Context) {
        if (!enabled(context)) return
        runCatching {
            io.execute { maybeFlush(context.applicationContext, force = true) }
        }.onFailure { error ->
            Log.w(LOG_TAG, "telemetry flush schedule failed: ${safeErrorMessage(error)}")
        }
    }

    fun clearLocal(context: Context) {
        runCatching {
            queue.clear()
            val dir = telemetryDir(context.applicationContext)
            File(dir, SPOOL_FILE_NAME).delete()
            Log.i(LOG_TAG, "telemetry local queue/spool cleared")
        }
    }

    fun errorKind(error: Throwable?): String {
        val message = error?.message.orEmpty().lowercase(Locale.ROOT)
        return when {
            error is SocketTimeoutException || "timeout" in message || "timed out" in message -> "timeout"
            error is ConnectException && ("refused" in message || "econnrefused" in message) -> "refused"
            error is UnknownHostException -> "dns"
            error is SSLException -> "tls"
            error is NoRouteToHostException -> "reset"
            "reset" in message || "broken pipe" in message -> "reset"
            "config" in message || "json" in message || "invalid" in message -> "config"
            "process" in message || "exit" in message -> "process"
            else -> "unknown"
        }
    }

    fun safeErrorMessage(error: Throwable?): String =
        sanitizeErrorText(error?.message ?: error?.javaClass?.simpleName.orEmpty())

    private fun enabled(context: Context): Boolean =
        runCatching { TransportLifecycleStore.telemetryEnabled(context.applicationContext) }.getOrDefault(false)

    private fun enqueue(event: QueuedEvent) {
        queue.add(event)
        while (queue.size > QUEUE_CAP) {
            queue.poll() ?: break
        }
    }

    private fun maybeFlush(context: Context, force: Boolean) {
        runCatching {
            if (!enabled(context)) return
            appendQueueToSpool(context)
            val nowElapsed = SystemClock.elapsedRealtime()
            if (!force && nowElapsed < nextFlushAtElapsedMs.get()) return
            val spool = spoolFile(context)
            val lines = if (spool.exists()) spool.readLines(Charsets.UTF_8) else emptyList()
            val batch = readBatch(lines)
            if (batch.events.isEmpty()) {
                if (batch.consumedLines > 0) {
                    removeConsumedLines(spool, lines, batch.consumedLines)
                }
                return
            }
            val body = buildBody(context, batch.events)
            val bodyString = body.toString()
            val bodyBytes = bodyString.toByteArray(Charsets.UTF_8)
            val endpointLabel = if (DeploymentConfig.IS_PUBLIC_PLATFORM) {
                PUBLIC_TELEMETRY_URL
            } else {
                BuildConfig.TELEMETRY_ENDPOINT
            }
            Log.i(LOG_TAG, "telemetry flush attempt events=${batch.events.size} endpoint=$endpointLabel")
            val post = if (DeploymentConfig.IS_PUBLIC_PLATFORM) {
                postPublic(context, bodyBytes)
            } else {
                val endpoint = URL(BuildConfig.TELEMETRY_ENDPOINT)
                val effectivePort = if (endpoint.port > 0) endpoint.port else endpoint.defaultPort
                if (
                    endpoint.protocol != "https" ||
                    endpoint.host == "127.0.0.1" ||
                    endpoint.host.equals("localhost", ignoreCase = true) ||
                    effectivePort in BANNED_ENDPOINT_PORTS
                ) {
                    Log.w(LOG_TAG, "telemetry endpoint rejected: ${endpoint.protocol}://${endpoint.host}:$effectivePort")
                    removeConsumedLines(spool, lines, batch.consumedLines)
                    return
                }
                post(context, endpoint, bodyBytes)
            }
            if (post.httpCode in 200..299) {
                removeConsumedLines(spool, lines, batch.consumedLines)
                backoffMs.set(BACKOFF_MIN_MS)
                nextFlushAtElapsedMs.set(0)
                if (post.disableTelemetry) {
                    TransportLifecycleStore.setTelemetryRemoteOff(context, true)
                }
                Log.i(LOG_TAG, "telemetry flush ok http=${post.httpCode} disable=${post.disableTelemetry}")
            } else {
                scheduleBackoff("http_${post.httpCode}")
            }
        }.onFailure { error ->
            scheduleBackoff(errorKind(error))
            Log.w(LOG_TAG, "telemetry flush failed: ${safeErrorMessage(error)}")
        }
    }

    private fun appendQueueToSpool(context: Context) {
        val lines = mutableListOf<String>()
        while (true) {
            val event = queue.poll() ?: break
            lines += event.toJson().toString()
        }
        if (lines.isEmpty()) return
        val spool = spoolFile(context)
        val dir = spool.parentFile
        if (dir != null && !dir.exists() && !dir.mkdirs()) return
        spool.appendText(lines.joinToString(separator = "\n", postfix = "\n"), Charsets.UTF_8)
        trimSpool(spool)
    }

    private fun trimSpool(spool: File) {
        if (!spool.exists() || spool.length() <= SPOOL_MAX_BYTES) return
        val lines = spool.readLines(Charsets.UTF_8)
        val kept = ArrayDeque<String>()
        var totalBytes = 0
        for (line in lines.asReversed()) {
            val lineBytes = line.toByteArray(Charsets.UTF_8).size + 1
            if (totalBytes + lineBytes > SPOOL_MAX_BYTES && kept.isNotEmpty()) break
            kept.addFirst(line)
            totalBytes += lineBytes
        }
        writeLinesAtomically(spool, kept.toList())
    }

    private fun readBatch(lines: List<String>): Batch {
        val events = mutableListOf<QueuedEvent>()
        var consumed = 0
        for (line in lines) {
            consumed++
            val event = parseQueuedEvent(line)
            if (event != null) {
                events += event
            }
            if (events.size >= BATCH_LIMIT) break
        }
        return Batch(events = events, consumedLines = consumed)
    }

    private fun removeConsumedLines(spool: File, lines: List<String>, consumedLines: Int) {
        if (!spool.exists()) return
        val remaining = lines.drop(consumedLines.coerceAtLeast(0))
        writeLinesAtomically(spool, remaining)
    }

    private fun writeLinesAtomically(spool: File, lines: List<String>) {
        val tmp = File(spool.parentFile, "${spool.name}.tmp")
        if (lines.isEmpty()) {
            tmp.writeText("", Charsets.UTF_8)
        } else {
            tmp.writeText(lines.joinToString(separator = "\n", postfix = "\n"), Charsets.UTF_8)
        }
        if (!tmp.renameTo(spool)) {
            spool.writeText(tmp.readText(Charsets.UTF_8), Charsets.UTF_8)
            tmp.delete()
        }
    }

    private fun buildBody(context: Context, events: List<QueuedEvent>): JSONObject {
        val deviceID = telemetryDeviceID(context)
        return JSONObject()
            .put("v", 1)
            .put("did", deviceID)
            .put("boot", bootID)
            .put("seq", nextSequence(context))
            .put("sent_at", System.currentTimeMillis())
            .put("ver", BuildConfig.VERSION_NAME)
            .put("vc", BuildConfig.VERSION_CODE)
            .put("flv", BuildConfig.FLAVOR)
            .put(
                "events",
                JSONArray().also { array ->
                    events.forEach { array.put(snapshotToJson(snapshotFrom(context, it))) }
                },
            )
    }

    private fun snapshotFrom(context: Context, event: QueuedEvent): TelemetrySnapshot {
        val state = runCatching { TransportRuntime.state }.getOrDefault(TransportUiState())
        val auth = runCatching { TransportRuntime.auth }.getOrDefault(AuthUiState())
        val network = networkSnapshot(context)
        val fields = event.fields
        return TelemetrySnapshot(
            kind = event.kind,
            wallTimeMs = event.wallTimeMs,
            monoMs = event.monoMs,
            reason = fields.stringValue("rsn"),
            net = network.net,
            metered = network.metered,
            vpn = network.vpn,
            doze = doze(context),
            batteryOptimizationsIgnored = batteryOptimizationsIgnored(context),
            skewSeconds = fields.longValue("skew_s") ?: state.clockSkewSeconds,
            enrollment = fields.stringValue("enr").ifBlank { enrollmentStatus(auth) },
            provisionedAwg = fields.booleanValue("prov_awg") ?: auth.provisionedSOCKS.isNotBlank() ||
                auth.internalIP.isNotBlank() ||
                auth.endpoint.isNotBlank(),
            provisionedReality = fields.booleanValue("prov_rl") ?: (auth.reality?.isComplete() == true),
            provisionedReality2 = fields.booleanValue("prov_rl2") ?: (auth.reality2?.isComplete() == true),
            mode = fields.stringValue("mode").ifBlank { TransportRuntime.selectedTransport.name },
            route = fields.stringValue("route").ifBlank { state.activeTransport },
            activeRoute = fields.stringValue("active_route").ifBlank { state.activeTransport },
            healthy = fields.booleanValue("healthy") ?: state.handshakeEstablished,
            stable = fields.booleanValue("stable") ?: state.tunnelStable,
            lastExchangeSeconds = fields.longValue("last_exch_s") ?: state.lastExchangeAgeSeconds,
            backoffMs = fields.longValue("backoff_ms"),
            awgStarted = fields.booleanValue("awg_started"),
            awgStartError = fields.stringValue("awg_start_err"),
            awgHandshake = fields.booleanValue("awg_hs"),
            awgCarrying = fields.booleanValue("awg_carry"),
            awgRxBytes = fields.longValue("awg_rx"),
            awgTxBytes = fields.longValue("awg_tx"),
            awgFailures = fields.longValue("awg_fail"),
            awgDemotionLevel = fields.longValue("awg_demote"),
            awgRetrySeconds = fields.longValue("awg_retry_s"),
            awgRekey = fields.booleanValue("awg_rekey"),
            awgRuStarted = fields.booleanValue("awgru_started"),
            awgRuStartError = fields.stringValue("awgru_start_err"),
            awgRuHandshake = fields.booleanValue("awgru_hs"),
            awgRuCarrying = fields.booleanValue("awgru_carry"),
            awgRuRxBytes = fields.longValue("awgru_rx"),
            awgRuTxBytes = fields.longValue("awgru_tx"),
            awgRuFailures = fields.longValue("awgru_fail"),
            awgRuDemotionLevel = fields.longValue("awgru_demote"),
            awgRuRetrySeconds = fields.longValue("awgru_retry_s"),
            awgRuRekey = fields.booleanValue("awgru_rekey"),
            awgRuUdpDead = fields.booleanValue("awgru_udp_dead"),
            awgRuUdpDeadBackoffMs = fields.longValue("awgru_udp_dead_backoff_ms"),
            sessionClosed = fields.longValue("sess_closed"),
            routeCooldownSeconds = fields.longValue("route_cd_s"),
            routeCooldownLevel = fields.longValue("route_cd_level"),
            realityStarted = fields.booleanValue("rl_started"),
            realityAlive = fields.booleanValue("rl_alive"),
            realityTcpOk = fields.booleanValue("rl_tcp_ok"),
            realityCarry = fields.booleanValue("rl_carry"),
            realityTcpError = fields.stringValue("rl_tcp_err"),
            realityEgress = fields.stringValue("rl_egress"),
            realityRxBytes = fields.longValue("rl_rx"),
            realityTxBytes = fields.longValue("rl_tx"),
            reality2Started = fields.booleanValue("rl2_started"),
            reality2Alive = fields.booleanValue("rl2_alive"),
            reality2Carry = fields.booleanValue("rl2_carry"),
            reality2Error = fields.stringValue("rl2_err"),
            reality2RxBytes = fields.longValue("rl2_rx"),
            reality2TxBytes = fields.longValue("rl2_tx"),
            reality2Uuid8 = fields.stringValue("rl2_uid8").ifBlank {
                realityUuid8(TransportRuntime.appliedReality2Uuid)
            },
            errorWhere = fields.stringValue("err_where"),
            errorKind = fields.stringValue("err_kind"),
            errorMessage = fields.stringValue("err_msg"),
            batteryHintAction = fields.stringValue("action"),
            batteryHintManufacturer = fields.stringValue("mfr"),
            batteryHintOem = fields.stringValue("oem"),
            batteryHintRestricted = fields.booleanValue("restricted"),
        )
    }

    private fun snapshotToJson(snapshot: TelemetrySnapshot): JSONObject =
        JSONObject()
            .put("k", snapshot.kind)
            .put("t", snapshot.wallTimeMs)
            .put("mono", snapshot.monoMs)
            .putStringIfNotBlank("rsn", snapshot.reason)
            .put("net", snapshot.net)
            .put("metered", snapshot.metered)
            .put("vpn", snapshot.vpn)
            .put("doze", snapshot.doze)
            .put("batt_opt", snapshot.batteryOptimizationsIgnored)
            .putLongIfNotNull("skew_s", snapshot.skewSeconds)
            .put("enr", snapshot.enrollment)
            .put("prov_awg", snapshot.provisionedAwg)
            .put("prov_rl", snapshot.provisionedReality)
            .put("prov_rl2", snapshot.provisionedReality2)
            .putStringIfNotBlank("mode", snapshot.mode)
            .putStringIfNotBlank("route", snapshot.route)
            .putStringIfNotBlank("active_route", snapshot.activeRoute)
            .put("healthy", snapshot.healthy)
            .put("stable", snapshot.stable)
            .putNullableLong("last_exch_s", snapshot.lastExchangeSeconds)
            .putLongIfNotNull("backoff_ms", snapshot.backoffMs)
            .putBooleanIfNotNull("awg_started", snapshot.awgStarted)
            .putStringIfNotBlank("awg_start_err", snapshot.awgStartError)
            .putBooleanIfNotNull("awg_hs", snapshot.awgHandshake)
            .putBooleanIfNotNull("awg_carry", snapshot.awgCarrying)
            .putLongIfNotNull("awg_rx", snapshot.awgRxBytes)
            .putLongIfNotNull("awg_tx", snapshot.awgTxBytes)
            .putLongIfNotNull("awg_fail", snapshot.awgFailures)
            .putLongIfNotNull("awg_demote", snapshot.awgDemotionLevel)
            .putLongIfNotNull("awg_retry_s", snapshot.awgRetrySeconds)
            .putBooleanIfNotNull("awg_rekey", snapshot.awgRekey)
            .putBooleanIfNotNull("awgru_started", snapshot.awgRuStarted)
            .putStringIfNotBlank("awgru_start_err", snapshot.awgRuStartError)
            .putBooleanIfNotNull("awgru_hs", snapshot.awgRuHandshake)
            .putBooleanIfNotNull("awgru_carry", snapshot.awgRuCarrying)
            .putLongIfNotNull("awgru_rx", snapshot.awgRuRxBytes)
            .putLongIfNotNull("awgru_tx", snapshot.awgRuTxBytes)
            .putLongIfNotNull("awgru_fail", snapshot.awgRuFailures)
            .putLongIfNotNull("awgru_demote", snapshot.awgRuDemotionLevel)
            .putLongIfNotNull("awgru_retry_s", snapshot.awgRuRetrySeconds)
            .putBooleanIfNotNull("awgru_rekey", snapshot.awgRuRekey)
            .putBooleanIfNotNull("awgru_udp_dead", snapshot.awgRuUdpDead)
            .putLongIfNotNull("awgru_udp_dead_backoff_ms", snapshot.awgRuUdpDeadBackoffMs)
            .putLongIfNotNull("sess_closed", snapshot.sessionClosed)
            .putLongIfNotNull("route_cd_s", snapshot.routeCooldownSeconds)
            .putLongIfNotNull("route_cd_level", snapshot.routeCooldownLevel)
            .putBooleanIfNotNull("rl_started", snapshot.realityStarted)
            .putBooleanIfNotNull("rl_alive", snapshot.realityAlive)
            .putBooleanIfNotNull("rl_tcp_ok", snapshot.realityTcpOk)
            .putBooleanIfNotNull("rl_carry", snapshot.realityCarry)
            .putStringIfNotBlank("rl_tcp_err", snapshot.realityTcpError)
            .putStringIfNotBlank("rl_egress", snapshot.realityEgress)
            .putLongIfNotNull("rl_rx", snapshot.realityRxBytes)
            .putLongIfNotNull("rl_tx", snapshot.realityTxBytes)
            .putBooleanIfNotNull("rl2_started", snapshot.reality2Started)
            .putBooleanIfNotNull("rl2_alive", snapshot.reality2Alive)
            .putBooleanIfNotNull("rl2_carry", snapshot.reality2Carry)
            .putStringIfNotBlank("rl2_err", snapshot.reality2Error)
            .putLongIfNotNull("rl2_rx", snapshot.reality2RxBytes)
            .putLongIfNotNull("rl2_tx", snapshot.reality2TxBytes)
            .putStringIfNotBlank("rl2_uid8", snapshot.reality2Uuid8)
            .putStringIfNotBlank("err_where", snapshot.errorWhere)
            .putStringIfNotBlank("err_kind", snapshot.errorKind)
            .putStringIfNotBlank("err_msg", snapshot.errorMessage)
            .putStringIfNotBlank("action", snapshot.batteryHintAction)
            .putStringIfNotBlank("mfr", snapshot.batteryHintManufacturer)
            .putStringIfNotBlank("oem", snapshot.batteryHintOem)
            .putBooleanIfNotNull("restricted", snapshot.batteryHintRestricted)

    private fun signedTelemetryHeaders(context: Context, bodyBytes: ByteArray): Map<String, String> {
        val store = SecureIdentityStore(context)
        val publicKey = store.deviceIdentityPublicKey()
        val deviceID = telemetryDeviceIDForPublicKey(publicKey)
        val ts = System.currentTimeMillis().toString()
        val nonce = randomNonce()
        val bodyHash = sha256Hex(bodyBytes)
        val canonical = listOf(
            TELEMETRY_SIGNATURE_DOMAIN,
            deviceID,
            ts,
            nonce,
            bodyHash,
        ).joinToString("\n")
        val signature = store.signTelemetry(canonical)
        return linkedMapOf(
            "X-TW-Device" to deviceID,
            "X-TW-Pub" to publicKey,
            "X-TW-KeyType" to "ecdsa-p256-sha256",
            "X-TW-Ts" to ts,
            "X-TW-Nonce" to nonce,
            "X-TW-Sig" to signature,
        )
    }

    private fun post(context: Context, endpoint: URL, bodyBytes: ByteArray): PostResult {
        val headers = signedTelemetryHeaders(context, bodyBytes)
        val connection = endpoint.openConnection(Proxy.NO_PROXY) as HttpsURLConnection
        return try {
            connection.requestMethod = "POST"
            connection.connectTimeout = HTTPS_TIMEOUT_MS
            connection.readTimeout = HTTPS_TIMEOUT_MS
            connection.doOutput = true
            connection.setRequestProperty("Content-Type", "application/json")
            connection.setRequestProperty("Accept", "application/json")
            headers.forEach { (key, value) -> connection.setRequestProperty(key, value) }
            connection.outputStream.use { it.write(bodyBytes) }
            val code = connection.responseCode
            val headerDisable = connection.getHeaderField("X-TW-Disable").isDisableValue()
            val bodyDisable = if (code in 200..299 && code != 204) {
                runCatching {
                    val responseText = connection.inputStream.bufferedReader().use { it.readText().take(MAX_RESPONSE_CHARS) }
                    responseText.isNotBlank() && JSONObject(responseText).optBoolean("telemetry_off", false)
                }.getOrDefault(false)
            } else {
                false
            }
            PostResult(httpCode = code, disableTelemetry = headerDisable || bodyDisable)
        } finally {
            connection.disconnect()
        }
    }

    private fun postPublic(context: Context, bodyBytes: ByteArray): PostResult {
        val endpoint = URL(PUBLIC_TELEMETRY_URL)
        val port = if (endpoint.port > 0) endpoint.port else endpoint.defaultPort
        val path = endpoint.file.ifBlank { "/" }
        val headers = signedTelemetryHeaders(context, bodyBytes)
        openRouterSocks5Socket(endpoint.host, port, PUBLIC_HTTP_TIMEOUT_MS).use { socket ->
            socket.soTimeout = PUBLIC_HTTP_TIMEOUT_MS
            val request = buildString {
                append("POST ")
                append(path)
                append(" HTTP/1.1\r\n")
                append("Host: ")
                append(endpoint.host)
                if (endpoint.port > 0) append(":").append(endpoint.port)
                append("\r\n")
                append("Content-Type: application/json\r\n")
                append("Accept: application/json\r\n")
                append("Connection: close\r\n")
                append("Content-Length: ")
                append(bodyBytes.size)
                append("\r\n")
                headers.forEach { (key, value) ->
                    append(key).append(": ").append(value).append("\r\n")
                }
                append("\r\n")
            }.toByteArray(Charsets.UTF_8)
            val output = socket.getOutputStream()
            output.write(request)
            output.write(bodyBytes)
            output.flush()
            val input = socket.getInputStream()
            val header = readPublicHttpHeader(input)
            val statusLine = header.lineSequence().firstOrNull().orEmpty()
            val code = statusLine.split(' ').firstOrNull { it.toIntOrNull() != null }?.toIntOrNull() ?: 0
            val responseText = if (code in 200..299 && code != 204) {
                input.readBytes().toString(Charsets.UTF_8).take(MAX_RESPONSE_CHARS)
            } else {
                ""
            }
            val disable = header.lineSequence().any { line ->
                line.substringBefore(':').equals("X-TW-Disable", ignoreCase = true) &&
                    line.substringAfter(':', "").isDisableValue()
            } || responseText.isNotBlank() && runCatching {
                JSONObject(responseText).optBoolean("telemetry_off", false)
            }.getOrDefault(false)
            return PostResult(httpCode = code, disableTelemetry = disable)
        }
    }

    private fun openRouterSocks5Socket(targetHost: String, targetPort: Int, timeoutMs: Int): Socket {
        val socket = Socket()
        try {
            socket.soTimeout = timeoutMs
            socket.connect(InetSocketAddress(PUBLIC_ROUTER_HOST, PUBLIC_ROUTER_PORT), timeoutMs)
            val input = socket.getInputStream()
            val output = socket.getOutputStream()
            output.write(byteArrayOf(SOCKS_VERSION.toByte(), 0x01, SOCKS_NO_AUTH.toByte()))
            output.flush()
            if (readSocksByte(input) != SOCKS_VERSION || readSocksByte(input) != SOCKS_NO_AUTH) {
                error("bad router socks greeting")
            }
            val hostBytes = targetHost.toByteArray(Charsets.UTF_8)
            if (hostBytes.size > BYTE_MASK) error("router target host is too long")
            output.write(byteArrayOf(SOCKS_VERSION.toByte(), SOCKS_CONNECT.toByte(), 0x00, SOCKS_ATYP_DOMAIN.toByte(), hostBytes.size.toByte()))
            output.write(hostBytes)
            output.write(byteArrayOf(((targetPort ushr 8) and BYTE_MASK).toByte(), (targetPort and BYTE_MASK).toByte()))
            output.flush()
            if (readSocksByte(input) != SOCKS_VERSION) error("bad router socks response")
            val reply = readSocksByte(input)
            readSocksByte(input)
            val atyp = readSocksByte(input)
            if (reply != 0) error("router socks connect failed rep=$reply")
            val bindLength = when (atyp) {
                SOCKS_ATYP_IPV4 -> 4
                SOCKS_ATYP_DOMAIN -> readSocksByte(input)
                SOCKS_ATYP_IPV6 -> 16
                else -> error("bad router socks bind atyp=$atyp")
            }
            readSocksExact(input, bindLength + 2)
            return socket
        } catch (error: Throwable) {
            runCatching { socket.close() }
            throw error
        }
    }

    private fun readPublicHttpHeader(input: InputStream): String {
        val bytes = ArrayList<Byte>(1024)
        var state = 0
        while (bytes.size < PUBLIC_HTTP_HEADER_LIMIT_BYTES) {
            val value = input.read()
            if (value < 0) error("bad telemetry http response")
            bytes += value.toByte()
            state = when (state) {
                0 -> if (value == '\r'.code) 1 else 0
                1 -> if (value == '\n'.code) 2 else 0
                2 -> if (value == '\r'.code) 3 else 0
                3 -> if (value == '\n'.code) return bytes.toByteArray().toString(Charsets.ISO_8859_1) else 0
                else -> 0
            }
        }
        error("telemetry http header is too large")
    }

    private fun readSocksByte(input: InputStream): Int {
        val value = input.read()
        if (value < 0) throw EOFException()
        return value and BYTE_MASK
    }

    private fun readSocksExact(input: InputStream, size: Int) {
        var remaining = size
        val buffer = ByteArray(256)
        while (remaining > 0) {
            val read = input.read(buffer, 0, minOf(buffer.size, remaining))
            if (read < 0) throw EOFException()
            remaining -= read
        }
    }

    private fun scheduleBackoff(reason: String) {
        val delayMs = backoffMs.get()
        nextFlushAtElapsedMs.set(SystemClock.elapsedRealtime() + delayMs)
        backoffMs.set((delayMs * 2).coerceAtMost(BACKOFF_MAX_MS))
        Log.w(LOG_TAG, "telemetry backoff=${delayMs}ms reason=$reason")
    }

    private fun nextSequence(context: Context): Long {
        if (seq.get() == SEQ_UNINITIALIZED) {
            synchronized(seqLock) {
                if (seq.get() == SEQ_UNINITIALIZED) {
                    seq.set(
                        context.applicationContext
                            .getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                            .getLong(KEY_SEQ, 0L),
                    )
                }
            }
        }
        val next = seq.incrementAndGet()
        context.applicationContext
            .getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .edit()
            .putLong(KEY_SEQ, next)
            .apply()
        return next
    }

    private fun telemetryDeviceID(context: Context): String =
        telemetryDeviceIDForPublicKey(SecureIdentityStore(context).deviceIdentityPublicKey())

    internal fun telemetryDeviceIDForPublicKey(publicKey: String): String =
        "twpk_" + sha256Hex(publicKey.toByteArray(Charsets.UTF_8)).take(32)

    private fun networkSnapshot(context: Context): NetworkSnapshot =
        runCatching {
            val connectivity = context.getSystemService(ConnectivityManager::class.java)
            val active = connectivity.activeNetwork ?: return NetworkSnapshot("none", metered = false, vpn = false)
            val caps = connectivity.getNetworkCapabilities(active)
                ?: return NetworkSnapshot("unknown", metered = connectivity.isActiveNetworkMetered, vpn = false)
            val net = when {
                caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "wifi"
                caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "cell"
                caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> "ethernet"
                caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) -> "vpn"
                else -> "unknown"
            }
            NetworkSnapshot(
                net = net,
                metered = connectivity.isActiveNetworkMetered,
                vpn = caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN),
            )
        }.getOrDefault(NetworkSnapshot("unknown", metered = false, vpn = false))

    private fun doze(context: Context): Boolean =
        runCatching {
            Build.VERSION.SDK_INT >= 23 && context.getSystemService(PowerManager::class.java).isDeviceIdleMode
        }.getOrDefault(false)

    private fun batteryOptimizationsIgnored(context: Context): Boolean =
        runCatching {
            context.getSystemService(PowerManager::class.java).isIgnoringBatteryOptimizations(context.packageName)
        }.getOrDefault(false)

    private fun enrollmentStatus(auth: AuthUiState): String =
        when (auth.statusTextRes) {
            R.string.enrollment_status_starting -> "starting"
            R.string.enrollment_status_registering -> "registering"
            R.string.enrollment_status_pending -> "pending"
            R.string.enrollment_status_approved -> "approved"
            R.string.enrollment_status_blocked -> "blocked"
            R.string.enrollment_status_limit -> "limit"
            R.string.enrollment_status_error -> "error"
            else -> "error"
        }

    private fun sanitizeFields(fields: Array<out Pair<String, Any?>>): Map<String, Any?> {
        val out = linkedMapOf<String, Any?>()
        fields.forEach { (rawKey, rawValue) ->
            val key = rawKey.takeIf { it in ALLOWED_FIELD_KEYS } ?: return@forEach
            val value = when (key) {
                "err_msg", "awg_start_err", "awgru_start_err", "rl_tcp_err", "rl2_err" -> sanitizeErrorText(rawValue?.toString().orEmpty())
                "err_kind" -> rawValue?.toString()?.takeIf { it.isNotBlank() }?.let { normalizeErrorKind(it) }
                "rsn", "enr", "mode", "route", "active_route", "rl_egress", "err_where",
                "rl2_uid8", "action", "mfr", "oem" -> sanitizeToken(rawValue?.toString().orEmpty(), MAX_VALUE_CHARS)
                "skew_s", "last_exch_s", "backoff_ms", "awg_rx", "awg_tx", "awg_fail",
                "awg_demote", "awg_retry_s", "awgru_rx", "awgru_tx", "awgru_fail",
                "awgru_demote", "awgru_retry_s", "awgru_udp_dead_backoff_ms",
                "sess_closed", "route_cd_s", "route_cd_level",
                "rl_rx", "rl_tx", "rl2_rx", "rl2_tx" -> rawValue.asLong()
                else -> rawValue.asBoolean() ?: rawValue.asLong() ?: sanitizeToken(rawValue?.toString().orEmpty(), MAX_VALUE_CHARS)
            }
            if (value != null) {
                out[key] = value
            }
        }
        return out
    }

    private fun sanitizeToken(value: String, maxChars: Int): String =
        value
            .replace(Regex("[^A-Za-z0-9_./:-]"), "_")
            .take(maxChars)

    private fun sanitizeErrorText(value: String): String {
        if (value.isBlank()) return ""
        return value
            .replace(Regex("\\b\\d{1,3}(?:\\.\\d{1,3}){3}\\b"), "<ip>")
            .replace(Regex("\\b[0-9a-fA-F]{0,4}:[0-9a-fA-F:]{2,}\\b"), "<ip6>")
            .replace(Regex("\\b(?:[A-Za-z0-9-]+\\.)+[A-Za-z]{2,}(?::\\d+)?\\b"), "<host>")
            .replace(Regex("[0-9a-fA-F]{8}-[0-9a-fA-F-]{27,}"), "<uuid>")
            .replace(Regex("\\s+"), " ")
            .take(MAX_ERROR_CHARS)
    }

    private fun normalizeErrorKind(value: String?): String =
        when (value?.lowercase(Locale.ROOT)) {
            "timeout", "reset", "refused", "dns", "tls", "config", "process" -> value.lowercase(Locale.ROOT)
            else -> "unknown"
        }

    private fun randomNonce(): String {
        val bytes = ByteArray(NONCE_BYTES)
        secureRandom.nextBytes(bytes)
        return Base64.encodeToString(bytes, Base64.NO_WRAP)
    }

    private fun sha256Hex(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256")
            .digest(bytes)
            .joinToString("") { "%02x".format(it) }

    private fun spoolFile(context: Context): File =
        File(telemetryDir(context), SPOOL_FILE_NAME)

    private fun telemetryDir(context: Context): File =
        File(context.applicationContext.filesDir, "telemetry")

    private fun QueuedEvent.toJson(): JSONObject =
        JSONObject()
            .put("k", kind)
            .put("t", wallTimeMs)
            .put("mono", monoMs)
            .put(
                "f",
                JSONObject().also { root ->
                    fields.forEach { (key, value) -> root.putJsonValue(key, value) }
                },
            )

    private fun parseQueuedEvent(line: String): QueuedEvent? =
        runCatching {
            val root = JSONObject(line)
            val fieldsJson = root.optJSONObject("f") ?: JSONObject()
            val fields = linkedMapOf<String, Any?>()
            fieldsJson.keys().forEach { key ->
                if (key in ALLOWED_FIELD_KEYS) {
                    fields[key] = fieldsJson.get(key).takeUnless { it == JSONObject.NULL }
                }
            }
            QueuedEvent(
                kind = sanitizeToken(root.optString("k"), MAX_KIND_CHARS).ifBlank { "unknown" },
                wallTimeMs = root.optLong("t"),
                monoMs = root.optLong("mono"),
                fields = fields,
            )
        }.getOrNull()

    private fun JSONObject.putStringIfNotBlank(key: String, value: String): JSONObject {
        if (value.isNotBlank()) put(key, value)
        return this
    }

    private fun JSONObject.putLongIfNotNull(key: String, value: Long?): JSONObject {
        if (value != null) put(key, value)
        return this
    }

    private fun JSONObject.putBooleanIfNotNull(key: String, value: Boolean?): JSONObject {
        if (value != null) put(key, value)
        return this
    }

    private fun JSONObject.putNullableLong(key: String, value: Long?): JSONObject {
        put(key, value ?: JSONObject.NULL)
        return this
    }

    private fun JSONObject.putJsonValue(key: String, value: Any?) {
        when (value) {
            null -> put(key, JSONObject.NULL)
            is Boolean, is Int, is Long, is Double, is Float -> put(key, value)
            else -> put(key, value.toString())
        }
    }

    private fun Map<String, Any?>.stringValue(key: String): String =
        this[key]?.toString().orEmpty()

    private fun Map<String, Any?>.longValue(key: String): Long? =
        this[key].asLong()

    private fun Map<String, Any?>.booleanValue(key: String): Boolean? =
        this[key].asBoolean()

    private fun Any?.asLong(): Long? =
        when (this) {
            is Long -> this
            is Int -> toLong()
            is Number -> toLong()
            is String -> toLongOrNull()
            else -> null
        }

    private fun Any?.asBoolean(): Boolean? =
        when (this) {
            is Boolean -> this
            is String -> when (lowercase(Locale.ROOT)) {
                "true", "1", "yes" -> true
                "false", "0", "no" -> false
                else -> null
            }
            else -> null
        }

    private fun String?.isDisableValue(): Boolean =
        when (this?.trim()?.lowercase(Locale.ROOT)) {
            "1", "true", "yes", "on" -> true
            else -> false
        }

    private data class QueuedEvent(
        val kind: String,
        val wallTimeMs: Long,
        val monoMs: Long,
        val fields: Map<String, Any?>,
    )

    private data class TelemetrySnapshot(
        val kind: String,
        val wallTimeMs: Long,
        val monoMs: Long,
        val reason: String,
        val net: String,
        val metered: Boolean,
        val vpn: Boolean,
        val doze: Boolean,
        val batteryOptimizationsIgnored: Boolean,
        val skewSeconds: Long?,
        val enrollment: String,
        val provisionedAwg: Boolean,
        val provisionedReality: Boolean,
        val provisionedReality2: Boolean,
        val mode: String,
        val route: String,
        val activeRoute: String,
        val healthy: Boolean,
        val stable: Boolean,
        val lastExchangeSeconds: Long?,
        val backoffMs: Long?,
        val awgStarted: Boolean?,
        val awgStartError: String,
        val awgHandshake: Boolean?,
        val awgCarrying: Boolean?,
        val awgRxBytes: Long?,
        val awgTxBytes: Long?,
        val awgFailures: Long?,
        val awgDemotionLevel: Long?,
        val awgRetrySeconds: Long?,
        val awgRekey: Boolean?,
        val awgRuStarted: Boolean?,
        val awgRuStartError: String,
        val awgRuHandshake: Boolean?,
        val awgRuCarrying: Boolean?,
        val awgRuRxBytes: Long?,
        val awgRuTxBytes: Long?,
        val awgRuFailures: Long?,
        val awgRuDemotionLevel: Long?,
        val awgRuRetrySeconds: Long?,
        val awgRuRekey: Boolean?,
        val awgRuUdpDead: Boolean?,
        val awgRuUdpDeadBackoffMs: Long?,
        val sessionClosed: Long?,
        val routeCooldownSeconds: Long?,
        val routeCooldownLevel: Long?,
        val realityStarted: Boolean?,
        val realityAlive: Boolean?,
        val realityTcpOk: Boolean?,
        val realityCarry: Boolean?,
        val realityTcpError: String,
        val realityEgress: String,
        val realityRxBytes: Long?,
        val realityTxBytes: Long?,
        val reality2Started: Boolean?,
        val reality2Alive: Boolean?,
        val reality2Carry: Boolean?,
        val reality2Error: String,
        val reality2RxBytes: Long?,
        val reality2TxBytes: Long?,
        val reality2Uuid8: String,
        val errorWhere: String,
        val errorKind: String,
        val errorMessage: String,
        val batteryHintAction: String,
        val batteryHintManufacturer: String,
        val batteryHintOem: String,
        val batteryHintRestricted: Boolean?,
    )

    private data class NetworkSnapshot(val net: String, val metered: Boolean, val vpn: Boolean)

    private data class Batch(val events: List<QueuedEvent>, val consumedLines: Int)

    private data class PostResult(val httpCode: Int, val disableTelemetry: Boolean)

    private const val LOG_TAG = "TWTelemetry"
    private const val PREFS_NAME = "trafficwrapper_telemetry"
    private const val KEY_SEQ = "seq"
    private const val SPOOL_FILE_NAME = "spool.jsonl"
    private const val SPOOL_MAX_BYTES = 256 * 1024
    private const val QUEUE_CAP = 200
    private const val BATCH_LIMIT = 20
    private const val DEDUP_WINDOW_MS = 30_000L
    private const val BACKOFF_MIN_MS = 5_000L
    private const val BACKOFF_MAX_MS = 5 * 60 * 1000L
    private const val HTTPS_TIMEOUT_MS = 5_000
    private const val PUBLIC_HTTP_TIMEOUT_MS = 5_000
    private const val PUBLIC_HTTP_HEADER_LIMIT_BYTES = 64 * 1024
    private const val PUBLIC_TELEMETRY_URL = "http://awg-gw:8080/tw/telemetry"
    private const val PUBLIC_ROUTER_HOST = "127.0.0.1"
    private const val PUBLIC_ROUTER_PORT = 18080
    private const val SOCKS_VERSION = 0x05
    private const val SOCKS_NO_AUTH = 0x00
    private const val SOCKS_CONNECT = 0x01
    private const val SOCKS_ATYP_IPV4 = 0x01
    private const val SOCKS_ATYP_DOMAIN = 0x03
    private const val SOCKS_ATYP_IPV6 = 0x04
    private const val BYTE_MASK = 0xff
    private const val NONCE_BYTES = 16
    private const val MAX_RESPONSE_CHARS = 4096
    private const val MAX_KIND_CHARS = 48
    private const val MAX_VALUE_CHARS = 80
    private const val MAX_ERROR_CHARS = 160
    private const val SEQ_UNINITIALIZED = Long.MIN_VALUE
    private val BANNED_ENDPOINT_PORTS = setOf(18080, 18081, 18082, 18083)
    private val ALLOWED_FIELD_KEYS = setOf(
        "rsn",
        "skew_s",
        "enr",
        "prov_awg",
        "prov_rl",
        "prov_rl2",
        "mode",
        "route",
        "active_route",
        "healthy",
        "stable",
        "last_exch_s",
        "backoff_ms",
        "awg_started",
        "awg_start_err",
        "awg_hs",
        "awg_carry",
        "awg_rx",
        "awg_tx",
        "awg_fail",
        "awg_demote",
        "awg_retry_s",
        "awg_rekey",
        "awgru_started",
        "awgru_start_err",
        "awgru_hs",
        "awgru_carry",
        "awgru_rx",
        "awgru_tx",
        "awgru_fail",
        "awgru_demote",
        "awgru_retry_s",
        "awgru_rekey",
        "awgru_udp_dead",
        "awgru_udp_dead_backoff_ms",
        "sess_closed",
        "route_cd_s",
        "route_cd_level",
        "rl_started",
        "rl_alive",
        "rl_tcp_ok",
        "rl_carry",
        "rl_tcp_err",
        "rl_egress",
        "rl_rx",
        "rl_tx",
        "rl2_started",
        "rl2_alive",
        "rl2_carry",
        "rl2_err",
        "rl2_rx",
        "rl2_tx",
        "rl2_uid8",
        "err_where",
        "err_kind",
        "err_msg",
        "action",
        "mfr",
        "oem",
        "restricted",
    )
}
