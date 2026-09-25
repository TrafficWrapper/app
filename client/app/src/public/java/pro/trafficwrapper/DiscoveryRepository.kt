package pro.trafficwrapper

import android.content.Context
import android.os.SystemClock
import android.util.Log
import okhttp3.ConnectionPool
import okhttp3.Dispatcher
import okhttp3.OkHttpClient
import okhttp3.Request
import org.json.JSONArray
import org.json.JSONObject
import pro.trafficwrapper.go.transport.Transport
import java.net.Proxy
import java.time.Instant
import java.time.ZonedDateTime
import java.time.format.DateTimeFormatter
import java.util.concurrent.TimeUnit

data class DiscoverySink(
    val name: String,
    val baseUrl: String,
    val socksListen: String = "",
    val pointerUrl: String = "",
)

data class DiscoveryRefreshResult(
    val applied: Boolean,
    val seq: Long = 0,
    val sinkName: String = "",
)

class DiscoveryRepository(private val context: Context) {
    private val appContext = context.applicationContext

    fun maybeRefresh(
        socksListen: String,
        force: Boolean = false,
    ): DiscoveryRefreshResult? {
        if (!TransportLifecycleStore.discoverySubscriptionEnabled(appContext) && !force) return null
        val store = SecureIdentityStore(appContext)
        val stored = store.readPublicPlatformState()
        if (stored.clientBundleJson.isBlank() || stored.configPubkeyPin.isBlank()) return null
        val config = PublicPlatformConfigParser.verifyAndParseClientConfig(
            envelopeRaw = stored.clientBundleJson,
            expectedPublicKey = stored.configPubkeyPin,
            maxSeenSeq = stored.maxSeenConfigSeq,
            nowMs = 0L,
        )
        // Fallback to the update key is safe only because updatePubkeyPin is never taken from an
        // unconfirmed external bootstrap once set (see externalBootstrapDecision in MainActivity).
        val publicKey = config.discoveryPubkey.ifBlank { stored.updatePubkeyPin }
        if (publicKey.isBlank()) return null
        val rendezvousState = store.readRendezvousState()
        val sinks = discoverySinks(stored, config, socksListen, rendezvousState)
        if (sinks.isEmpty()) return null
        val slots = ensureCoreConfig(stored, config, publicKey)
        val tunnelUp = discoveryTunnelUp(
            authorized = TransportRuntime.auth.authorized,
            handshakeEstablished = TransportRuntime.state.handshakeEstablished,
            socksListen = socksListen,
        )

        var lastError: Throwable? = null
        var tunnelSinks = 0
        var tunnelAnswered = false
        for (sink in sinks) {
            val tunnelSink = sink.socksListen.isNotBlank()
            if (!tunnelSink && !directDiscoveryAllowed(tunnelUp, tunnelSinks, tunnelAnswered)) {
                // X-M7: the tunnel works, so the control plane is not contacted off-tunnel.
                Log.i(TAG, "public discovery: tunnel is up, skipping direct sinks")
                break
            }
            val attempt = SinkAttempt()
            val result = runCatching { fetchAndApply(store, stored, publicKey, sink, slots, attempt) }
                .onFailure { error ->
                    lastError = error
                    Log.w(TAG, "public discovery failed via ${sink.name}", error)
                }
                .getOrNull()
            if (tunnelSink) {
                tunnelSinks++
                tunnelAnswered = tunnelAnswered || attempt.answered
            }
            if (result != null) {
                Log.i(TAG, "public discovery applied seq=${result.seq} via ${sink.name}")
                return result
            }
        }
        lastError?.let { throw it }
        return null
    }

    private fun fetchAndApply(
        store: SecureIdentityStore,
        stored: StoredPublicPlatformState,
        publicKey: String,
        sink: DiscoverySink,
        slots: PublicPlatformRouteSlots,
        attempt: SinkAttempt,
    ): DiscoveryRefreshResult {
        val jsonResponse = fetchDiscoveryJSON(sink, publicKey, attempt)
        val state = store.readRendezvousState()
        val request = discoveryApplyRequest(
            endpointsJson = jsonResponse.body,
            minisig = jsonResponse.minisig,
            publicKey = publicKey,
            maxSeenSeq = state.maxSeenRendezvousSeq,
            nowIso = Instant.ofEpochMilli(discoveryNowMs(jsonResponse.dateHeaderMs)).toString(),
            slots = slots,
        )
        val response = JSONObject(Transport.applyDiscoveredEndpoints(request.toString()))
        if (!response.optBoolean("ok", false)) {
            throw IllegalStateException(response.optString("error", "discovery apply failed"))
        }
        val seq = response.getLong("seq")
        val issuedAtMs = parseIssuedAt(jsonResponse.body)
        val trusted = trustedTime(issuedAtMs)
        store.recordVerifiedRendezvous(
            seq = seq,
            trustedWallTimeMs = trusted.first,
            trustedElapsedRealtimeMs = trusted.second,
            issuedAtMs = issuedAtMs,
            discoverySinks = signedNextSinks(jsonResponse.body),
            // Go core already validated expires_at; next_sinks expire together with the feed.
            discoverySinksExpiresAtMs = parseExpiresAt(jsonResponse.body),
        )
        // The core returns a REALITY entry only when it belongs to the slot's own worker (X-M6),
        // so another worker's egress never becomes this slot's expected egress.
        matchedRealityEgress(response, "reality")?.let { TransportRuntime.publicRealityEgressIp = it }
        matchedRealityEgress(response, "reality2")?.let { TransportRuntime.publicReality2EgressIp = it }
        val mergedSlots = response.optJSONArray("awg_merged_slots")
        if (mergedSlots != null && mergedSlots.length() > 0) {
            // Go core already installed the merged AWG config(s) in pendingProvision.
            // Keep stored client-config unchanged; discovery is additive runtime state.
            Log.i(TAG, "public discovery merged awg slots=$mergedSlots device=${stored.deviceID}")
        }
        return DiscoveryRefreshResult(applied = true, seq = seq, sinkName = sink.name)
    }

    private fun ensureCoreConfig(
        stored: StoredPublicPlatformState,
        config: PublicClientConfig,
        rendezvousPublicKey: String,
    ): PublicPlatformRouteSlots {
        val credentials = stored.toPublicPlatformCredentials()
        val slots = PublicPlatformConfigParser.routeSlots(config, stored.deviceID, credentials)
        val applyRequest = publicCoreApplyRequest(
            stored = stored,
            config = config,
            slots = slots,
            socksListen = AWG_SOCKS_LISTEN,
            awgRuSocksListen = AWG_RU_SOCKS_LISTEN,
            mtu = DEFAULT_MTU,
            rendezvousPublicKey = rendezvousPublicKey,
        )
        val response = JSONObject(Transport.applyPublicPlatformConfig(applyRequest.toString()))
        if (!response.optBoolean("ok", false)) {
            throw IllegalStateException(response.optString("error", "public core config restore failed"))
        }
        return slots
    }

    /** Whether a sink returned any HTTP response (the path to it works). */
    private class SinkAttempt {
        var answered = false
    }

    private fun fetchString(sink: DiscoverySink, fileName: String, attempt: SinkAttempt): FetchResponse {
        val url = sink.baseUrl.trimEnd('/') + "/" + fileName
        return fetchURL(sink, url, attempt)
    }

    private fun fetchURL(sink: DiscoverySink, url: String, attempt: SinkAttempt): FetchResponse {
        if (sink.socksListen.isBlank() && !url.startsWith(HTTPS_PREFIX, ignoreCase = true)) {
            throw IllegalArgumentException("direct discovery sink must be https")
        }
        val request = Request.Builder()
            .url(url)
            .get()
            .header("Cache-Control", "no-store")
            .build()
        clientFor(sink.socksListen).newCall(request).execute().use { response ->
            attempt.answered = true
            if (!response.isSuccessful) {
                throw IllegalStateException("discovery ${response.code}")
            }
            val body = response.body
            if (body.contentLength() > MAX_DISCOVERY_BODY_BYTES) {
                throw IllegalStateException("discovery response too large")
            }
            val source = body.source()
            if (source.request(MAX_DISCOVERY_BODY_BYTES + 1)) {
                throw IllegalStateException("discovery response too large")
            }
            return FetchResponse(
                body = source.buffer.readUtf8(),
                dateHeaderMs = parseHttpDate(response.header("Date")),
            )
        }
    }

    private fun fetchDiscoveryJSON(sink: DiscoverySink, publicKey: String, attempt: SinkAttempt): DiscoveryPayload {
        if (sink.pointerUrl.isBlank()) {
            val json = fetchString(sink, ENDPOINTS_JSON, attempt)
            return DiscoveryPayload(
                body = json.body,
                minisig = fetchString(sink, ENDPOINTS_MINISIG, attempt).body,
                dateHeaderMs = json.dateHeaderMs,
            )
        }
        val pointer = fetchURL(sink, sink.pointerUrl, attempt)
        val pointerSig = fetchURL(sink, sink.pointerUrl.trimEnd('/') + ".minisig", attempt).body
        if (!verifyMinisign(pointer.body, pointerSig, publicKey)) {
            throw IllegalStateException("rescue pointer signature invalid")
        }
        validateRescuePointer(pointer.body, pointer.dateHeaderMs)
        val pointerRoot = JSONObject(pointer.body)
        val endpointsURL = pointerRoot.optString("endpoints_url").trim()
        val minisigURL = pointerRoot.optString("minisig_url").trim()
        if (!endpointsURL.startsWith(HTTPS_PREFIX, ignoreCase = true) ||
            !minisigURL.startsWith(HTTPS_PREFIX, ignoreCase = true)
        ) {
            throw IllegalStateException("rescue pointer urls must be https")
        }
        val json = fetchURL(sink, endpointsURL, attempt)
        return DiscoveryPayload(
            body = json.body,
            minisig = fetchURL(sink, minisigURL, attempt).body,
            dateHeaderMs = json.dateHeaderMs ?: pointer.dateHeaderMs,
        )
    }

    private fun verifyMinisign(message: String, signature: String, publicKey: String): Boolean {
        val result = JSONObject(Transport.verifyMinisign(message, signature, publicKey))
        return result.optBoolean("ok", false)
    }

    private fun validateRescuePointer(body: String, dateHeaderMs: Long?) {
        val expires = JSONObject(body).optString("expires_at").trim()
        if (expires.isBlank()) return
        val expiresAtMs = runCatching { Instant.parse(expires).toEpochMilli() }.getOrNull()
            ?: throw IllegalStateException("rescue pointer expires_at invalid")
        if (discoveryNowMs(dateHeaderMs) >= expiresAtMs) {
            throw IllegalStateException("rescue pointer expired")
        }
    }

    private data class FetchResponse(
        val body: String,
        val dateHeaderMs: Long?,
    )

    private data class DiscoveryPayload(
        val body: String,
        val minisig: String,
        val dateHeaderMs: Long?,
    )

    private companion object {
        private const val TAG = "TWDiscovery"
        private const val ENDPOINTS_JSON = "endpoints.json"
        private const val ENDPOINTS_MINISIG = "endpoints.json.minisig"
        private const val HTTPS_PREFIX = "https://"
        private const val AWG_SOCKS_LISTEN = "127.0.0.1:18082"
        private const val AWG_RU_SOCKS_LISTEN = "127.0.0.1:18084"
        private const val DEFAULT_MTU = 1420
        // Signed feeds, pointers and signatures are a few KiB; matches the core's 256 KiB bundle cap.
        private const val MAX_DISCOVERY_BODY_BYTES = 256L * 1024

        private fun clientFor(socksListen: String): OkHttpClient {
            val dispatcher = Dispatcher().apply {
                maxRequests = 1
                maxRequestsPerHost = 1
            }
            val builder = OkHttpClient.Builder()
                .dispatcher(dispatcher)
                .connectionPool(ConnectionPool(1, 1, TimeUnit.MINUTES))
                .callTimeout(18, TimeUnit.SECONDS)
                .connectTimeout(6, TimeUnit.SECONDS)
                .readTimeout(8, TimeUnit.SECONDS)
            builder.proxy(Proxy.NO_PROXY)
            if (socksListen.isNotBlank()) {
                // The loopback SOCKS listeners require RFC 1929 auth with the in-process
                // credentials; java.net SOCKS proxies can only authenticate via the global
                // Authenticator, so tunnel through our own socket factory instead. Host names are
                // resolved by the tunnel (PlaceholderDns keeps them intact, no local DNS leak).
                builder
                    .socketFactory(LocalSocksSocketFactory.forListen(socksListen))
                    .dns(PlaceholderDns)
            }
            return builder.build()
        }
    }
}

/** The tunnel carries traffic: authorized, handshake established and a SOCKS listener known. */
internal fun discoveryTunnelUp(authorized: Boolean, handshakeEstablished: Boolean, socksListen: String): Boolean =
    authorized && handshakeEstablished && socksListen.isNotBlank()

/**
 * X-M7: direct (NO_PROXY) sinks, the orchestrator included, are used only when the tunnel is down,
 * or when it is up but every tunnel sink failed without any HTTP answer through it (the tunnel
 * path is actually broken). A tunnel sink that answered (even 404 from a worker that does not
 * serve the feed yet) proves the tunnel works, so the control plane is not contacted off-tunnel.
 */
internal fun directDiscoveryAllowed(tunnelUp: Boolean, tunnelSinksTried: Int, tunnelSinkAnswered: Boolean): Boolean =
    !tunnelUp || (tunnelSinksTried > 0 && !tunnelSinkAnswered)

/**
 * Transport.applyDiscoveredEndpoints request. reality_slot / reality2_slot identify the workers of
 * the REALITY slots so the core returns only their own entries (X-M6); a slot without a worker id
 * and egress is omitted.
 */
internal fun discoveryApplyRequest(
    endpointsJson: String,
    minisig: String,
    publicKey: String,
    maxSeenSeq: Long,
    nowIso: String,
    slots: PublicPlatformRouteSlots,
): JSONObject {
    val request = JSONObject()
        .put("endpoints_json", endpointsJson)
        .put("endpoints_json_minisig", minisig)
        .put("public_key", publicKey)
        .put("max_seen_seq", maxSeenSeq)
        .put("now", nowIso)
    discoverySlotIdentity(slots.realityWorkerId, slots.realityExpectedEgressIp)?.let {
        request.put("reality_slot", it)
    }
    discoverySlotIdentity(slots.reality2WorkerId, slots.reality2ExpectedEgressIp)?.let {
        request.put("reality2_slot", it)
    }
    return request
}

private fun discoverySlotIdentity(workerId: String, egressIp: String): JSONObject? {
    val worker = workerId.trim()
    val egress = egressIp.trim()
    if (worker.isEmpty() && egress.isEmpty()) return null
    return JSONObject().apply {
        if (worker.isNotEmpty()) put("worker_id", worker)
        if (egress.isNotEmpty()) put("egress_ip", egress)
    }
}

/** Egress of the REALITY entry the core matched to [slot] ("reality" / "reality2"), or null. */
internal fun matchedRealityEgress(response: JSONObject, slot: String): String? =
    response.optJSONObject(slot)?.optString("egress_ip")?.trim()?.takeIf { it.isNotEmpty() }

/**
 * Discovery sinks come only from operator-signed fields (APP-M20): the tunnel config_url of each
 * route, next_sinks of the last verified rendezvous feed and discovery_rescue_pointers of the
 * client bundle, plus the orchestrator itself. Worker-supplied route params such as
 * discovery_url(s) are ignored: a single worker must not point the fleet at direct (off-tunnel)
 * hosts. next_sinks and rescue pointers expire together with their signed container (APP-L25).
 */
internal fun discoverySinks(
    stored: StoredPublicPlatformState,
    config: PublicClientConfig,
    socksListen: String,
    rendezvousState: StoredRendezvousState = StoredRendezvousState(),
    nowMs: Long = discoveryNowMs(null),
): List<DiscoverySink> {
    val tunnelSinks = linkedMapOf<String, DiscoverySink>()
    val directSinks = linkedMapOf<String, DiscoverySink>()
    val tunnelSocks = socksListen.ifBlank { UPDATE_ROUTER_SOCKS_LISTEN }
    config.workers
        .flatMap { it.routes }
        .map { it.params }
        .forEachIndexed { index, params ->
            params.optString("config_url").trim().takeIf { it.isNotBlank() }?.let { raw ->
                normalizeDiscoveryUrl(raw)?.let { url ->
                    tunnelSinks.putIfAbsent(
                        "tunnel-config|$url",
                        DiscoverySink("route-config-$index", url, tunnelSocks),
                    )
                }
            }
        }
    if (signedContainerValid(rendezvousState.discoverySinksExpiresAtMs, nowMs)) {
        rendezvousState.discoverySinks.forEachIndexed { index, raw ->
            normalizeDiscoveryUrl(raw)?.let { url ->
                addDiscoverySink(tunnelSinks, directSinks, "signed-next-$index", url, tunnelSocks)
            }
        }
    }
    if (signedContainerValid(parseInstantMsOrZero(config.expiresAt), nowMs)) {
        config.discoveryRescuePointers.forEachIndexed { index, raw ->
            normalizeDiscoveryUrl(raw)?.takeIf { it.startsWith("https://", ignoreCase = true) }?.let { url ->
                directSinks.putIfAbsent("rescue|$url", DiscoverySink("rescue-pointer-$index", url, pointerUrl = url))
            }
        }
    }
    val bootstrapBase = runCatching {
        PublicPlatformConfigParser.parseBootstrap(stored.bootstrapRaw, nowMs = 0).orchestratorUrl
    }.getOrDefault("")
    discoveryBaseUrl(bootstrapBase)?.let {
        directSinks.putIfAbsent("direct|$it", DiscoverySink("orchestrator-direct", it))
    }
    return tunnelSinks.values.toList() + directSinks.values.toList()
}

/**
 * A pointer inherited from a signed container is usable until that container's expires_at.
 * 0 means the expiry is unknown (sinks persisted by an older app); those stay usable until the
 * next verified feed replaces them.
 */
internal fun signedContainerValid(expiresAtMs: Long, nowMs: Long): Boolean =
    expiresAtMs <= 0L || nowMs < expiresAtMs

private fun parseInstantMsOrZero(value: String): Long =
    runCatching { Instant.parse(value.trim()).toEpochMilli() }.getOrDefault(0L)

private fun addDiscoverySink(
    tunnelSinks: MutableMap<String, DiscoverySink>,
    directSinks: MutableMap<String, DiscoverySink>,
    name: String,
    url: String,
    tunnelSocks: String,
) {
    if (url.startsWith("https://", ignoreCase = true)) {
        directSinks.putIfAbsent("direct|$url", DiscoverySink(name, url))
    } else {
        tunnelSinks.putIfAbsent("tunnel|$url", DiscoverySink(name, url, tunnelSocks))
    }
}

internal fun signedNextSinks(bundleJSON: String): List<String> =
    runCatching {
        sanitizedDiscoverySinkUrls(JSONObject(bundleJSON).optJSONArray("next_sinks"))
    }.getOrDefault(emptyList())

internal fun sanitizedDiscoverySinkUrls(array: JSONArray?, maxItems: Int = 16): List<String> {
    if (array == null) return emptyList()
    val out = mutableListOf<String>()
    val seen = mutableSetOf<String>()
    for (index in 0 until array.length()) {
        val url = normalizeDiscoveryUrl(array.optString(index)) ?: continue
        if (seen.add(url)) {
            out += url
            if (out.size >= maxItems) break
        }
    }
    return out
}

private fun discoveryBaseUrl(base: String): String? =
    normalizeDiscoveryUrl(base.trim().trimEnd('/') + "/discovery")

private fun normalizeDiscoveryUrl(raw: String): String? {
    val value = raw.trim().trimEnd('/')
    if (value.isBlank()) return null
    if (!value.startsWith("https://", ignoreCase = true) && !value.startsWith("http://", ignoreCase = true)) {
        return null
    }
    return value
}

private fun parseHttpDate(value: String?): Long? =
    try {
        value?.let {
            ZonedDateTime.parse(it, DateTimeFormatter.RFC_1123_DATE_TIME)
                .toInstant()
                .toEpochMilli()
        }
    } catch (_: Throwable) {
        null
    }

private fun parseIssuedAt(endpointsJson: String): Long =
    Instant.parse(JSONObject(endpointsJson).getString("issued_at")).toEpochMilli()

private fun parseExpiresAt(endpointsJson: String): Long =
    Instant.parse(JSONObject(endpointsJson).getString("expires_at")).toEpochMilli()

private fun discoveryNowMs(httpsDateMs: Long?): Long =
    discoveryValidationNowMs(
        mirrorDateMs = httpsDateMs,
        localNowMs = runCatching { ClockDiagnostics.trustedTime().wallTimeMs }.getOrDefault(System.currentTimeMillis()),
    )

/**
 * Time used to validate discovery bundles / rescue pointers. The mirror's `Date` header is not
 * authenticated: a stale or replaying mirror could send an old Date to make an expired bundle look
 * fresh. Taking the max with the local (SNTP-backed when available) clock means the header can
 * only help when the device clock is behind, never rewind validation time. A forward-skewed Date
 * can at worst reject a bundle, which a hostile mirror could do anyway by withholding it.
 */
internal fun discoveryValidationNowMs(mirrorDateMs: Long?, localNowMs: Long): Long =
    maxOf(mirrorDateMs ?: 0L, localNowMs)

/**
 * Trusted time persisted after a verified rendezvous. Only signed data (issued_at) and the local
 * clock ratchet it forward; the unauthenticated mirror Date header must not be persisted.
 */
private fun trustedTime(issuedAtMs: Long): Pair<Long, Long> {
    val elapsed = SystemClock.elapsedRealtime()
    val trusted = runCatching { ClockDiagnostics.trustedTime().wallTimeMs }.getOrDefault(System.currentTimeMillis())
    return maxOf(trusted, issuedAtMs) to elapsed
}
