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
import java.net.InetSocketAddress
import java.net.Proxy
import java.time.Instant
import java.time.ZonedDateTime
import java.time.format.DateTimeFormatter
import java.util.concurrent.TimeUnit

data class DiscoverySink(
    val name: String,
    val baseUrl: String,
    val socksListen: String = "",
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
        val publicKey = config.discoveryPubkey.ifBlank { stored.updatePubkeyPin }
        if (publicKey.isBlank()) return null
        val sinks = discoverySinks(stored, config, socksListen)
        if (sinks.isEmpty()) return null
        ensureCoreConfig(stored, config)

        var lastError: Throwable? = null
        for (sink in sinks) {
            val result = runCatching { fetchAndApply(store, stored, publicKey, sink) }
                .onFailure { error ->
                    lastError = error
                    Log.w(TAG, "public discovery failed via ${sink.name}", error)
                }
                .getOrNull()
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
    ): DiscoveryRefreshResult {
        val jsonResponse = fetchString(sink, ENDPOINTS_JSON)
        val minisig = fetchString(sink, ENDPOINTS_MINISIG).body
        val state = store.readRendezvousState()
        val request = JSONObject()
            .put("endpoints_json", jsonResponse.body)
            .put("endpoints_json_minisig", minisig)
            .put("public_key", publicKey)
            .put("max_seen_seq", state.maxSeenRendezvousSeq)
            .put("now", Instant.ofEpochMilli(discoveryNowMs(jsonResponse.dateHeaderMs)).toString())
        val response = JSONObject(Transport.applyDiscoveredEndpoints(request.toString()))
        if (!response.optBoolean("ok", false)) {
            throw IllegalStateException(response.optString("error", "discovery apply failed"))
        }
        val seq = response.getLong("seq")
        val issuedAtMs = parseIssuedAt(jsonResponse.body)
        val trusted = trustedTime(jsonResponse.dateHeaderMs, issuedAtMs)
        store.recordVerifiedRendezvous(
            seq = seq,
            trustedWallTimeMs = trusted.first,
            trustedElapsedRealtimeMs = trusted.second,
            issuedAtMs = issuedAtMs,
        )
        response.optJSONObject("reality")?.optString("egress_ip")?.takeIf { it.isNotBlank() }?.let {
            TransportRuntime.publicRealityEgressIp = it
        }
        val configJson = response.optString("config_json")
        if (configJson.isNotBlank()) {
            // Go core already installed the merged AWG config in pendingProvision.
            // Keep stored client-config unchanged; discovery is additive runtime state.
            Log.i(TAG, "public discovery merged awg config bytes=${configJson.length} device=${stored.deviceID}")
        }
        return DiscoveryRefreshResult(applied = true, seq = seq, sinkName = sink.name)
    }

    private fun ensureCoreConfig(stored: StoredPublicPlatformState, config: PublicClientConfig) {
        val credentials = PublicPlatformCredentials(
            deviceID = stored.deviceID,
            realityUUID = stored.realityUUID,
            internalIP = stored.internalIP,
            psk2 = stored.psk2,
            serverAWGPublic = stored.serverAWGPublic,
            awgPrivateKey = stored.awgPrivateKey,
            awgPublicKey = stored.awgPublicKey,
        )
        val slots = PublicPlatformConfigParser.routeSlots(config, stored.deviceID, credentials)
        val applyRequest = JSONObject()
            .put("awg_private_key", stored.awgPrivateKey)
            .put("internal_ip", stored.internalIP)
            .put("psk2", stored.psk2)
            .put("server_awg_public", stored.serverAWGPublic)
            .put("socks_listen", AWG_SOCKS_LISTEN)
            .put("awg_ru_socks_listen", AWG_RU_SOCKS_LISTEN)
            .put("mtu", DEFAULT_MTU)
            .put("dns_servers", JSONArray(config.dnsServers))
        slots.awgRu?.let { applyRequest.put("awg_ru", PublicPlatformConfigParser.awgRouteJson(it)) }
        slots.awg?.let { applyRequest.put("awg", PublicPlatformConfigParser.awgRouteJson(it)) }
        val response = JSONObject(Transport.applyPublicPlatformConfig(applyRequest.toString()))
        if (!response.optBoolean("ok", false)) {
            throw IllegalStateException(response.optString("error", "public core config restore failed"))
        }
    }

    private fun fetchString(sink: DiscoverySink, fileName: String): FetchResponse {
        val url = sink.baseUrl.trimEnd('/') + "/" + fileName
        if (sink.socksListen.isBlank() && !url.startsWith(HTTPS_PREFIX, ignoreCase = true)) {
            throw IllegalArgumentException("direct discovery sink must be https")
        }
        val request = Request.Builder()
            .url(url)
            .get()
            .header("Cache-Control", "no-store")
            .build()
        clientFor(sink.socksListen).newCall(request).execute().use { response ->
            if (!response.isSuccessful) {
                throw IllegalStateException("discovery ${response.code}")
            }
            return FetchResponse(
                body = response.body.string(),
                dateHeaderMs = parseHttpDate(response.header("Date")),
            )
        }
    }

    private data class FetchResponse(
        val body: String,
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
            if (socksListen.isBlank()) {
                builder.proxy(Proxy.NO_PROXY)
            } else {
                val host = socksListen.substringBefore(":", "127.0.0.1").ifBlank { "127.0.0.1" }
                val port = socksListen.substringAfterLast(":", "18080").toIntOrNull() ?: 18080
                builder.proxy(Proxy(Proxy.Type.SOCKS, InetSocketAddress(host, port)))
            }
            return builder.build()
        }
    }
}

internal fun discoverySinks(
    stored: StoredPublicPlatformState,
    config: PublicClientConfig,
    socksListen: String,
): List<DiscoverySink> {
    val tunnelSinks = linkedMapOf<String, DiscoverySink>()
    val directSinks = linkedMapOf<String, DiscoverySink>()
    val tunnelSocks = socksListen.ifBlank { UPDATE_ROUTER_SOCKS_LISTEN }
    config.workers
        .flatMap { it.routes }
        .map { it.params }
        .forEachIndexed { index, params ->
            collectDiscoveryUrls(params.optJSONArray("discovery_urls")).forEach { url ->
                addDiscoverySink(tunnelSinks, directSinks, "route-discovery-$index", url, tunnelSocks)
            }
            params.optString("discovery_url").trim().takeIf { it.isNotBlank() }?.let { raw ->
                normalizeDiscoveryUrl(raw)?.let { url ->
                    addDiscoverySink(tunnelSinks, directSinks, "route-discovery-$index", url, tunnelSocks)
                }
            }
            params.optString("config_url").trim().takeIf { it.isNotBlank() }?.let { raw ->
                normalizeDiscoveryUrl(raw)?.let { url ->
                    tunnelSinks.putIfAbsent(
                        "tunnel-config|$url",
                        DiscoverySink("route-config-$index", url, tunnelSocks),
                    )
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

private fun collectDiscoveryUrls(array: JSONArray?): List<String> {
    if (array == null) return emptyList()
    val out = mutableListOf<String>()
    for (index in 0 until array.length()) {
        normalizeDiscoveryUrl(array.optString(index))?.let(out::add)
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

private fun discoveryNowMs(httpsDateMs: Long?): Long =
    httpsDateMs ?: runCatching { ClockDiagnostics.trustedTime().wallTimeMs }.getOrDefault(System.currentTimeMillis())

private fun trustedTime(httpsDateMs: Long?, issuedAtMs: Long): Pair<Long, Long> {
    val elapsed = SystemClock.elapsedRealtime()
    val trusted = runCatching { ClockDiagnostics.trustedTime().wallTimeMs }.getOrDefault(System.currentTimeMillis())
    return maxOf(trusted, httpsDateMs ?: 0L, issuedAtMs) to elapsed
}
