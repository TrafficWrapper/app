package pro.trafficwrapper

import org.json.JSONObject

enum class IpFamily(val wire: String) {
    V4("v4"),
    V6("v6"),
}

/** Address families usable on the current network (see AutoTransportService.networkIpFamilies). */
data class NetworkIpFamilies(val ipv4: Boolean = true, val ipv6: Boolean = false) {
    val v6Only: Boolean
        get() = ipv6 && !ipv4

    companion object {
        /** No IPv6: exactly the pre-IPv6 behaviour. */
        val DEFAULT = NetworkIpFamilies(ipv4 = true, ipv6 = false)
        val ALL = NetworkIpFamilies(ipv4 = true, ipv6 = true)
    }
}

/** One way to reach a REALITY slot: a profile/network/family/flow of the slot's worker. */
data class RealityRouteVariant(
    val key: String,
    val family: IpFamily,
    val config: RealityUiConfig,
) {
    companion object {
        fun single(config: RealityUiConfig): RealityRouteVariant =
            RealityRouteVariant(
                key = routeVariantKey("", REALITY_BASE_PROFILE, config.network, IpFamily.V4, config.flow),
                family = IpFamily.V4,
                config = config,
            )
    }
}

/** One address family of an AWG slot. */
data class AwgRouteVariant(
    val key: String,
    val family: IpFamily,
    val route: PublicRouteConfig,
) {
    companion object {
        fun single(route: PublicRouteConfig): AwgRouteVariant =
            AwgRouteVariant(
                key = routeVariantKey("", awgProfileName(route), "awg", IpFamily.V4, ""),
                family = IpFamily.V4,
                route = route,
            )
    }
}

internal fun routeVariantKey(
    workerId: String,
    profile: String,
    network: String,
    family: IpFamily,
    flow: String,
): String =
    listOf(workerId.trim(), profile.trim(), network.trim().lowercase(), family.wire, flow.trim())
        .joinToString("|")

private fun awgProfileName(route: PublicRouteConfig): String =
    route.params.optString("awg_profile").ifBlank { route.params.optString("profile") }.trim()

/** Strips brackets from "[addr]" and returns a bare IPv6 literal (or ""). */
internal fun bareIpv6Address(value: String): String =
    value.trim().removePrefix("[").substringBefore("]").trim()

object RouteVariants {
    const val XHTTP_DEFAULT_MODE = "stream-up"

    /**
     * Expands a primary REALITY route into its ordered variants:
     * primary route first, then TCP alternatives with a flow (Vision), TCP alternatives without a
     * flow and XHTTP alternatives (IPv4), then the same list over IPv6 for entries that publish
     * address_v6. Alternatives come from the worker's fallback routes (separate `routes` entries
     * with a `profile`) and from params.reality_profiles. Without any of them the result is exactly
     * one variant equal to the pre-variant behaviour.
     */
    fun expandRealityVariants(
        primary: PublicResolvedRoute,
        fallbacks: List<PublicRouteConfig>,
        credentials: PublicPlatformCredentials,
        families: NetworkIpFamilies = NetworkIpFamilies.ALL,
    ): List<RealityRouteVariant> {
        val workerId = primary.worker.workerId
        val route = primary.route
        val primaryConfig = PublicPlatformConfigParser.realityUiConfig(route.address, route.port, route.params, credentials)
        val primaryProfile = route.params.optString("profile").trim().ifBlank { REALITY_BASE_PROFILE }
        val entries = mutableListOf(
            RealityEntry(primaryProfile, primaryConfig, bareIpv6Address(route.params.optString("address_v6"))),
        )
        val alternatives = mutableListOf<RealityEntry>()
        fallbacks.forEach { fallback ->
            val config = PublicPlatformConfigParser.realityUiConfig(
                fallback.address,
                fallback.port,
                fallback.params,
                credentials,
            ).normalizedAlternative()
            alternatives += RealityEntry(
                profile = fallback.params.optString("profile").trim(),
                config = config,
                addressV6 = bareIpv6Address(fallback.params.optString("address_v6")),
            )
        }
        route.params.optJSONArray("reality_profiles")?.let { profiles ->
            for (index in 0 until profiles.length()) {
                val profile = profiles.optJSONObject(index) ?: continue
                profileEntry(route, profile, credentials)?.let { alternatives += it }
            }
        }
        entries += alternatives.sortedBy { entry ->
            when {
                entry.config.network.equals("xhttp", ignoreCase = true) -> 2
                entry.config.flow.isNotBlank() -> 0
                else -> 1
            }
        }
        val v4 = entries.map { entry ->
            RealityRouteVariant(
                key = routeVariantKey(workerId, entry.profile, entry.config.network, IpFamily.V4, entry.config.flow),
                family = IpFamily.V4,
                config = entry.config,
            )
        }
        val v6 = entries.filter { it.addressV6.isNotBlank() }.map { entry ->
            RealityRouteVariant(
                key = routeVariantKey(workerId, entry.profile, entry.config.network, IpFamily.V6, entry.config.flow),
                family = IpFamily.V6,
                config = entry.config.copy(address = entry.addressV6, ip = ""),
            )
        }
        val unique = (v4 + v6)
            .filter { it.config.isComplete() || it === v4.first() }
            .distinctBy { it.key }
        return orderForNetwork(unique, RealityRouteVariant::family, families)
    }

    /** AWG slot variants: the route as is (v4) and, when the worker publishes endpoint_v6, v6. */
    fun expandAwgVariants(
        resolved: PublicResolvedRoute,
        families: NetworkIpFamilies = NetworkIpFamilies.ALL,
    ): List<AwgRouteVariant> {
        val route = resolved.route
        val profile = awgProfileName(route)
        val v4 = AwgRouteVariant(
            key = routeVariantKey(resolved.worker.workerId, profile, "awg", IpFamily.V4, ""),
            family = IpFamily.V4,
            route = route,
        )
        val endpointV6 = route.params.optString("endpoint_v6").trim()
        val variants = if (endpointV6.isNotEmpty()) {
            listOf(
                v4,
                AwgRouteVariant(
                    key = routeVariantKey(resolved.worker.workerId, profile, "awg", IpFamily.V6, ""),
                    family = IpFamily.V6,
                    route = route,
                ),
            )
        } else {
            listOf(v4)
        }
        return orderForNetwork(variants, AwgRouteVariant::family, families)
    }

    /**
     * IPv6 variants are a fallback: dropped without IPv6, tried after IPv4 on a dual-stack network
     * and first on an IPv6-only one (IPv4 may still work through 464XLAT, so it stays listed).
     */
    fun <T> orderForNetwork(variants: List<T>, familyOf: (T) -> IpFamily, families: NetworkIpFamilies): List<T> {
        val v4 = variants.filter { familyOf(it) == IpFamily.V4 }
        val v6 = variants.filter { familyOf(it) == IpFamily.V6 }
        return when {
            !families.ipv6 -> v4
            families.v6Only -> v6 + v4
            else -> v4 + v6
        }
    }

    private data class RealityEntry(
        val profile: String,
        val config: RealityUiConfig,
        val addressV6: String,
    )

    /** params.reality_profiles[] entry (worker selfdescribe format) on top of the primary params. */
    private fun profileEntry(
        primary: PublicRouteConfig,
        profile: JSONObject,
        credentials: PublicPlatformCredentials,
    ): RealityEntry? {
        val name = profile.optString("name").trim()
        val port = profile.optInt("port", 0)
        if (port <= 0) return null
        val network = profile.optString("network").trim().lowercase().ifBlank { "tcp" }
        val params = JSONObject(primary.params.toString())
        // Flat xhttp_* keys of the primary route must not leak into the alternative either.
        (listOf("xhttp", "flow", "flows", "reality_profiles", "address_v6", "profile", "vision") + FLAT_XHTTP_KEYS)
            .forEach { params.remove(it) }
        params.put("network", network)
        params.put("flow", "")
        profile.optJSONArray("flows")?.let { flows ->
            params.put("vision", (0 until flows.length()).any { flows.optString(it).trim() == REALITY_FLOW_VISION })
        }
        profile.optString("server_name").trim().takeIf { it.isNotEmpty() }?.let {
            params.put("server_name", it).put("serverName", it)
        }
        profile.optString("public_key").trim().takeIf { it.isNotEmpty() }?.let {
            params.put("public_key", it).put("publicKey", it)
        }
        profile.optString("short_id").trim().takeIf { it.isNotEmpty() }?.let {
            params.put("short_id", it).put("shortId", it)
        }
        if (network == "xhttp") {
            val xhttp = profile.optJSONObject("xhttp") ?: JSONObject()
            val nested = JSONObject()
                .put("path", xhttp.optString("path").trim())
                .put("mode", xhttp.optString("mode").trim())
            // X-L11: the worker's XHTTP inbound checks Host; the orchestrator sends it only when it
            // differs from server_name, so it has to reach the outbound.
            xhttp.optString("host").trim().takeIf { it.isNotEmpty() }?.let { nested.put("host", it) }
            params.put("xhttp", nested)
        }
        val address = profile.optString("address").trim().ifBlank { primary.address }
        val config = PublicPlatformConfigParser.realityUiConfig(address, port, params, credentials)
            .normalizedAlternative()
        return RealityEntry(
            profile = name.ifBlank { "$network-$port" },
            config = config,
            addressV6 = bareIpv6Address(profile.optString("address_v6")),
        )
    }

    private fun RealityUiConfig.normalizedAlternative(): RealityUiConfig =
        if (network.equals("xhttp", ignoreCase = true)) {
            // A non-empty xhttp host is kept (X-L11); an empty one stays empty.
            copy(xhttpMode = xhttpMode.ifBlank { XHTTP_DEFAULT_MODE })
        } else {
            this
        }

    private val FLAT_XHTTP_KEYS = listOf(
        "xhttp_host", "xhttpHost", "xhttp_path", "xhttpPath",
        "xhttp_mode", "xhttpMode", "xhttp_extra", "xhttpExtra",
    )
}

/**
 * Walks the variants of one slot. The current variant is kept while it works; after
 * [failuresBeforeAdvance] consecutive failed probes, or [readyTimeoutMs] without a successful one,
 * the cursor moves to the next variant (wrapping around). A remembered key that is not in the list
 * is ignored.
 */
class VariantCursor<T>(
    val variants: List<T>,
    private val keyOf: (T) -> String,
    rememberedKey: String? = null,
    private val failuresBeforeAdvance: Int = VARIANT_FAILURES_BEFORE_ADVANCE,
    private val readyTimeoutMs: Long = VARIANT_READY_TIMEOUT_MS,
) {
    var index: Int = rememberedKey
        ?.let { key -> variants.indexOfFirst { keyOf(it) == key } }
        ?.takeIf { it >= 0 }
        ?: 0
        private set

    private var consecutiveFailures = 0
    private var unreadySinceMs = NOT_SET

    val current: T?
        get() = variants.getOrNull(index)

    val currentKey: String
        get() = current?.let(keyOf).orEmpty()

    val size: Int
        get() = variants.size

    /** Records a probe of the current variant; returns true when the cursor moved. */
    fun onProbe(healthy: Boolean, nowMs: Long): Boolean {
        if (healthy) {
            consecutiveFailures = 0
            unreadySinceMs = NOT_SET
            return false
        }
        consecutiveFailures++
        if (unreadySinceMs == NOT_SET) unreadySinceMs = nowMs
        if (variants.size <= 1) return false
        val timedOut = nowMs - unreadySinceMs >= readyTimeoutMs
        if (consecutiveFailures < failuresBeforeAdvance && !timedOut) return false
        advance()
        return true
    }

    /** Moves to the next variant (wrapping around); returns true when the cursor moved. */
    fun advance(): Boolean {
        if (variants.size <= 1) return false
        index = (index + 1) % variants.size
        consecutiveFailures = 0
        unreadySinceMs = NOT_SET
        return true
    }

    fun keys(): List<String> = variants.map(keyOf)

    private companion object {
        const val NOT_SET = Long.MIN_VALUE
    }
}

const val VARIANT_FAILURES_BEFORE_ADVANCE = 2
const val VARIANT_READY_TIMEOUT_MS = 30_000L

/**
 * Keeps a [VariantCursor] in sync with a slot whose variant list may change (config polls,
 * network changes): the cursor is rebuilt only when the list of keys changes, starting from the
 * current key when still present, else from [rememberedKey].
 */
class VariantSlot<T>(private val keyOf: (T) -> String) {
    var cursor: VariantCursor<T>? = null
        private set

    fun sync(variants: List<T>, rememberedKey: String?): VariantCursor<T>? {
        val existing = cursor
        val keys = variants.map(keyOf)
        if (existing != null && existing.keys() == keys) return existing
        if (variants.isEmpty()) {
            cursor = null
            return null
        }
        val startKey = existing?.currentKey?.takeIf { it in keys } ?: rememberedKey
        return VariantCursor(variants, keyOf, startKey).also { cursor = it }
    }

    /** Restarts from [rememberedKey] (network change). */
    fun reset(variants: List<T>, rememberedKey: String?): VariantCursor<T>? {
        cursor = null
        return sync(variants, rememberedKey)
    }
}

/** Telemetry form of a variant key without the worker id, e.g. "xhttp-8443/xhttp/v6/none". */
internal fun routeVariantTelemetryLabel(key: String): String {
    val parts = key.split("|")
    if (parts.size < 5) return key
    val flow = when (parts[4]) {
        "" -> "none"
        REALITY_FLOW_VISION -> "vision"
        else -> parts[4]
    }
    return listOf(parts[1].ifBlank { "-" }, parts[2], parts[3], flow).joinToString("/")
}

/**
 * Address families of a network from its LinkProperties: a family counts when the link has an
 * address of it (a global one for IPv6: not link-local, loopback or ULA) and a default route.
 */
internal fun networkIpFamiliesOf(
    linkAddresses: List<java.net.InetAddress>,
    defaultRouteFamilies: Set<IpFamily>,
): NetworkIpFamilies {
    val hasV4Address = linkAddresses.any { it is java.net.Inet4Address && !it.isLoopbackAddress }
    val hasGlobalV6Address = linkAddresses.any { address ->
        address is java.net.Inet6Address &&
            !address.isLinkLocalAddress &&
            !address.isLoopbackAddress &&
            !address.isSiteLocalAddress &&
            !address.isAnyLocalAddress &&
            (address.address[0].toInt() and 0xfe) != 0xfc
    }
    return NetworkIpFamilies(
        ipv4 = hasV4Address && IpFamily.V4 in defaultRouteFamilies,
        ipv6 = hasGlobalV6Address && IpFamily.V6 in defaultRouteFamilies,
    )
}
