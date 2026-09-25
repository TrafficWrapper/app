package pro.trafficwrapper

import org.json.JSONArray
import org.json.JSONObject
import pro.trafficwrapper.go.transport.Transport
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.time.Instant
import java.util.Base64
import kotlin.math.ln

data class PublicBootstrapConfig(
    val orchestratorUrl: String,
    val configPubkeyPin: String,
    val orchNoisePublic: String,
    val updatePubkey: String,
    val seedWorkers: List<String>,
    val bootstrapToken: String,
    val expiresAt: String,
    val limits: JSONObject?,
    /**
     * Optional orch_tls_spki_sha256: SHA-256 SPKI pins of the orchestrator TLS certificate
     * (current + spare). Used only for the first enrollment; empty = legacy behaviour.
     */
    val orchTlsSpkiSha256: List<String> = emptyList(),
)

/**
 * An expiry decided only by the device clock (bootstrap or client config) beyond the skew
 * tolerance: retryable, since a wrong clock is the usual cause (APP-L27).
 */
class PublicClockSkewException(message: String) : PublicConfigVerificationException(message)

/** Tolerance for device clock skew in bootstrap/config expiry checks. */
internal const val PUBLIC_CLOCK_SKEW_TOLERANCE_MS = 10 * 60_000L

data class PublicClientConfigEnvelope(
    val configJson: String,
    val minisig: String,
    val publicKey: String,
    val configSha256: String,
    val serverTime: String,
)

/**
 * REALITY uTLS fingerprint for this build: params.fingerprint_modern when the bundle offers it and
 * this build's derived version code reaches fingerprint_modern_min_version_code, otherwise
 * params.fingerprint ("chrome" by default).
 */
internal fun realityFingerprintFor(params: JSONObject, clientVersionCode: Long): String {
    val modern = params.optString("fingerprint_modern").trim()
    val threshold = params.opt("fingerprint_modern_min_version_code")
        .let { (it as? Number)?.toLong() ?: (it as? String)?.trim()?.toLongOrNull() }
    if (modern.isNotEmpty() && threshold != null && threshold > 0 && clientVersionCode >= threshold) {
        return modern
    }
    return params.optString("fingerprint", "chrome")
}

internal fun clampRealityFingerprint(value: String): String =
    when (value.trim().lowercase()) {
        "chrome",
        "firefox",
        "safari",
        "ios",
        "android",
        "edge",
        "360",
        "qq",
        "random",
        "randomized",
        -> value.trim().lowercase()
        else -> "chrome"
    }

data class PublicClientConfig(
    val schema: Int,
    val namespace: String,
    val seq: Long,
    val issuedAt: String,
    val expiresAt: String,
    val updatePubkey: String,
    val discoveryPubkey: String,
    val discoveryRescuePointers: List<String>,
    val dnsServers: List<String>,
    val limits: JSONObject?,
    val workers: List<PublicWorkerConfig>,
)

data class PublicWorkerConfig(
    val workerId: String,
    val label: String,
    val priority: Int,
    val weight: Int,
    val routes: List<PublicRouteConfig>,
)

data class PublicRouteConfig(
    val type: String,
    val enabled: Boolean,
    val address: String,
    val port: Int,
    val expectedEgressIp: String,
    val dialectId: String,
    val region: String = "",
    val params: JSONObject,
)

data class PublicPlatformCredentials(
    val deviceID: String,
    val realityUUID: String,
    val internalIP: String,
    val psk2: String,
    val serverAWGPublic: String,
    val awgPrivateKey: String,
    val awgPublicKey: String,
    /** reality_flow from the enroll response; only meaningful when [realityFlowKnown]. */
    val realityFlow: String = "",
    /** True when the enroll response carried reality_flow (even an empty one). */
    val realityFlowKnown: Boolean = false,
    /**
     * Names of the AWG profiles this device holds awg_profiles credentials for; null = unknown
     * (no filtering). A non-base profile outside this set is never used (X-M4).
     */
    val awgProfileNames: Set<String>? = null,
    /** Version gate code of this build (see [derivedClientVersionCode]), not the Android versionCode. */
    val clientVersionCode: Long = PUBLIC_CLIENT_DERIVED_VERSION_CODE,
    /** reality_flow_pending of the last enroll response (two-phase Vision switch). */
    val realityFlowPending: String = "",
    val realityFlowPendingKnown: Boolean = false,
)

internal fun StoredPublicPlatformState.toPublicPlatformCredentials(): PublicPlatformCredentials =
    PublicPlatformCredentials(
        deviceID = deviceID,
        realityUUID = realityUUID,
        internalIP = internalIP,
        psk2 = psk2,
        serverAWGPublic = serverAWGPublic,
        awgPrivateKey = awgPrivateKey,
        awgPublicKey = awgPublicKey,
        realityFlow = realityFlow,
        realityFlowKnown = realityFlowKnown,
        awgProfileNames = publicAwgProfileNames(awgProfilesJson),
        realityFlowPending = realityFlowPending,
        realityFlowPendingKnown = realityFlowPendingKnown,
    )

/** Worker AWG profile a route targets (awg_profile wins over profile); "" = base. */
internal fun awgRouteProfileName(route: PublicRouteConfig): String =
    route.params.optString("awg_profile").ifBlank { route.params.optString("profile") }.trim()

/** The worker's base AWG inbound, served with the top-level device credentials. */
internal fun isBaseAwgProfile(profile: String): Boolean = profile.isBlank() || profile.trim() == "awg"

/** A base profile always; another one only with this device's credentials for it (or when unknown). */
internal fun awgProfileUsable(profile: String, credentials: PublicPlatformCredentials): Boolean {
    if (isBaseAwgProfile(profile)) return true
    val known = credentials.awgProfileNames ?: return true
    return profile.trim() in known
}

/** Profiles with complete credentials (internal_ip and psk2) in an enroll awg_profiles object. */
internal fun publicAwgProfileNames(awgProfilesJson: String): Set<String> {
    val root = awgProfilesJson.trim().takeIf { it.isNotEmpty() }
        ?.let { runCatching { JSONObject(it) }.getOrNull() } ?: return emptySet()
    val out = linkedSetOf<String>()
    val keys = root.keys()
    while (keys.hasNext()) {
        val name = keys.next()
        val creds = root.optJSONObject(name) ?: continue
        if (creds.optString("internal_ip").isNotBlank() && creds.optString("psk2").isNotBlank()) {
            out += name.trim()
        }
    }
    return out
}

/**
 * Capabilities announced in the enroll request (client_capabilities). The orchestrator stores
 * them per device and derives the device's REALITY flow from "reality_vision".
 */
val PUBLIC_CLIENT_CAPABILITIES: List<String> = listOf(
    "reality_vision",
    "reality_profiles",
    "reality_short_id",
    "awg_dialect_wide",
    "ipv6_endpoints",
    "tunnel_dns",
    // Nested params.awg_profiles alternatives chosen by credentials and min_version_code (X-M4).
    "route_alternatives_v1",
    // Two-phase Vision switch: reality_flow_pending is confirmed with reality_flow_ack (X-L13).
    "reality_flow_ack",
)

/**
 * Version gate code of a versionName: major*10000 + minor*100 + patch ("0.1.31" -> 131). This is
 * the unit of min_version_code and fingerprint_modern_min_version_code, never the Android
 * versionCode. Suffixes after the numeric part are ignored; an unparsable name gives 0.
 */
internal fun derivedClientVersionCode(versionName: String): Long {
    val match = Regex("""^\s*v?(\d{1,4})\.(\d{1,2})(?:\.(\d{1,2}))?""").find(versionName) ?: return 0L
    val (major, minor, patch) = match.destructured
    return major.toLong() * 10_000L + minor.toLong() * 100L + (patch.toLongOrNull() ?: 0L)
}

val PUBLIC_CLIENT_DERIVED_VERSION_CODE: Long by lazy { derivedClientVersionCode(BuildConfig.VERSION_NAME) }

/**
 * Per-platform device hint sent instead of ANDROID_ID (APP-L19): HMAC-SHA256 keyed by the
 * platform's config_pubkey_pin, so two platforms cannot link the same device by it. Blank when
 * ANDROID_ID is unavailable.
 */
internal fun publicDeviceHint(androidId: String, configPubkeyPin: String): String {
    if (androidId.isBlank()) return ""
    val mac = javax.crypto.Mac.getInstance("HmacSHA256")
    mac.init(
        javax.crypto.spec.SecretKeySpec(
            "TrafficWrapper device hint v1\n${configPubkeyPin.trim()}".toByteArray(Charsets.UTF_8),
            "HmacSHA256",
        ),
    )
    return "h1_" + mac.doFinal(androidId.trim().toByteArray(Charsets.UTF_8))
        .joinToString("") { "%02x".format(it.toInt() and 0xff) }
        .take(32)
}

const val REALITY_FLOW_VISION = "xtls-rprx-vision"

/**
 * Flow for a REALITY outbound. XHTTP never carries a flow. When the enroll response told us the
 * device's flow (reality_flow), it is applied only where the inbound accepts Vision: routes marked
 * "vision": true, or - for bundles without the mark - TCP routes. Without a known device flow the
 * route's own params.flow is used exactly as before.
 */
internal fun resolveRealityFlow(
    network: String,
    deviceFlow: String,
    deviceFlowKnown: Boolean,
    paramsFlow: String,
    routeVision: Boolean? = null,
): String {
    val net = network.trim().lowercase()
    if (net == "xhttp") return ""
    if (!deviceFlowKnown) return paramsFlow.trim()
    if (deviceFlow.trim() != REALITY_FLOW_VISION) return ""
    val acceptsVision = routeVision ?: (net.isEmpty() || net == "tcp")
    return if (acceptsVision) REALITY_FLOW_VISION else ""
}

/** The route's "vision" mark (true/false), or null when the bundle predates it. */
internal fun realityRouteVision(params: JSONObject): Boolean? {
    if (!params.has("vision")) return null
    return when (val value = params.opt("vision")) {
        is Boolean -> value
        is String -> value.trim().equals("true", ignoreCase = true)
        is Number -> value.toInt() != 0
        else -> null
    }
}

/** Cohort slot of a device: uint32be(sha256(utf8(device_id))[0:4]) % size. */
internal fun realityCohortIndex(deviceId: String, size: Int): Int {
    if (size <= 0) return -1
    val hash = MessageDigest.getInstance("SHA-256").digest(deviceId.toByteArray(Charsets.UTF_8))
    val value = ((hash[0].toLong() and 0xff) shl 24) or
        ((hash[1].toLong() and 0xff) shl 16) or
        ((hash[2].toLong() and 0xff) shl 8) or
        (hash[3].toLong() and 0xff)
    return (value % size.toLong()).toInt()
}

/**
 * REALITY short id: the device's slot in params.cohort_short_ids (revoked slots are ""), falling
 * back to the route's short_id when the list is absent/empty, the device id is unknown or the
 * slot is blank.
 */
internal fun resolveRealityShortId(params: JSONObject, deviceId: String): String {
    val base = params.optString("shortId").ifBlank { params.optString("short_id") }
    val cohorts = params.optJSONArray("cohort_short_ids") ?: return base
    if (cohorts.length() == 0 || deviceId.isBlank()) return base
    val index = realityCohortIndex(deviceId, cohorts.length())
    val value = cohorts.opt(index)
    val cohort = if (value is String) value.trim() else ""
    return cohort.ifBlank { base }
}

/** A primary REALITY route has no profile (or the worker's base profile "reality"). */
internal fun isPrimaryRealityRoute(route: PublicRouteConfig): Boolean {
    val profile = route.params.optString("profile").trim()
    return profile.isEmpty() || profile.equals(REALITY_BASE_PROFILE, ignoreCase = true)
}

internal const val REALITY_BASE_PROFILE = "reality"

/** Process-wide AWG address family chosen per slot ("" = default v4, the pre-IPv6 request). */
object PublicAwgFamilyState {
    @Volatile
    var awgRu: String = ""

    @Volatile
    var awg: String = ""

    /** Key of the AWG_RU/AWG profile alternative in use ("" = the slot's primary route). */
    @Volatile
    var awgRuVariantKey: String = ""

    @Volatile
    var awgVariantKey: String = ""
}

/** Selection key of an AWG slot variant: "" for the primary route, else the variant key. */
internal fun awgVariantSelectionKey(variant: AwgRouteVariant?, primary: PublicRouteConfig?): String =
    if (variant == null || variant.route === primary) "" else variant.key

private fun selectedAwgRoute(
    primary: PublicRouteConfig?,
    variants: List<AwgRouteVariant>,
    selectionKey: String,
): PublicRouteConfig? {
    if (primary == null || selectionKey.isBlank()) return primary
    return variants.firstOrNull { it.key == selectionKey }?.route ?: primary
}

/**
 * The single builder of Transport.applyPublicPlatformConfig requests (activity, service and
 * discovery). awg_profiles is sent only when the enroll response carried it.
 */
internal fun publicCoreApplyRequest(
    stored: StoredPublicPlatformState,
    config: PublicClientConfig,
    slots: PublicPlatformRouteSlots,
    socksListen: String,
    awgRuSocksListen: String,
    mtu: Int = PUBLIC_DEFAULT_MTU,
    rendezvousPublicKey: String? = null,
    awgRuFamily: String = PublicAwgFamilyState.awgRu,
    awgFamily: String = PublicAwgFamilyState.awg,
    awgRuVariantKey: String = PublicAwgFamilyState.awgRuVariantKey,
    awgVariantKey: String = PublicAwgFamilyState.awgVariantKey,
): JSONObject {
    val request = JSONObject()
        .put("awg_private_key", stored.awgPrivateKey)
        .put("internal_ip", stored.internalIP)
        .put("psk2", stored.psk2)
        .put("server_awg_public", stored.serverAWGPublic)
        .put("socks_listen", socksListen)
        .put("awg_ru_socks_listen", awgRuSocksListen)
        .put("mtu", mtu)
        .put("dns_servers", JSONArray(config.dnsServers))
    if (rendezvousPublicKey != null) {
        // The core only verifies discovery bundles against a key pinned here from the
        // verified client config, never against the key sent with the bundle request.
        request.put("rendezvous_public_key", rendezvousPublicKey)
    }
    val awgProfiles = stored.awgProfilesJson.trim()
        .takeIf { it.isNotEmpty() }
        ?.let { runCatching { JSONObject(it) }.getOrNull() }
    if (awgProfiles != null && awgProfiles.length() > 0) {
        request.put("awg_profiles", awgProfiles)
    }
    selectedAwgRoute(slots.awgRu, slots.awgRuVariants, awgRuVariantKey)
        ?.let { request.put("awg_ru", publicAwgRouteRequest(it, awgRuFamily)) }
    selectedAwgRoute(slots.awg, slots.awgVariants, awgVariantKey)
        ?.let { request.put("awg", publicAwgRouteRequest(it, awgFamily)) }
    return request
}

private fun publicAwgRouteRequest(route: PublicRouteConfig, family: String): JSONObject {
    val json = PublicPlatformConfigParser.awgRouteJson(route)
    val normalized = family.trim().lowercase()
    if (normalized == IpFamily.V6.wire && route.params.optString("endpoint_v6").isNotBlank()) {
        json.put("ip_family", IpFamily.V6.wire)
    } else if (normalized == IpFamily.V4.wire) {
        json.put("ip_family", IpFamily.V4.wire)
    }
    return json
}

internal const val PUBLIC_DEFAULT_MTU = 1420

data class PublicResolvedRoute(
    val worker: PublicWorkerConfig,
    val route: PublicRouteConfig,
)

data class PublicPlatformRouteSlots(
    val awgRu: PublicRouteConfig? = null,
    val awg: PublicRouteConfig? = null,
    val reality2: RealityUiConfig? = null,
    val reality: RealityUiConfig? = null,
    val awgRuExpectedEgressIp: String = "",
    val awgExpectedEgressIp: String = "",
    val reality2ExpectedEgressIp: String = "",
    val realityExpectedEgressIp: String = "",
    val orderedRoutes: List<PublicResolvedRoute> = emptyList(),
    val routePriorities: Map<String, Int> = emptyMap(),
    val routeRegions: Map<String, String> = emptyMap(),
    /** Ordered alternatives of the REALITY slot; the first one is [reality]. */
    val realityVariants: List<RealityRouteVariant> = listOfNotNull(reality?.let { RealityRouteVariant.single(it) }),
    val reality2Variants: List<RealityRouteVariant> = listOfNotNull(reality2?.let { RealityRouteVariant.single(it) }),
    /** Address families of the AWG_RU/AWG slots; the first one is the plain (v4) route. */
    val awgRuVariants: List<AwgRouteVariant> = listOfNotNull(awgRu?.let { AwgRouteVariant.single(it) }),
    val awgVariants: List<AwgRouteVariant> = listOfNotNull(awg?.let { AwgRouteVariant.single(it) }),
) {
    fun hasUsableRoute(): Boolean =
        awgRu != null || awg != null || reality2?.isComplete() == true || reality?.isComplete() == true
}

open class PublicConfigVerificationException(message: String) : IllegalArgumentException(message)

interface PublicMinisignVerifier {
    fun verify(message: String, signature: String, publicKey: String): Boolean
}

object TransportPublicMinisignVerifier : PublicMinisignVerifier {
    override fun verify(message: String, signature: String, publicKey: String): Boolean {
        val result = JSONObject(Transport.verifyMinisign(message, signature, publicKey))
        return result.optBoolean("ok", false)
    }
}

object PublicPlatformConfigParser {
    fun parseBootstrap(raw: String, nowMs: Long = System.currentTimeMillis()): PublicBootstrapConfig {
        val json = decodePossiblyBase64Json(raw)
        val root = JSONObject(json)
        val expiresAt = root.getString(JSON_EXPIRES)
        if (expiredBeyondClockTolerance(parseInstantMs(expiresAt), nowMs)) {
            // Only the device clock says so: retryable, see PublicClockSkewException.
            throw PublicClockSkewException("bootstrap expired by device clock")
        }
        val seedWorkers = root.optJSONArray(JSON_SEED_WORKERS).toStringList()
        return PublicBootstrapConfig(
            orchestratorUrl = root.getString(JSON_ORCHESTRATOR_URL),
            configPubkeyPin = root.getString(JSON_CONFIG_PUBKEY_PIN),
            orchNoisePublic = root.getString(JSON_ORCH_NOISE_PUBLIC),
            updatePubkey = root.optString(JSON_UPDATE_PUBKEY),
            seedWorkers = seedWorkers,
            bootstrapToken = root.getString(JSON_BOOTSTRAP_TOKEN),
            expiresAt = expiresAt,
            limits = root.optJSONObject(JSON_LIMITS),
            orchTlsSpkiSha256 = root.optJSONArray(JSON_ORCH_TLS_SPKI_SHA256).toStringListLenient(),
        )
    }

    /** nowMs <= 0 disables the check (re-enrollment of an enrolled device, restore). */
    private fun expiredBeyondClockTolerance(expiresAtMs: Long, nowMs: Long): Boolean =
        nowMs > 0 && expiresAtMs <= nowMs - PUBLIC_CLOCK_SKEW_TOLERANCE_MS

    private fun JSONArray?.toStringListLenient(): List<String> =
        if (this == null) {
            emptyList()
        } else {
            (0 until length()).mapNotNull { index -> (opt(index) as? String)?.trim()?.takeIf { it.isNotEmpty() } }
        }

    fun verifyAndParseClientConfig(
        envelopeRaw: String,
        expectedPublicKey: String,
        maxSeenSeq: Long,
        verifier: PublicMinisignVerifier = TransportPublicMinisignVerifier,
        nowMs: Long = System.currentTimeMillis(),
    ): PublicClientConfig {
        val envelope = parseEnvelope(envelopeRaw, expectedPublicKey)
        if (envelope.publicKey != expectedPublicKey) {
            throw PublicConfigVerificationException("config public key mismatch")
        }
        if (!sha256(envelope.configJson).equals(envelope.configSha256, ignoreCase = true)) {
            throw PublicConfigVerificationException("config sha256 mismatch")
        }
        if (!verifier.verify(envelope.configJson, envelope.minisig, envelope.publicKey)) {
            throw PublicConfigVerificationException("config signature invalid")
        }
        val root = JSONObject(envelope.configJson)
        rejectForbiddenKeys(root)
        val config = parseClientConfig(root)
        if (config.schema != CLIENT_CONFIG_SCHEMA) {
            throw PublicConfigVerificationException("unsupported client config schema")
        }
        if (config.namespace != CLIENT_CONFIG_NAMESPACE) {
            throw PublicConfigVerificationException("unsupported client config namespace")
        }
        if (config.seq < maxSeenSeq) {
            throw PublicConfigVerificationException("client config rollback")
        }
        if (expiredBeyondClockTolerance(parseInstantMs(config.expiresAt), nowMs)) {
            throw PublicClockSkewException("client config expired by device clock")
        }
        return config
    }

    /**
     * Stable per-device worker order. The seed is deviceId+workerId only: it deliberately does not
     * include the config seq, so a re-issued bundle (new seq, same workers) does not reshuffle
     * every client onto different workers.
     */
    fun deterministicWorkerOrder(
        workers: List<PublicWorkerConfig>,
        deviceId: String,
    ): List<PublicWorkerConfig> =
        workers
            .filter { it.weight > 0 && it.routes.any(PublicRouteConfig::enabled) }
            .groupBy { it.priority }
            .toSortedMap()
            .values
            .flatMap { samePriority ->
                samePriority.sortedBy { worker ->
                    weightedRankKey("$deviceId:${worker.workerId}", worker.weight)
                }
            }

    fun deterministicRouteOrder(
        config: PublicClientConfig,
        deviceId: String,
    ): List<PublicResolvedRoute> =
        deterministicWorkerOrder(config.workers, deviceId)
            .flatMap { worker ->
                worker.routes
                    .filter { it.enabled }
                    .map { route -> PublicResolvedRoute(worker = worker, route = route) }
            }

    fun routeSlots(
        config: PublicClientConfig,
        deviceId: String,
        credentials: PublicPlatformCredentials,
    ): PublicPlatformRouteSlots {
        val ordered = deterministicRouteOrder(config, deviceId)
        val awgResolved = ordered
            .filter { it.route.type in AWG_ROUTE_TYPES && it.route.address.isNotBlank() && it.route.port > 0 }
            // A route on another AWG profile needs this device's credentials for that profile;
            // the base ones have no peer there (X-M4).
            .filter { awgProfileUsable(awgRouteProfileName(it.route), credentials) }
        val realityCandidates = ordered
            .filter { it.route.type in REALITY_ROUTE_TYPES && it.route.address.isNotBlank() && it.route.port > 0 }
        // Fallback profiles (xhttp, another port) never take a slot of their own: they only
        // extend the variants of their worker's primary route.
        val realityResolved = realityCandidates.filter { isPrimaryRealityRoute(it.route) }
        val primaryAwgResolved = awgResolved.getOrNull(0)
        val secondaryAwgResolved = awgResolved.getOrNull(1)
        val primaryRealityResolved = realityResolved.getOrNull(0)
        val secondaryRealityResolved = realityResolved.getOrNull(1)
        val primaryAwg = primaryAwgResolved?.route
        val secondaryAwg = secondaryAwgResolved?.route
        val primaryReality = primaryRealityResolved?.route
        val secondaryReality = secondaryRealityResolved?.route
        fun fallbacksOf(resolved: PublicResolvedRoute?): List<PublicRouteConfig> =
            if (resolved == null) {
                emptyList()
            } else {
                realityCandidates
                    .filter { it.worker.workerId == resolved.worker.workerId && !isPrimaryRealityRoute(it.route) }
                    .map(PublicResolvedRoute::route)
            }
        val realityVariants = primaryRealityResolved?.let {
            RouteVariants.expandRealityVariants(it, fallbacksOf(it), credentials)
        }.orEmpty()
        val reality2Variants = secondaryRealityResolved?.let {
            RouteVariants.expandRealityVariants(it, fallbacksOf(it), credentials)
        }.orEmpty()
        return PublicPlatformRouteSlots(
            awgRu = primaryAwg,
            awg = secondaryAwg,
            reality = realityVariants.firstOrNull()?.config,
            reality2 = reality2Variants.firstOrNull()?.config,
            awgRuExpectedEgressIp = primaryAwg?.expectedEgressIp.orEmpty(),
            awgExpectedEgressIp = secondaryAwg?.expectedEgressIp.orEmpty(),
            realityExpectedEgressIp = primaryReality?.expectedEgressIp.orEmpty(),
            reality2ExpectedEgressIp = secondaryReality?.expectedEgressIp.orEmpty(),
            orderedRoutes = ordered,
            routePriorities = publicRoutePriorities(
                ordered = ordered,
                awgRu = primaryAwg,
                awg = secondaryAwg,
                reality = primaryReality,
                reality2 = secondaryReality,
            ),
            routeRegions = publicRouteRegions(
                awgRu = primaryAwg,
                awg = secondaryAwg,
                reality = primaryReality,
                reality2 = secondaryReality,
            ),
            realityVariants = realityVariants,
            reality2Variants = reality2Variants,
            awgRuVariants = primaryAwgResolved?.let { RouteVariants.expandAwgVariants(it, credentials = credentials) }.orEmpty(),
            awgVariants = secondaryAwgResolved?.let { RouteVariants.expandAwgVariants(it, credentials = credentials) }.orEmpty(),
        )
    }

    /**
     * AWG profiles the bundle offers to this build (route-level profiles and nested
     * params.awg_profiles passing min_version_code) for which the device holds no credentials.
     * Non-empty means a re-enrollment could fetch them (X-M4). Empty when credentials are unknown.
     */
    fun missingAwgProfileCredentials(
        config: PublicClientConfig,
        credentials: PublicPlatformCredentials,
    ): Set<String> {
        val known = credentials.awgProfileNames ?: return emptySet()
        val missing = linkedSetOf<String>()
        config.workers.flatMap { it.routes }
            .filter { it.enabled && it.type in AWG_ROUTE_TYPES }
            .forEach { route ->
                val profile = awgRouteProfileName(route)
                if (!isBaseAwgProfile(profile) && profile !in known) missing += profile
                RouteVariants.nestedAwgProfiles(route).forEach { nested ->
                    if (nested.minVersionCode <= credentials.clientVersionCode && nested.profile !in known) {
                        missing += nested.profile
                    }
                }
            }
        return missing
    }

    fun awgRouteJson(route: PublicRouteConfig): JSONObject =
        JSONObject(route.params.toString())
            .put(JSON_TYPE, route.type)
            .put(JSON_ADDRESS, route.address)
            .put(JSON_PORT, route.port)
            .put(JSON_EGRESS_IP, route.expectedEgressIp)

    private fun publicRoutePriorities(
        ordered: List<PublicResolvedRoute>,
        awgRu: PublicRouteConfig?,
        awg: PublicRouteConfig?,
        reality2: PublicRouteConfig?,
        reality: PublicRouteConfig?,
    ): Map<String, Int> {
        val assignments = listOf(
            "AWG_RU" to awgRu,
            "REALITY" to reality,
            "AWG" to awg,
            "REALITY2" to reality2,
        )
            .mapNotNull { (slot, route) ->
                route ?: return@mapNotNull null
                val index = ordered.indexOfFirst { it.route === route }
                if (index < 0) null else slot to index
            }
            .sortedBy { it.second }
        return assignments
            .mapIndexed { rank, item -> item.first to rank }
            .toMap()
    }

    private fun publicRouteRegions(
        awgRu: PublicRouteConfig?,
        awg: PublicRouteConfig?,
        reality2: PublicRouteConfig?,
        reality: PublicRouteConfig?,
    ): Map<String, String> =
        listOf(
            "AWG_RU" to awgRu,
            "REALITY" to reality,
            "AWG" to awg,
            "REALITY2" to reality2,
        )
            .mapNotNull { (slot, route) ->
                val region = route?.region?.trim().orEmpty()
                if (region.isBlank()) null else slot to region
            }
            .toMap()

    private fun parseEnvelope(raw: String, expectedPublicKey: String): PublicClientConfigEnvelope {
        val root = JSONObject(raw)
        val configJson = root.getString(JSON_CONFIG_JSON)
        val minisig = if (root.has(JSON_CONFIG_JSON_MINISIG)) {
            root.optString(JSON_CONFIG_JSON_MINISIG)
        } else {
            root.getString(JSON_MINISIG)
        }
        return PublicClientConfigEnvelope(
            configJson = configJson,
            minisig = minisig,
            publicKey = root.optString(JSON_PUBLIC_KEY, expectedPublicKey),
            configSha256 = root.optString(JSON_CONFIG_SHA256, sha256(configJson)),
            serverTime = root.optString(JSON_SERVER_TIME),
        )
    }

    private fun parseClientConfig(root: JSONObject): PublicClientConfig =
        PublicClientConfig(
            schema = root.getInt(JSON_SCHEMA),
            namespace = root.getString(JSON_NS),
            seq = root.getLong(JSON_SEQ),
            issuedAt = root.getString(JSON_ISSUED_AT),
            expiresAt = root.optString(JSON_EXPIRES_AT, DEFAULT_CONFIG_EXPIRES_AT),
            updatePubkey = root.optString(JSON_UPDATE_PUBKEY),
            discoveryPubkey = root.optString(JSON_DISCOVERY_PUBKEY),
            discoveryRescuePointers = root.optJSONArray(JSON_DISCOVERY_RESCUE_POINTERS).toStringList(),
            dnsServers = root.optJSONArray(JSON_DNS_SERVERS).toStringList(),
            limits = root.optJSONObject(JSON_LIMITS),
            workers = root.getJSONArray(JSON_WORKERS).toWorkers(),
        )

    private fun JSONArray.toWorkers(): List<PublicWorkerConfig> =
        List(length()) { index ->
            val item = getJSONObject(index)
            val workerId = item.optString(JSON_WORKER_ID).ifBlank { item.getString(JSON_ID) }
            PublicWorkerConfig(
                workerId = workerId,
                label = item.optString(JSON_LABEL, workerId),
                priority = item.optInt(JSON_PRIORITY, 0),
                weight = item.optInt(JSON_WEIGHT, 100).coerceIn(0, 100),
                routes = item.optJSONArray(JSON_ROUTES).toRoutes(item),
            )
        }

    private fun JSONArray?.toRoutes(worker: JSONObject): List<PublicRouteConfig> =
        if (this == null) {
            emptyList()
        } else {
            List(length()) { index ->
                val value = get(index)
                if (value is JSONObject) {
                    val params = value.withMergedParams()
                    PublicRouteConfig(
                        type = value.getString(JSON_TYPE).lowercase(),
                        enabled = value.optBoolean(JSON_ENABLED, true),
                        address = value.getString(JSON_ADDRESS),
                        port = value.getInt(JSON_PORT),
                        expectedEgressIp = value.optString(
                            JSON_EGRESS_IP,
                            value.optString(
                                JSON_EXPECTED_EGRESS_IP,
                                worker.optString(JSON_EGRESS_IP, worker.optString(JSON_EXPECTED_EGRESS_IP)),
                            ),
                        ),
                        dialectId = value.optString(JSON_DIALECT_ID).ifBlank { params.optString(JSON_DIALECT_ID) },
                        region = value.optString(JSON_REGION).ifBlank { params.optString(JSON_REGION) }.trim(),
                        params = params,
                    )
                } else {
                    routeFromLegacyWorkerShape(worker, value.toString())
                }
            }
        }

    private fun routeFromLegacyWorkerShape(worker: JSONObject, type: String): PublicRouteConfig {
        val routeType = type.lowercase()
        val params = when (routeType) {
            "reality", "reality2" -> worker.getJSONObject(JSON_REALITY)
            "awg", "awgru", "awg_ru" -> worker.getJSONObject(JSON_AWG)
            else -> throw PublicConfigVerificationException("unsupported route type: $type")
        }
        val endpoint = params.optString(JSON_ENDPOINT)
        val endpointHost = endpoint.substringBefore(":")
        val endpointPort = endpoint.substringAfter(":", "").toIntOrNull()
        return PublicRouteConfig(
            type = routeType,
            enabled = true,
            address = params.optString(JSON_ADDRESS).ifBlank { endpointHost },
            port = params.optInt(JSON_PORT, endpointPort ?: 0),
            expectedEgressIp = worker.optString(JSON_EGRESS_IP, worker.getString(JSON_EXPECTED_EGRESS_IP)),
            dialectId = params.optString(JSON_DIALECT_ID),
            region = params.optString(JSON_REGION).trim(),
            params = params,
        )
    }

    /** REALITY outbound config for [address]:[port] described by route [params]. */
    internal fun realityUiConfig(
        address: String,
        port: Int,
        params: JSONObject,
        credentials: PublicPlatformCredentials,
    ): RealityUiConfig {
        val network = params.optString(JSON_REALITY_NETWORK, "tcp")
        return RealityUiConfig(
            transport = params.optString(JSON_REALITY_TRANSPORT, "REALITY"),
            address = address,
            ip = params.optString(JSON_REALITY_IP),
            port = port,
            uuid = credentials.realityUUID,
            email = credentials.deviceID,
            flow = resolveRealityFlow(
                network = network,
                deviceFlow = credentials.realityFlow,
                deviceFlowKnown = credentials.realityFlowKnown,
                paramsFlow = params.optString(JSON_REALITY_FLOW),
                routeVision = realityRouteVision(params),
            ),
            security = params.optString(JSON_REALITY_SECURITY, "reality"),
            network = network,
            serverName = params.optString(JSON_REALITY_SERVER_NAME).ifBlank {
                params.optString(JSON_REALITY_SERVER_NAME_SNAKE, "example.com")
            },
            publicKey = params.optString(JSON_REALITY_PUBLIC_KEY).ifBlank {
                params.optString(JSON_REALITY_PUBLIC_KEY_SNAKE)
            },
            shortId = resolveRealityShortId(params, credentials.deviceID),
            fingerprint = clampRealityFingerprint(realityFingerprintFor(params, credentials.clientVersionCode)),
            spiderX = params.optString(JSON_REALITY_SPIDER_X, "/"),
            dest = params.optString(JSON_REALITY_DEST),
            xhttpHost = params.xhttpString(JSON_REALITY_XHTTP_HOST, JSON_REALITY_XHTTP_HOST_SNAKE),
            xhttpPath = params.xhttpString(JSON_REALITY_XHTTP_PATH, JSON_REALITY_XHTTP_PATH_SNAKE),
            xhttpMode = params.xhttpString(JSON_REALITY_XHTTP_MODE, JSON_REALITY_XHTTP_MODE_SNAKE),
            xhttpExtraJson = params.xhttpObjectString(JSON_REALITY_XHTTP_EXTRA, JSON_REALITY_XHTTP_EXTRA_SNAKE),
        )
    }

    private fun JSONObject.xhttpString(camelKey: String, snakeKey: String): String {
        val xhttp = optJSONObject(JSON_REALITY_XHTTP)
        return xhttp?.optString(camelKey).orEmpty()
            .ifBlank { xhttp?.optString(snakeKey).orEmpty() }
            .ifBlank { optString("xhttp_$snakeKey") }
            .ifBlank { optString("xhttp${camelKey.replaceFirstChar { it.uppercaseChar() }}") }
            .trim()
    }

    private fun JSONObject.xhttpObjectString(camelKey: String, snakeKey: String): String {
        val xhttp = optJSONObject(JSON_REALITY_XHTTP)
        return xhttp?.optJSONObject(camelKey)?.toString().orEmpty()
            .ifBlank { xhttp?.optJSONObject(snakeKey)?.toString().orEmpty() }
            .ifBlank { optJSONObject("xhttp_$snakeKey")?.toString().orEmpty() }
            .ifBlank { optJSONObject("xhttp${camelKey.replaceFirstChar { it.uppercaseChar() }}")?.toString().orEmpty() }
            .trim()
    }

    private fun JSONObject.withMergedParams(): JSONObject {
        val merged = JSONObject(toString())
        val nested = optJSONObject(JSON_PARAMS) ?: return merged
        val keys = nested.keys()
        while (keys.hasNext()) {
            val key = keys.next()
            merged.put(key, nested.get(key))
        }
        return merged
    }

    private fun rejectForbiddenKeys(value: Any) {
        when (value) {
            is JSONObject -> {
                val keys = value.keys()
                while (keys.hasNext()) {
                    val key = keys.next()
                    if (key.lowercase().replace("-", "_") in FORBIDDEN_KEYS) {
                        throw PublicConfigVerificationException("forbidden config key: $key")
                    }
                    rejectForbiddenKeys(value.get(key))
                }
            }
            is JSONArray -> {
                for (index in 0 until value.length()) rejectForbiddenKeys(value.get(index))
            }
        }
    }

    private fun decodePossiblyBase64Json(raw: String): String {
        val trimmed = raw.trim()
        if (trimmed.startsWith("{")) return trimmed
        return runCatching {
            String(Base64.getDecoder().decode(trimmed), Charsets.UTF_8)
        }.getOrElse {
            throw PublicConfigVerificationException("bootstrap is not json/base64")
        }
    }

    private fun JSONArray?.toStringList(): List<String> =
        if (this == null) {
            emptyList()
        } else {
            List(length()) { index -> getString(index) }
        }

    private fun parseInstantMs(value: String): Long =
        try {
            Instant.parse(value).toEpochMilli()
        } catch (_: Throwable) {
            throw PublicConfigVerificationException("invalid instant")
        }

    private fun sha256(value: String): String =
        MessageDigest.getInstance("SHA-256")
            .digest(value.toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02x".format(it.toInt() and 0xff) }

    private fun weightedRankKey(seed: String, weight: Int): Double {
        val hash = MessageDigest.getInstance("SHA-256").digest(seed.toByteArray(Charsets.UTF_8))
        val positive = ByteBuffer.wrap(hash, 0, 8).long and Long.MAX_VALUE
        val uniform = ((positive ushr 10) + 1).toDouble() / ((1L shl 53).toDouble() + 1.0)
        return -ln(uniform) / weight.coerceAtLeast(1).toDouble()
    }

    private const val CLIENT_CONFIG_SCHEMA = 1
    private const val CLIENT_CONFIG_NAMESPACE = "client-config-v1"
    private const val JSON_ORCHESTRATOR_URL = "orchestrator_url"
    private const val JSON_CONFIG_PUBKEY_PIN = "config_pubkey_pin"
    private const val JSON_ORCH_NOISE_PUBLIC = "orch_noise_public"
    private const val JSON_UPDATE_PUBKEY = "update_pubkey"
    private const val JSON_DISCOVERY_PUBKEY = "discovery_pubkey"
    private const val JSON_DISCOVERY_RESCUE_POINTERS = "discovery_rescue_pointers"
    private const val JSON_DNS_SERVERS = "dns_servers"
    private const val JSON_SEED_WORKERS = "seed_workers"
    private const val JSON_BOOTSTRAP_TOKEN = "bootstrap_token"
    private const val JSON_LIMITS = "limits"
    private const val JSON_EXPIRES = "expires"
    private const val JSON_ORCH_TLS_SPKI_SHA256 = "orch_tls_spki_sha256"
    private const val JSON_CONFIG_JSON = "config_json"
    private const val JSON_CONFIG_JSON_MINISIG = "config_json_minisig"
    private const val JSON_MINISIG = "minisig"
    private const val JSON_PUBLIC_KEY = "public_key"
    private const val JSON_CONFIG_SHA256 = "config_sha256"
    private const val JSON_SERVER_TIME = "server_time"
    private const val JSON_SCHEMA = "schema"
    private const val JSON_NS = "ns"
    private const val JSON_SEQ = "seq"
    private const val JSON_ISSUED_AT = "issued_at"
    private const val JSON_EXPIRES_AT = "expires_at"
    private const val JSON_WORKERS = "workers"
    private const val JSON_ID = "id"
    private const val JSON_WORKER_ID = "worker_id"
    private const val JSON_LABEL = "label"
    private const val JSON_REGION = "region"
    private const val JSON_PRIORITY = "priority"
    private const val JSON_WEIGHT = "weight"
    private const val JSON_ROUTES = "routes"
    private const val JSON_TYPE = "type"
    private const val JSON_ENABLED = "enabled"
    private const val JSON_ADDRESS = "address"
    private const val JSON_ENDPOINT = "endpoint"
    private const val JSON_PORT = "port"
    private const val JSON_EGRESS_IP = "egress_ip"
    private const val JSON_EXPECTED_EGRESS_IP = "expected_egress_ip"
    private const val JSON_DIALECT_ID = "dialect_id"
    private const val JSON_PARAMS = "params"
    private const val JSON_REALITY = "reality"
    private const val JSON_AWG = "awg"
    private const val JSON_REALITY_TRANSPORT = "transport"
    private const val JSON_REALITY_IP = "ip"
    private const val JSON_REALITY_FLOW = "flow"
    private const val JSON_REALITY_SECURITY = "security"
    private const val JSON_REALITY_NETWORK = "network"
    private const val JSON_REALITY_SERVER_NAME = "serverName"
    private const val JSON_REALITY_SERVER_NAME_SNAKE = "server_name"
    private const val JSON_REALITY_PUBLIC_KEY = "publicKey"
    private const val JSON_REALITY_PUBLIC_KEY_SNAKE = "public_key"
    private const val JSON_REALITY_SHORT_ID = "shortId"
    private const val JSON_REALITY_SHORT_ID_SNAKE = "short_id"
    private const val JSON_REALITY_FINGERPRINT = "fingerprint"
    private const val JSON_REALITY_SPIDER_X = "spiderX"
    private const val JSON_REALITY_DEST = "dest"
    private const val JSON_REALITY_XHTTP = "xhttp"
    private const val JSON_REALITY_XHTTP_HOST = "host"
    private const val JSON_REALITY_XHTTP_HOST_SNAKE = "host"
    private const val JSON_REALITY_XHTTP_PATH = "path"
    private const val JSON_REALITY_XHTTP_PATH_SNAKE = "path"
    private const val JSON_REALITY_XHTTP_MODE = "mode"
    private const val JSON_REALITY_XHTTP_MODE_SNAKE = "mode"
    private const val JSON_REALITY_XHTTP_EXTRA = "extra"
    private const val JSON_REALITY_XHTTP_EXTRA_SNAKE = "extra"
    private const val DEFAULT_CONFIG_EXPIRES_AT = "9999-12-31T23:59:59Z"
    private val REALITY_ROUTE_TYPES = setOf("reality", "reality2")
    private val AWG_ROUTE_TYPES = setOf("awg", "awgru", "awg_ru")
    private val FORBIDDEN_KEYS = setOf("private_key", "psk2", "internal_ip", "server_private_key")
}

/**
 * Trusted fields of a bootstrap: everything that decides whom the client talks to and which keys
 * it trusts. Only the one-time token, expiry and advisory limits may differ for an external
 * bootstrap to be accepted without explicit user confirmation.
 */
internal fun publicBootstrapTrustedFieldsMatch(
    current: PublicBootstrapConfig,
    incoming: PublicBootstrapConfig,
): Boolean =
    current.orchestratorUrl == incoming.orchestratorUrl &&
        current.configPubkeyPin == incoming.configPubkeyPin &&
        current.orchNoisePublic == incoming.orchNoisePublic &&
        current.updatePubkey.trim() == incoming.updatePubkey.trim() &&
        current.seedWorkers.map { it.trim() }.toSet() == incoming.seedWorkers.map { it.trim() }.toSet()

/** An external bootstrap must not carry an update key that contradicts an already pinned one. */
internal fun updatePubkeyCompatibleWithPin(pinnedUpdatePubkey: String, incomingUpdatePubkey: String): Boolean {
    val pinned = pinnedUpdatePubkey.trim()
    val incoming = incomingUpdatePubkey.trim()
    return pinned.isEmpty() || incoming.isEmpty() || pinned == incoming
}

/**
 * Chooses the update_pubkey pin after enrollment:
 *  1. a key from the client config signed by the pinned config key always wins;
 *  2. otherwise an existing pin is kept - a bootstrap cannot replace it - unless the user switched
 *     to a different platform (different config_pubkey_pin, which always requires confirmation);
 *  3. only when nothing is pinned yet is the bootstrap's key used (trust on first use).
 */
internal fun resolveUpdatePubkeyPin(
    signedConfigUpdatePubkey: String,
    previous: StoredPublicPlatformState,
    bootstrap: PublicBootstrapConfig,
): String {
    val signed = signedConfigUpdatePubkey.trim()
    if (signed.isNotEmpty()) return signed
    val pinned = previous.updatePubkeyPin.trim()
    val samePlatform = previous.configPubkeyPin.isBlank() || previous.configPubkeyPin == bootstrap.configPubkeyPin
    if (pinned.isNotEmpty() && samePlatform) return pinned
    return bootstrap.updatePubkey.trim().ifEmpty { pinned }
}

/**
 * Rollback floor for a client config signed by [configPubkeyPin]: the stored maxSeenConfigSeq
 * only applies to the platform (config key) it was recorded for. A blank stored pin means no
 * platform yet (or legacy state) and keeps the stored floor.
 */
internal fun StoredPublicPlatformState.configSeqFloorFor(configPubkeyPin: String): Long {
    val stored = this.configPubkeyPin.trim()
    return if (stored.isEmpty() || stored == configPubkeyPin.trim()) maxSeenConfigSeq else 0L
}

/**
 * Rollback floor for an update manifest signed by [updatePubkeyPin]: maxSeenUpdateSeq only applies
 * to the update key recorded in maxSeenUpdateSeqPin (blank = legacy/unknown owner, keeps the floor).
 * After any change of the update key pin (platform switch, signed key rotation) checks start from 0.
 */
internal fun StoredPublicPlatformState.updateSeqFloorFor(updatePubkeyPin: String): Long {
    val owner = maxSeenUpdateSeqPin.trim()
    return if (owner.isEmpty() || owner == updatePubkeyPin.trim()) maxSeenUpdateSeq else 0L
}

/**
 * Merges freshly enrolled credentials into the current stored state inside
 * SecureIdentityStore.updatePublicPlatformState: monotonic counters and trusted time never go
 * backwards, and the update key pin is recomputed against the current state.
 */
internal fun mergeEnrolledPublicPlatformState(
    current: StoredPublicPlatformState,
    enrolled: StoredPublicPlatformState,
    configSeq: Long,
    signedConfigUpdatePubkey: String,
    bootstrap: PublicBootstrapConfig,
): StoredPublicPlatformState {
    // The rollback floor belongs to the config key it was seen under: a user-confirmed switch to
    // another platform (different config_pubkey_pin) starts from 0 instead of failing as a rollback.
    val configSeqFloor = current.configSeqFloorFor(enrolled.configPubkeyPin)
    if (configSeq < configSeqFloor) {
        throw PublicConfigVerificationException("client config rollback")
    }
    val updatePubkeyPin = resolveUpdatePubkeyPin(signedConfigUpdatePubkey, current, bootstrap)
    val keepCurrentTime = current.trustedWallTimeMs >= enrolled.trustedWallTimeMs
    return enrolled.copy(
        updatePubkeyPin = updatePubkeyPin,
        maxSeenConfigSeq = maxOf(configSeqFloor, enrolled.maxSeenConfigSeq, configSeq),
        maxSeenUpdateSeq = maxOf(
            current.updateSeqFloorFor(updatePubkeyPin),
            enrolled.updateSeqFloorFor(updatePubkeyPin),
        ),
        maxSeenUpdateSeqPin = updatePubkeyPin,
        trustedWallTimeMs = if (keepCurrentTime) current.trustedWallTimeMs else enrolled.trustedWallTimeMs,
        trustedElapsedRealtimeMs = if (keepCurrentTime) {
            current.trustedElapsedRealtimeMs
        } else {
            enrolled.trustedElapsedRealtimeMs
        },
    )
}
