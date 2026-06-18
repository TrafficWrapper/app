package pro.netcloud.trafficwrapper

import org.json.JSONArray
import org.json.JSONObject
import pro.netcloud.trafficwrapper.go.transport.Transport
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
)

data class PublicClientConfigEnvelope(
    val configJson: String,
    val minisig: String,
    val publicKey: String,
    val configSha256: String,
    val serverTime: String,
)

data class PublicClientConfig(
    val schema: Int,
    val namespace: String,
    val seq: Long,
    val issuedAt: String,
    val expiresAt: String,
    val updatePubkey: String,
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
)

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
) {
    fun hasUsableRoute(): Boolean =
        awgRu != null || awg != null || reality2?.isComplete() == true || reality?.isComplete() == true
}

class PublicConfigVerificationException(message: String) : IllegalArgumentException(message)

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
        if (parseInstantMs(expiresAt) <= nowMs) {
            throw PublicConfigVerificationException("bootstrap expired")
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
        )
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
        if (parseInstantMs(config.expiresAt) <= nowMs) {
            throw PublicConfigVerificationException("client config expired")
        }
        return config
    }

    fun deterministicWorkerOrder(
        workers: List<PublicWorkerConfig>,
        deviceId: String,
        configSeq: Long,
    ): List<PublicWorkerConfig> =
        workers
            .filter { it.weight > 0 && it.routes.any(PublicRouteConfig::enabled) }
            .groupBy { it.priority }
            .toSortedMap()
            .values
            .flatMap { samePriority ->
                samePriority.sortedBy { worker ->
                    weightedRankKey("$deviceId:$configSeq:${worker.workerId}", worker.weight)
                }
            }

    fun deterministicRouteOrder(
        config: PublicClientConfig,
        deviceId: String,
    ): List<PublicResolvedRoute> =
        deterministicWorkerOrder(config.workers, deviceId, config.seq)
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
        val awgRoutes = ordered
            .map(PublicResolvedRoute::route)
            .filter { it.type in AWG_ROUTE_TYPES && it.address.isNotBlank() && it.port > 0 }
        val realityRoutes = ordered
            .map(PublicResolvedRoute::route)
            .filter { it.type in REALITY_ROUTE_TYPES && it.address.isNotBlank() && it.port > 0 }
        val primaryAwg = awgRoutes.getOrNull(0)
        val secondaryAwg = awgRoutes.getOrNull(1)
        val primaryReality = realityRoutes.getOrNull(0)
        val secondaryReality = realityRoutes.getOrNull(1)
        return PublicPlatformRouteSlots(
            awgRu = primaryAwg,
            awg = secondaryAwg,
            reality = primaryReality?.toRealityUiConfig(credentials),
            reality2 = secondaryReality?.toRealityUiConfig(credentials),
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
        )
    }

    fun awgRouteJson(route: PublicRouteConfig): JSONObject =
        JSONObject(route.params.toString())
            .put(JSON_TYPE, route.type)
            .put(JSON_ADDRESS, route.address)
            .put(JSON_PORT, route.port)

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
                            JSON_EXPECTED_EGRESS_IP,
                            worker.optString(JSON_EXPECTED_EGRESS_IP),
                        ),
                        dialectId = value.optString(JSON_DIALECT_ID).ifBlank { params.optString(JSON_DIALECT_ID) },
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
            expectedEgressIp = worker.getString(JSON_EXPECTED_EGRESS_IP),
            dialectId = params.optString(JSON_DIALECT_ID),
            params = params,
        )
    }

    private fun PublicRouteConfig.toRealityUiConfig(credentials: PublicPlatformCredentials): RealityUiConfig =
        RealityUiConfig(
            transport = params.optString(JSON_REALITY_TRANSPORT, "REALITY"),
            address = address,
            ip = params.optString(JSON_REALITY_IP),
            port = port,
            uuid = credentials.realityUUID,
            email = credentials.deviceID,
            flow = params.optString(JSON_REALITY_FLOW),
            security = params.optString(JSON_REALITY_SECURITY, "reality"),
            network = params.optString(JSON_REALITY_NETWORK, "tcp"),
            serverName = params.optString(JSON_REALITY_SERVER_NAME).ifBlank {
                params.optString(JSON_REALITY_SERVER_NAME_SNAKE, "example.com")
            },
            publicKey = params.optString(JSON_REALITY_PUBLIC_KEY).ifBlank {
                params.optString(JSON_REALITY_PUBLIC_KEY_SNAKE)
            },
            shortId = params.optString(JSON_REALITY_SHORT_ID).ifBlank {
                params.optString(JSON_REALITY_SHORT_ID_SNAKE)
            },
            fingerprint = params.optString(JSON_REALITY_FINGERPRINT, "chrome"),
            spiderX = params.optString(JSON_REALITY_SPIDER_X, "/"),
            dest = params.optString(JSON_REALITY_DEST),
        )

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
    private const val JSON_SEED_WORKERS = "seed_workers"
    private const val JSON_BOOTSTRAP_TOKEN = "bootstrap_token"
    private const val JSON_LIMITS = "limits"
    private const val JSON_EXPIRES = "expires"
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
    private const val JSON_PRIORITY = "priority"
    private const val JSON_WEIGHT = "weight"
    private const val JSON_ROUTES = "routes"
    private const val JSON_TYPE = "type"
    private const val JSON_ENABLED = "enabled"
    private const val JSON_ADDRESS = "address"
    private const val JSON_ENDPOINT = "endpoint"
    private const val JSON_PORT = "port"
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
    private const val DEFAULT_CONFIG_EXPIRES_AT = "9999-12-31T23:59:59Z"
    private val REALITY_ROUTE_TYPES = setOf("reality", "reality2")
    private val AWG_ROUTE_TYPES = setOf("awg", "awgru", "awg_ru")
    private val FORBIDDEN_KEYS = setOf("private_key", "psk2", "internal_ip", "server_private_key")
}
