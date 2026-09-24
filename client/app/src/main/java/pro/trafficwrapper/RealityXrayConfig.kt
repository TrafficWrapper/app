package pro.trafficwrapper

import org.json.JSONArray
import org.json.JSONObject

internal fun realityStreamSettingsJson(
    cfg: RealityUiConfig,
    sockopt: JSONObject,
    onInvalidXhttpExtra: ((String) -> Unit)? = null,
): JSONObject {
    val streamSettings = JSONObject()
        .put("network", cfg.network.ifBlank { "tcp" })
        .put("security", cfg.security)
        .put("sockopt", sockopt)
        .put(
            "realitySettings",
            JSONObject()
                .put("serverName", cfg.serverName)
                .put("fingerprint", cfg.fingerprint)
                .put("publicKey", cfg.publicKey)
                .put("shortId", cfg.shortId)
                .put("spiderX", cfg.spiderX),
        )
    if (cfg.network.equals("xhttp", ignoreCase = true)) {
        streamSettings.put("xhttpSettings", realityXhttpSettingsJson(cfg, onInvalidXhttpExtra))
    }
    return streamSettings
}

internal fun realityXhttpSettingsJson(
    cfg: RealityUiConfig,
    onInvalidXhttpExtra: ((String) -> Unit)? = null,
): JSONObject =
    JSONObject()
        .put("path", cfg.xhttpPath)
        .put("mode", realityXhttpOutboundMode(cfg.xhttpMode))
        .apply {
            val extra = cfg.xhttpExtraJson.trim()
            if (extra.isNotBlank()) {
                runCatching { put("extra", JSONObject(extra)) }
                    .onFailure { onInvalidXhttpExtra?.invoke(it.message.orEmpty()) }
            }
        }

internal fun realityOutboundFlow(cfg: RealityUiConfig): String =
    if (cfg.network.equals("xhttp", ignoreCase = true)) {
        ""
    } else {
        cfg.flow.trim()
    }

internal fun realityXhttpOutboundMode(mode: String): String {
    val normalized = mode.trim()
    return if (normalized.isBlank() || normalized.equals("auto", ignoreCase = true)) {
        XHTTP_DEFAULT_OUTBOUND_MODE
    } else {
        normalized
    }
}

/**
 * Xray log level. Verbose xhttp dial diagnostics ("debug") are only emitted in debug builds:
 * release builds must not spam logcat with per-connection lines that include destinations.
 */
internal fun realityXrayLogLevel(cfg: RealityUiConfig, debugBuild: Boolean = BuildConfig.DEBUG): String =
    if (debugBuild && cfg.network.equals("xhttp", ignoreCase = true)) "debug" else "warning"

/**
 * Settings for the loopback SOCKS inbound of an xray sidecar. The listener always requires the
 * process-internal credentials (RFC 1929), so other apps on the device cannot use the sidecar
 * directly and bypass the router.
 */
internal fun realityXraySocksInboundSettings(credentials: SocksCredentials): JSONObject =
    JSONObject()
        .put("auth", "password")
        .put(
            "accounts",
            JSONArray().put(
                JSONObject()
                    .put("user", credentials.username)
                    .put("pass", credentials.password),
            ),
        )
        .put("udp", false)

private const val XHTTP_DEFAULT_OUTBOUND_MODE = "stream-up"
