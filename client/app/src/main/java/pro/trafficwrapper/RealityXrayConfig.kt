package pro.trafficwrapper

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
        .put("mode", cfg.xhttpMode)
        .apply {
            val host = cfg.xhttpHost.ifBlank { cfg.serverName }.trim()
            if (host.isNotBlank()) {
                put("host", host)
            }
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
