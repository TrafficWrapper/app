package pro.trafficwrapper

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class RealityXrayConfigTest {
    @Test
    fun tcpRealityStreamSettingsDoNotEmitXhttpSettings() {
        val stream = realityStreamSettingsJson(
            baseConfig(network = "tcp"),
            JSONObject().put("tcpMaxSeg", 1200),
        )

        assertEquals("tcp", stream.getString("network"))
        assertFalse(stream.has("xhttpSettings"))
        assertEquals("reality", stream.getString("security"))
    }

    @Test
    fun xhttpRealityStreamSettingsIncludeOperatorParamsAndExtraJson() {
        val stream = realityStreamSettingsJson(
            baseConfig(
                network = "xhttp",
                xhttpHost = "cdn.operator.example",
                xhttpPath = "/operator-path",
                xhttpMode = "auto",
                xhttpExtraJson = """{"headers":{"X-Test":"1"}}""",
            ),
            JSONObject().put("tcpMaxSeg", 1200),
        )

        assertEquals("xhttp", stream.getString("network"))
        val xhttp = stream.getJSONObject("xhttpSettings")
        assertEquals("cdn.operator.example", xhttp.getString("host"))
        assertEquals("/operator-path", xhttp.getString("path"))
        assertEquals("stream-up", xhttp.getString("mode"))
        assertEquals("1", xhttp.getJSONObject("extra").getJSONObject("headers").getString("X-Test"))
    }

    @Test
    fun xhttpHostDefaultsToServerNameForOlderBundles() {
        val stream = realityStreamSettingsJson(
            baseConfig(network = "xhttp", xhttpPath = "/x", xhttpMode = "stream-up"),
            JSONObject(),
        )

        val xhttp = stream.getJSONObject("xhttpSettings")
        assertEquals("www.microsoft.com", xhttp.getString("host"))
    }

    @Test
    fun xhttpOutboundModeAutoOrBlankUsesStreamUp() {
        assertEquals("stream-up", realityXhttpOutboundMode("auto"))
        assertEquals("stream-up", realityXhttpOutboundMode(""))
        assertEquals("packet-up", realityXhttpOutboundMode(" packet-up "))
    }

    @Test
    fun invalidXhttpExtraIsIgnoredWithoutBreakingSettings() {
        var warning = ""
        val stream = realityStreamSettingsJson(
            baseConfig(network = "xhttp", xhttpPath = "/x", xhttpMode = "packet-up", xhttpExtraJson = "{"),
            JSONObject(),
        ) { warning = it }

        val xhttp = stream.getJSONObject("xhttpSettings")
        assertEquals("/x", xhttp.getString("path"))
        assertEquals("packet-up", xhttp.getString("mode"))
        assertFalse(xhttp.has("extra"))
        assertTrue(warning.isNotBlank())
    }

    @Test
    fun xhttpRealityOutboundFlowIsAlwaysBlank() {
        val cfg = baseConfig(network = "xhttp", xhttpPath = "/x", xhttpMode = "auto", flow = "xtls-rprx-vision")

        assertEquals("", realityOutboundFlow(cfg))
    }

    @Test
    fun tcpRealityOutboundFlowIsPreserved() {
        val cfg = baseConfig(network = "tcp", flow = "xtls-rprx-vision")

        assertEquals("xtls-rprx-vision", realityOutboundFlow(cfg))
    }

    private fun baseConfig(
        network: String,
        flow: String = "",
        xhttpHost: String = "",
        xhttpPath: String = "",
        xhttpMode: String = "",
        xhttpExtraJson: String = "",
    ): RealityUiConfig =
        RealityUiConfig(
            transport = "REALITY",
            address = "worker.example",
            port = 443,
            uuid = "33333333-3333-4333-8333-333333333333",
            email = "device",
            flow = flow,
            security = "reality",
            network = network,
            serverName = "www.microsoft.com",
            publicKey = "pub",
            shortId = "sid",
            fingerprint = "chrome",
            spiderX = "/",
            xhttpHost = xhttpHost,
            xhttpPath = xhttpPath,
            xhttpMode = xhttpMode,
            xhttpExtraJson = xhttpExtraJson,
        )
}
