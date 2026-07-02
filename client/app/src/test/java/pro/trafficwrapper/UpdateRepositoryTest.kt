package pro.trafficwrapper

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class UpdateRepositoryTest {
    @Test
    fun publicUpdateEndpointsRequireOptInForDirectFallback() {
        val params = listOf(
            JSONObject()
                .put("direct_update_urls", JSONArray(listOf("https://mirror.example/tw", "http://clear.example/tw")))
                .put("fallback_urls", JSONArray(listOf("https://fallback.example/tw/")))
                .put("direct_update_url", "https://single.example/tw")
                .put("config_url", "http://awg-gw:8080/tw"),
        )

        assertTrue(
            publicUpdateEndpoints(
                routeParams = params,
                socksListen = "",
                tunnelViable = false,
                directEnabled = false,
            ).isEmpty(),
        )

        val direct = publicUpdateEndpoints(
            routeParams = params,
            socksListen = "",
            tunnelViable = false,
            directEnabled = true,
        )
        assertEquals(
            listOf(
                "https://mirror.example/tw",
                "https://fallback.example/tw",
                "https://single.example/tw",
            ),
            direct.map { it.baseUrl },
        )
        assertTrue(direct.all { it.source == UpdateSource.DIRECT && it.socksListen.isBlank() })
    }

    @Test
    fun publicUpdateEndpointsUseTunnelConfigUrlsWhenTunnelViable() {
        val endpoints = publicUpdateEndpoints(
            routeParams = listOf(JSONObject().put("config_url", "http://awg-gw:8080/tw/")),
            socksListen = "127.0.0.1:18080",
            tunnelViable = true,
            directEnabled = true,
        )

        assertEquals(listOf("http://awg-gw:8080/tw"), endpoints.map { it.baseUrl })
        assertEquals(listOf("127.0.0.1:18080"), endpoints.map { it.socksListen })
        assertTrue(endpoints.all { it.source == UpdateSource.PLATFORM })
    }
}
