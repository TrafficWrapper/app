package pro.trafficwrapper

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Discovery slot identity (X-M6), tunnel-first sinks (X-M7) and egress probes (APP-M17). */
class DiscoverySlotsTest {
    private val credentials = PublicPlatformCredentials(
        deviceID = "device-a",
        realityUUID = "11111111-1111-4111-8111-111111111111",
        internalIP = "10.13.13.2/32",
        psk2 = "psk",
        serverAWGPublic = "server",
        awgPrivateKey = "private",
        awgPublicKey = "public",
    )

    private fun worker(id: String, priority: Int, egress: String): PublicWorkerConfig =
        PublicWorkerConfig(
            workerId = id,
            label = id,
            priority = priority,
            weight = 100,
            routes = listOf(
                PublicRouteConfig(
                    type = "awg",
                    enabled = true,
                    address = "$id.example",
                    port = 51820,
                    expectedEgressIp = egress,
                    dialectId = "",
                    params = JSONObject().put("public_key", "k-$id"),
                ),
                PublicRouteConfig(
                    type = "reality",
                    enabled = true,
                    address = "$id.example",
                    port = 443,
                    expectedEgressIp = egress,
                    dialectId = "",
                    params = JSONObject()
                        .put("public_key", "pk-$id")
                        .put("short_id", "sid")
                        .put("server_name", "sni.example"),
                ),
            ),
        )

    private fun config(vararg workers: PublicWorkerConfig) = PublicClientConfig(
        schema = 1,
        namespace = "client-config-v1",
        seq = 1,
        issuedAt = "2030-01-01T00:00:00Z",
        expiresAt = "2035-01-01T00:00:00Z",
        updatePubkey = "",
        discoveryPubkey = "",
        discoveryRescuePointers = emptyList(),
        dnsServers = emptyList(),
        limits = null,
        workers = workers.toList(),
    )

    @Test
    fun slotsCarryTheirWorkerIds() {
        // Distinct priorities make the order deterministic: A primary, B secondary.
        val slots = PublicPlatformConfigParser.routeSlots(
            config(worker("w-a", 0, "203.0.113.10"), worker("w-b", 1, "203.0.113.20")),
            "device-a",
            credentials,
        )
        assertEquals("w-a", slots.awgRuWorkerId)
        assertEquals("w-b", slots.awgWorkerId)
        assertEquals("w-a", slots.realityWorkerId)
        assertEquals("w-b", slots.reality2WorkerId)

        val request = publicCoreApplyRequest(
            stored = StoredPublicPlatformState(deviceID = "device-a"),
            config = config(),
            slots = slots,
            socksListen = "127.0.0.1:1",
            awgRuSocksListen = "127.0.0.1:2",
        )
        assertEquals("w-a", request.getJSONObject("awg_ru").getString("worker_id"))
        assertEquals("w-b", request.getJSONObject("awg").getString("worker_id"))
    }

    @Test
    fun discoveryRequestIdentifiesRealitySlots() {
        val slots = PublicPlatformConfigParser.routeSlots(
            config(worker("w-a", 0, "203.0.113.10"), worker("w-b", 1, "")),
            "device-a",
            credentials,
        )
        val request = discoveryApplyRequest("{}", "sig", "key", 7, "2030-01-01T00:00:00Z", slots)
        val reality = request.getJSONObject("reality_slot")
        assertEquals("w-a", reality.getString("worker_id"))
        assertEquals("203.0.113.10", reality.getString("egress_ip"))
        val reality2 = request.getJSONObject("reality2_slot")
        assertEquals("w-b", reality2.getString("worker_id"))
        assertFalse(reality2.has("egress_ip"))
        assertEquals(7, request.getLong("max_seen_seq"))

        // One worker only: no REALITY2 slot identity is sent.
        val single = PublicPlatformConfigParser.routeSlots(config(worker("w-a", 0, "203.0.113.10")), "device-a", credentials)
        val singleRequest = discoveryApplyRequest("{}", "sig", "key", 0, "2030-01-01T00:00:00Z", single)
        assertTrue(singleRequest.has("reality_slot"))
        assertFalse(singleRequest.has("reality2_slot"))
    }

    @Test
    fun onlyMatchedRealityEntryUpdatesEgress() {
        // Reduced feed / no match: the core returns no "reality" object and nothing changes.
        assertNull(matchedRealityEgress(JSONObject().put("ok", true), "reality"))
        assertNull(matchedRealityEgress(JSONObject().put("reality", JSONObject().put("egress_ip", " ")), "reality"))
        assertEquals(
            "198.51.100.9",
            matchedRealityEgress(JSONObject().put("reality2", JSONObject().put("egress_ip", "198.51.100.9")), "reality2"),
        )
    }

    @Test
    fun directSinksOnlyWhenTunnelIsDownOrUnreachable() {
        assertTrue(discoveryTunnelUp(authorized = true, handshakeEstablished = true, socksListen = "127.0.0.1:18080"))
        assertFalse(discoveryTunnelUp(authorized = true, handshakeEstablished = false, socksListen = "127.0.0.1:18080"))
        assertFalse(discoveryTunnelUp(authorized = true, handshakeEstablished = true, socksListen = ""))

        // Tunnel down: direct sinks are the rescue path.
        assertTrue(directDiscoveryAllowed(tunnelUp = false, tunnelSinksTried = 0, tunnelSinkAnswered = false))
        assertTrue(directDiscoveryAllowed(tunnelUp = false, tunnelSinksTried = 2, tunnelSinkAnswered = true))
        // Tunnel up and a tunnel sink answered (even with 404): never go off-tunnel.
        assertFalse(directDiscoveryAllowed(tunnelUp = true, tunnelSinksTried = 1, tunnelSinkAnswered = true))
        // Tunnel up but no tunnel sink at all: stay on-tunnel as well.
        assertFalse(directDiscoveryAllowed(tunnelUp = true, tunnelSinksTried = 0, tunnelSinkAnswered = false))
        // Tunnel up but every tunnel sink failed without an answer: the tunnel path is broken.
        assertTrue(directDiscoveryAllowed(tunnelUp = true, tunnelSinksTried = 2, tunnelSinkAnswered = false))
    }

    @Test
    fun egressProbeUrlsParseTolerantly() {
        assertEquals(emptyList<String>(), PublicPlatformConfigParser.parseEgressProbeUrls(null))
        assertEquals(emptyList<String>(), PublicPlatformConfigParser.parseEgressProbeUrls("https://echo.example/ip"))
        assertEquals(emptyList<String>(), PublicPlatformConfigParser.parseEgressProbeUrls(JSONObject()))
        val parsed = PublicPlatformConfigParser.parseEgressProbeUrls(
            JSONArray()
                .put(" https://echo.example/ip ")
                .put(42)
                .put("ftp://echo.example/ip")
                .put("https://user:pw@echo.example/ip")
                .put("not a url")
                .put("http://awg-gw:8080/tw/ip")
                .put("https://echo.example/ip"),
        )
        assertEquals(listOf("https://echo.example/ip", "http://awg-gw:8080/tw/ip"), parsed)
    }

    @Test
    fun egressProbeUrlsAreReadFromTheSignedBundle() {
        val base = """{"schema":1,"ns":"client-config-v1","seq":1,"issued_at":"2030-01-01T00:00:00Z","expires_at":"2035-01-01T00:00:00Z","workers":[]"""
        val verifier = object : PublicMinisignVerifier {
            override fun verify(message: String, signature: String, publicKey: String) = true
        }
        fun parse(configJson: String) = PublicPlatformConfigParser.verifyAndParseClientConfig(
            envelopeRaw = JSONObject().put("config_json", configJson).put("minisig", "sig").toString(),
            expectedPublicKey = "key",
            maxSeenSeq = 0,
            verifier = verifier,
            nowMs = 0,
        )
        assertEquals(emptyList<String>(), parse("$base}").egressProbeUrls)
        assertEquals(emptyList<String>(), parse("$base,\"egress_probe_urls\":\"https://x.example\"}").egressProbeUrls)
        assertEquals(
            listOf("https://echo.example/ip"),
            parse("$base,\"egress_probe_urls\":[\"https://echo.example/ip\"]}").egressProbeUrls,
        )
    }

    @Test
    fun egressProbeUrlPriority() {
        assertEquals(listOf("https://echo.example/ip"), egressProbeUrls(listOf("https://echo.example/ip"), "https://build.example"))
        assertEquals(listOf("https://build.example"), egressProbeUrls(emptyList(), " https://build.example "))
        assertEquals(listOf(FALLBACK_EGRESS_PROBE_URL), egressProbeUrls(emptyList(), ""))
        assertTrue(isHealthProbeDestination("echo.example:443", listOf("https://other.example", "https://echo.example/ip")))
        assertFalse(isHealthProbeDestination("api.ipify.org:443", listOf("https://echo.example/ip")))
    }

    @Test
    fun egressProbeResponseIsTextOrJson() {
        assertEquals("198.51.100.7", parseEgressProbeResponse("198.51.100.7\n"))
        assertEquals("2001:db8::7", parseEgressProbeResponse("2001:db8::7"))
        assertEquals("198.51.100.8", parseEgressProbeResponse("""{"egress_ip":"198.51.100.8"}"""))
        assertEquals("", parseEgressProbeResponse("""{"ip":"198.51.100.8"}"""))
        assertEquals("", parseEgressProbeResponse("<html>blocked</html>"))
        assertEquals("", parseEgressProbeResponse("999.1.1.1"))
        assertEquals("", parseEgressProbeResponse("example.com"))
        assertEquals("", parseEgressProbeResponse(""))
    }
}
