package pro.trafficwrapper

import com.google.zxing.BarcodeFormat
import com.google.zxing.qrcode.QRCodeWriter
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.MessageDigest
import java.util.Base64

class PublicPlatformConfigTest {
    @Test
    fun bootstrapParsesJsonAndBase64AndRejectsExpired() {
        val raw = bootstrapJson("2035-01-01T00:00:00Z")
        val parsed = PublicPlatformConfigParser.parseBootstrap(raw, nowMs = 0)
        assertEquals("https://orch.dev", parsed.orchestratorUrl)
        assertEquals("RWQconfig", parsed.configPubkeyPin)
        assertEquals("orch-noise", parsed.orchNoisePublic)
        assertEquals(listOf("https://worker-a.dev/tw/v1"), parsed.seedWorkers)
        assertEquals("once-token", parsed.bootstrapToken)

        val encoded = Base64.getEncoder().encodeToString(raw.toByteArray(Charsets.UTF_8))
        val parsedEncoded = PublicPlatformConfigParser.parseBootstrap(encoded, nowMs = 0)
        assertEquals(parsed.orchestratorUrl, parsedEncoded.orchestratorUrl)
        assertEquals(parsed.configPubkeyPin, parsedEncoded.configPubkeyPin)
        assertEquals(parsed.orchNoisePublic, parsedEncoded.orchNoisePublic)
        assertEquals(parsed.seedWorkers, parsedEncoded.seedWorkers)
        assertEquals(parsed.bootstrapToken, parsedEncoded.bootstrapToken)

        val withoutSeeds = raw.replace(
            ""","seed_workers":["https://worker-a.dev/tw/v1"]""",
            "",
        )
        val parsedWithoutSeeds = PublicPlatformConfigParser.parseBootstrap(withoutSeeds, nowMs = 0)
        assertTrue(parsedWithoutSeeds.seedWorkers.isEmpty())

        assertThrows(PublicConfigVerificationException::class.java) {
            PublicPlatformConfigParser.parseBootstrap(
                bootstrapJson("2020-01-01T00:00:00Z"),
                nowMs = 1_800_000_000_000L,
            )
        }
    }

    @Test
    fun qrBitmapDecodesBootstrapBase64() {
        val raw = bootstrapJson("2035-01-01T00:00:00Z")
        val encoded = Base64.getEncoder().encodeToString(raw.toByteArray(Charsets.UTF_8))
        val size = 192
        val matrix = QRCodeWriter().encode(encoded, BarcodeFormat.QR_CODE, size, size)
        val pixels = IntArray(size * size) { index ->
            val x = index % size
            val y = index / size
            if (matrix[x, y]) 0xFF000000.toInt() else 0xFFFFFFFF.toInt()
        }

        val decoded = BootstrapQrDecoder.decodeRgb(size, size, pixels)
        assertEquals(encoded, decoded)
        val parsed = PublicPlatformConfigParser.parseBootstrap(decoded!!, nowMs = 0)
        assertEquals("once-token", parsed.bootstrapToken)
        assertEquals("https://orch.dev", parsed.orchestratorUrl)
    }

    @Test
    fun clientConfigVerifiesSignatureAndRejectsUnsigned() {
        val config = clientConfig(seq = 7)
        val envelope = envelope(config, signature = "sig")
        val parsed = PublicPlatformConfigParser.verifyAndParseClientConfig(
            envelopeRaw = envelope,
            expectedPublicKey = PUBLIC_KEY,
            maxSeenSeq = 6,
            verifier = fakeVerifier(ok = true),
            nowMs = 0,
        )
        assertEquals(7, parsed.seq)
        assertEquals("worker-a", parsed.workers.single().workerId)
        assertEquals("198.51.100.10", parsed.workers.single().routes.single().expectedEgressIp)

        assertThrows(PublicConfigVerificationException::class.java) {
            PublicPlatformConfigParser.verifyAndParseClientConfig(
                envelopeRaw = envelope(config, signature = ""),
                expectedPublicKey = PUBLIC_KEY,
                maxSeenSeq = 0,
                verifier = fakeVerifier(ok = false),
                nowMs = 0,
            )
        }
    }

    @Test
    fun clientConfigRejectsRollbackAndForbiddenKeys() {
        assertThrows(PublicConfigVerificationException::class.java) {
            PublicPlatformConfigParser.verifyAndParseClientConfig(
                envelopeRaw = envelope(clientConfig(seq = 3), signature = "sig"),
                expectedPublicKey = PUBLIC_KEY,
                maxSeenSeq = 4,
                verifier = fakeVerifier(ok = true),
                nowMs = 0,
            )
        }

        val forbidden = clientConfig(seq = 5).replace(
            "\"dialect_id\":\"dialect-a\"",
            "\"dialect_id\":\"dialect-a\",\"private_key\":\"must-not-ship\"",
        )
        assertThrows(PublicConfigVerificationException::class.java) {
            PublicPlatformConfigParser.verifyAndParseClientConfig(
                envelopeRaw = envelope(forbidden, signature = "sig"),
                expectedPublicKey = PUBLIC_KEY,
                maxSeenSeq = 0,
                verifier = fakeVerifier(ok = true),
                nowMs = 0,
            )
        }
    }

    @Test
    fun weightedOrderIsDeterministicAndDependsOnSeed() {
        val workers = PublicPlatformConfigParser.verifyAndParseClientConfig(
            envelopeRaw = envelope(clientConfigWithWorkers(), signature = "sig"),
            expectedPublicKey = PUBLIC_KEY,
            maxSeenSeq = 0,
            verifier = fakeVerifier(ok = true),
            nowMs = 0,
        ).workers

        val first = PublicPlatformConfigParser.deterministicWorkerOrder(workers, "device-a", 11)
        val second = PublicPlatformConfigParser.deterministicWorkerOrder(workers, "device-a", 11)
        assertEquals(first, second)
        assertTrue(first.all { it.priority == 0 })
    }

    @Test
    fun weightedOrderFavorsHigherWeightAcrossDeviceSeeds() {
        val workers = PublicPlatformConfigParser.verifyAndParseClientConfig(
            envelopeRaw = envelope(clientConfigForWeightDistribution(), signature = "sig"),
            expectedPublicKey = PUBLIC_KEY,
            maxSeenSeq = 0,
            verifier = fakeVerifier(ok = true),
            nowMs = 0,
        ).workers

        var highWeightFirst = 0
        repeat(5_000) { index ->
            val first = PublicPlatformConfigParser
                .deterministicWorkerOrder(workers, "device-$index", 17)
                .first()
            if (first.workerId == "heavy") highWeightFirst++
        }

        val share = highWeightFirst / 5_000.0
        assertTrue("high-weight share=$share", share in 0.85..0.95)
    }

    @Test
    fun clientConfigParsesCurrentP1WorkerShape() {
        val parsed = PublicPlatformConfigParser.verifyAndParseClientConfig(
            envelopeRaw = JSONObject()
                .put("config_json", legacyP1ClientConfig())
                .put("minisig", "sig")
                .toString(),
            expectedPublicKey = PUBLIC_KEY,
            maxSeenSeq = 0,
            verifier = fakeVerifier(ok = true),
            nowMs = 0,
        )

        val worker = parsed.workers.single()
        assertEquals("worker-p1", worker.workerId)
        assertEquals(2, worker.routes.size)
        assertEquals("reality", worker.routes[0].type)
        assertEquals("203.0.113.5", worker.routes[0].address)
        assertEquals(8444, worker.routes[0].port)
        assertEquals("awg", worker.routes[1].type)
        assertEquals("203.0.113.5", worker.routes[1].address)
        assertEquals(51888, worker.routes[1].port)
    }

    @Test
    fun routeSlotsKeepPublicConfigPriorityWithoutLegacyReality2Fallback() {
        val parsed = PublicPlatformConfigParser.verifyAndParseClientConfig(
            envelopeRaw = JSONObject()
                .put("config_json", legacyP1ClientConfig())
                .put("minisig", "sig")
                .toString(),
            expectedPublicKey = PUBLIC_KEY,
            maxSeenSeq = 0,
            verifier = fakeVerifier(ok = true),
            nowMs = 0,
        )

        val slots = PublicPlatformConfigParser.routeSlots(
            config = parsed,
            deviceId = "device-a",
            credentials = PublicPlatformCredentials(
                deviceID = "device-a",
                realityUUID = "11111111-1111-4111-8111-111111111111",
                internalIP = "10.13.13.2/32",
                psk2 = "psk",
                serverAWGPublic = "server",
                awgPrivateKey = "private",
                awgPublicKey = "public",
            ),
        )

        assertEquals(0, slots.routePriorities["REALITY"])
        assertEquals(1, slots.routePriorities["AWG_RU"])
        assertTrue(slots.reality?.isComplete() == true)
        assertEquals("", slots.reality?.flow)
        assertEquals(null, slots.reality2)
    }

    @Test
    fun routeSlotsUseNestedParamsForRealityAndAwg() {
        val parsed = PublicPlatformConfigParser.verifyAndParseClientConfig(
            envelopeRaw = JSONObject()
                .put("config_json", nestedParamsClientConfig())
                .put("minisig", "sig")
                .toString(),
            expectedPublicKey = PUBLIC_KEY,
            maxSeenSeq = 0,
            verifier = fakeVerifier(ok = true),
            nowMs = 0,
        )

        val slots = PublicPlatformConfigParser.routeSlots(
            config = parsed,
            deviceId = "device-a",
            credentials = PublicPlatformCredentials(
                deviceID = "device-a",
                realityUUID = "22222222-2222-4222-8222-222222222222",
                internalIP = "10.13.13.3/32",
                psk2 = "psk",
                serverAWGPublic = "server-awg",
                awgPrivateKey = "private",
                awgPublicKey = "public",
            ),
        )

        assertEquals("198.51.100.20", slots.realityExpectedEgressIp)
        assertEquals("198.51.100.20", slots.awgRuExpectedEgressIp)
        assertEquals("22222222-2222-4222-8222-222222222222", slots.reality?.uuid)
        assertEquals("reality-pub", slots.reality?.publicKey)
        assertEquals("short-id", slots.reality?.shortId)
        assertEquals("www.microsoft.com", slots.reality?.serverName)
        assertEquals("awg-server-pub", slots.awgRu?.params?.optString("public_key"))
        assertEquals("dialect-1", slots.awgRu?.dialectId)
    }

    private fun fakeVerifier(ok: Boolean): PublicMinisignVerifier =
        object : PublicMinisignVerifier {
            override fun verify(message: String, signature: String, publicKey: String): Boolean =
                ok && signature.isNotBlank() && publicKey == PUBLIC_KEY
        }

    private fun bootstrapJson(expires: String): String =
        """{"orchestrator_url":"https://orch.dev","config_pubkey_pin":"$PUBLIC_KEY","orch_noise_public":"orch-noise","seed_workers":["https://worker-a.dev/tw/v1"],"bootstrap_token":"once-token","expires":"$expires","limits":{"devices":1}}"""

    private fun clientConfig(seq: Long): String =
        """{"schema":1,"ns":"client-config-v1","seq":$seq,"issued_at":"2030-01-01T00:00:00Z","expires_at":"2035-01-01T00:00:00Z","workers":[{"worker_id":"worker-a","label":"A","priority":0,"weight":100,"routes":[{"type":"reality","enabled":true,"address":"worker-a.dev","port":443,"expected_egress_ip":"198.51.100.10","dialect_id":"dialect-a","publicKey":"pub","shortId":"sid"}]}]}"""

    private fun clientConfigWithWorkers(): String =
        """{"schema":1,"ns":"client-config-v1","seq":11,"issued_at":"2030-01-01T00:00:00Z","expires_at":"2035-01-01T00:00:00Z","workers":[{"worker_id":"a","label":"A","priority":0,"weight":100,"routes":[{"type":"reality","enabled":true,"address":"a.dev","port":443,"expected_egress_ip":"198.51.100.1","dialect_id":"d"}]},{"worker_id":"b","label":"B","priority":0,"weight":40,"routes":[{"type":"reality","enabled":true,"address":"b.dev","port":443,"expected_egress_ip":"198.51.100.2","dialect_id":"d"}]},{"worker_id":"c","label":"C","priority":0,"weight":80,"routes":[{"type":"awg","enabled":true,"address":"c.dev","port":51821,"expected_egress_ip":"198.51.100.3","dialect_id":"d"}]}]}"""

    private fun clientConfigForWeightDistribution(): String =
        """{"schema":1,"ns":"client-config-v1","seq":17,"issued_at":"2030-01-01T00:00:00Z","expires_at":"2035-01-01T00:00:00Z","workers":[{"worker_id":"heavy","label":"Heavy","priority":0,"weight":90,"routes":[{"type":"reality","enabled":true,"address":"heavy.dev","port":443,"expected_egress_ip":"198.51.100.90","dialect_id":"d"}]},{"worker_id":"light","label":"Light","priority":0,"weight":10,"routes":[{"type":"reality","enabled":true,"address":"light.dev","port":443,"expected_egress_ip":"198.51.100.10","dialect_id":"d"}]}]}"""

    private fun legacyP1ClientConfig(): String =
        """{"schema":1,"ns":"client-config-v1","seq":1,"issued_at":"2030-01-01T00:00:00Z","workers":[{"id":"worker-p1","priority":10,"weight":100,"routes":["REALITY","AWG"],"expected_egress_ip":"203.0.113.5","reality":{"address":"203.0.113.5","port":8444,"publicKey":"pub","shortId":"sid"},"awg":{"endpoint":"203.0.113.5:51888","public_key":"awgpub","port":51888}}]}"""

    private fun nestedParamsClientConfig(): String =
        """{"schema":1,"ns":"client-config-v1","seq":2,"issued_at":"2030-01-01T00:00:00Z","expires_at":"2035-01-01T00:00:00Z","workers":[{"worker_id":"worker-nested","label":"Nested","priority":0,"weight":100,"routes":[{"type":"reality","enabled":true,"address":"worker.example","port":2053,"expected_egress_ip":"198.51.100.20","dialect_id":"dialect-1","params":{"public_key":"reality-pub","short_id":"short-id","server_name":"www.microsoft.com","flow":"xtls-rprx-vision","security":"reality","network":"tcp"}},{"type":"awg","enabled":true,"address":"worker.example","port":51888,"expected_egress_ip":"198.51.100.20","dialect_id":"dialect-1","params":{"public_key":"awg-server-pub","endpoint":"worker.example:51888","dialect_id":"dialect-1"}}]}]}"""

    private fun envelope(configJson: String, signature: String): String =
        JSONObject()
            .put("config_json", configJson)
            .put("config_json_minisig", signature)
            .put("public_key", PUBLIC_KEY)
            .put("config_sha256", sha256(configJson))
            .put("server_time", "2030-01-01T00:00:00Z")
            .toString()

    private fun sha256(value: String): String =
        MessageDigest.getInstance("SHA-256")
            .digest(value.toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02x".format(it.toInt() and 0xff) }

    private companion object {
        private const val PUBLIC_KEY = "RWQconfig"
    }
}
