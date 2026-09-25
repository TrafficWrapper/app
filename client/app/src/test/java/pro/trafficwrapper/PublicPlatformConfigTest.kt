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
    fun enrollDeepLinkExtractsBootstrapPayloadOnly() {
        val raw = bootstrapJson("2035-01-01T00:00:00Z")
        val encoded = Base64.getEncoder().encodeToString(raw.toByteArray(Charsets.UTF_8))
        val link = "twp://enroll?bootstrap=${java.net.URLEncoder.encode(encoded, Charsets.UTF_8.name())}"

        val extracted = publicEnrollDeepLinkBootstrap(link)
        assertEquals(encoded, extracted)
        assertEquals("once-token", PublicPlatformConfigParser.parseBootstrap(extracted!!, nowMs = 0).bootstrapToken)
        assertEquals(null, publicEnrollDeepLinkBootstrap("twp://enroll?token=once-token"))
        assertEquals(null, publicEnrollDeepLinkBootstrap("https://example.test/enroll?bootstrap=$encoded"))
    }

    @Test
    fun externalBootstrapDecisionUsesTrustRootNotTokenForWarnings() {
        val activeRaw = bootstrapJson("2035-01-01T00:00:00Z")
        val activeEncoded = Base64.getEncoder().encodeToString(activeRaw.toByteArray(Charsets.UTF_8))
        val parsed = PublicPlatformConfigParser.parseBootstrap(activeRaw, nowMs = 0)
        assertTrue(publicBootstrapMatchesActive(activeEncoded, parsed))
        assertEquals(ExternalBootstrapDecision.IGNORE, externalBootstrapDecision(activeEncoded, parsed))

        val refreshedRaw = activeRaw
            .replace("once-token", "fresh-token")
            .replace("2035-01-01T00:00:00Z", "2036-01-01T00:00:00Z")
        val refreshedParsed = PublicPlatformConfigParser.parseBootstrap(refreshedRaw, nowMs = 0)
        assertTrue(publicBootstrapMatchesActive(activeEncoded, refreshedParsed))
        assertEquals(
            ExternalBootstrapDecision.REFRESH,
            externalBootstrapDecision(activeEncoded, refreshedParsed),
        )

        val replacement = PublicPlatformConfigParser.parseBootstrap(
            activeRaw.replace("https://orch.dev", "https://other-orch.dev"),
            nowMs = 0,
        )
        assertEquals(false, publicBootstrapMatchesActive(activeEncoded, replacement))
        assertEquals(
            ExternalBootstrapDecision.CONFIRM_REPLACE,
            externalBootstrapDecision(activeEncoded, replacement),
        )

        val differentNoise = PublicPlatformConfigParser.parseBootstrap(
            activeRaw.replace("orch-noise", "other-noise"),
            nowMs = 0,
        )
        assertEquals(false, publicBootstrapMatchesActive(activeEncoded, differentNoise))
    }

    @Test
    fun externalBootstrapWithDifferentUpdateKeyOrSeedsRequiresConfirmation() {
        val activeRaw = bootstrapJson("2035-01-01T00:00:00Z").replace(
            "\"seed_workers\"",
            "\"update_pubkey\":\"RWQupdate\",\"seed_workers\"",
        )
        val active = PublicPlatformConfigParser.parseBootstrap(activeRaw, nowMs = 0)
        assertEquals("RWQupdate", active.updatePubkey)

        // Only token/expiry changed: silent refresh is fine.
        val refreshed = PublicPlatformConfigParser.parseBootstrap(
            activeRaw.replace("once-token", "fresh-token"),
            nowMs = 0,
        )
        assertEquals(ExternalBootstrapDecision.REFRESH, externalBootstrapDecision(activeRaw, refreshed, "RWQupdate"))

        // A different update key is a trust-root change.
        val otherUpdateKey = PublicPlatformConfigParser.parseBootstrap(
            activeRaw.replace("RWQupdate", "RWQattacker").replace("once-token", "fresh-token"),
            nowMs = 0,
        )
        assertEquals(false, publicBootstrapMatchesActive(activeRaw, otherUpdateKey))
        assertEquals(
            ExternalBootstrapDecision.CONFIRM_REPLACE,
            externalBootstrapDecision(activeRaw, otherUpdateKey, "RWQupdate"),
        )

        // Dropping or adding the update key also counts as a change.
        val withoutUpdateKey = PublicPlatformConfigParser.parseBootstrap(
            bootstrapJson("2035-01-01T00:00:00Z").replace("once-token", "fresh-token"),
            nowMs = 0,
        )
        assertEquals(
            ExternalBootstrapDecision.CONFIRM_REPLACE,
            externalBootstrapDecision(activeRaw, withoutUpdateKey),
        )

        // Seed workers are trusted routing data too.
        val otherSeeds = PublicPlatformConfigParser.parseBootstrap(
            activeRaw.replace("https://worker-a.dev/tw/v1", "https://evil.dev/tw/v1"),
            nowMs = 0,
        )
        assertEquals(
            ExternalBootstrapDecision.CONFIRM_REPLACE,
            externalBootstrapDecision(activeRaw, otherSeeds, "RWQupdate"),
        )
    }

    @Test
    fun externalBootstrapConflictingWithPinnedUpdateKeyRequiresConfirmation() {
        val raw = bootstrapJson("2035-01-01T00:00:00Z").replace(
            "\"seed_workers\"",
            "\"update_pubkey\":\"RWQother\",\"seed_workers\"",
        )
        val parsed = PublicPlatformConfigParser.parseBootstrap(raw.replace("once-token", "fresh-token"), nowMs = 0)
        // Stored raw bootstrap matches, but the pin (e.g. from signed config) differs.
        assertEquals(
            ExternalBootstrapDecision.CONFIRM_REPLACE,
            externalBootstrapDecision(raw, parsed, pinnedUpdatePubkey = "RWQpinned"),
        )
        assertTrue(updatePubkeyCompatibleWithPin("", "RWQother"))
        assertTrue(updatePubkeyCompatibleWithPin("RWQpinned", ""))
        assertEquals(false, updatePubkeyCompatibleWithPin("RWQpinned", "RWQother"))
    }

    @Test
    fun updatePubkeyPinIsNotReplacedByBootstrap() {
        val bootstrap = PublicPlatformConfigParser.parseBootstrap(
            bootstrapJson("2035-01-01T00:00:00Z").replace(
                "\"seed_workers\"",
                "\"update_pubkey\":\"RWQbootstrap\",\"seed_workers\"",
            ),
            nowMs = 0,
        )
        val pinned = StoredPublicPlatformState(configPubkeyPin = PUBLIC_KEY, updatePubkeyPin = "RWQpinned")

        // Signed client config wins.
        assertEquals("RWQsigned", resolveUpdatePubkeyPin("RWQsigned", pinned, bootstrap))
        // Existing pin is kept against an (unsigned) bootstrap for the same platform.
        assertEquals("RWQpinned", resolveUpdatePubkeyPin("", pinned, bootstrap))
        // First enrollment: trust on first use of the bootstrap key.
        assertEquals("RWQbootstrap", resolveUpdatePubkeyPin("", StoredPublicPlatformState(), bootstrap))
        // User-confirmed switch to another platform (different config key) takes the new key.
        val otherPlatform = pinned.copy(configPubkeyPin = "RWQotherConfig")
        assertEquals("RWQbootstrap", resolveUpdatePubkeyPin("", otherPlatform, bootstrap))
    }

    @Test
    fun mergeEnrolledStateKeepsMonotonicCountersAndTrustedTime() {
        val bootstrap = PublicPlatformConfigParser.parseBootstrap(bootstrapJson("2035-01-01T00:00:00Z"), nowMs = 0)
        val current = StoredPublicPlatformState(
            configPubkeyPin = PUBLIC_KEY,
            updatePubkeyPin = "RWQpinned",
            maxSeenConfigSeq = 5,
            maxSeenUpdateSeq = 9,
            trustedWallTimeMs = 2_000,
            trustedElapsedRealtimeMs = 20,
        )
        val enrolled = StoredPublicPlatformState(
            configPubkeyPin = PUBLIC_KEY,
            updatePubkeyPin = "",
            maxSeenConfigSeq = 6,
            maxSeenUpdateSeq = 3,
            deviceID = "dev",
        )
        val merged = mergeEnrolledPublicPlatformState(current, enrolled, configSeq = 6, signedConfigUpdatePubkey = "", bootstrap = bootstrap)
        assertEquals("dev", merged.deviceID)
        assertEquals("RWQpinned", merged.updatePubkeyPin)
        assertEquals(6L, merged.maxSeenConfigSeq)
        assertEquals(9L, merged.maxSeenUpdateSeq)
        assertEquals(2_000L, merged.trustedWallTimeMs)
        assertEquals(20L, merged.trustedElapsedRealtimeMs)

        assertThrows(PublicConfigVerificationException::class.java) {
            mergeEnrolledPublicPlatformState(current.copy(maxSeenConfigSeq = 7), enrolled, 6, "", bootstrap)
        }
    }

    @Test
    fun mergeEnrolledStateAfterConfirmedPlatformSwitchStartsCountersFromZero() {
        // APP-M3: platform A reached seq 240; platform B (different config key) is at seq 3.
        val bootstrap = PublicPlatformConfigParser.parseBootstrap(bootstrapJson("2035-01-01T00:00:00Z"), nowMs = 0)
        val platformA = StoredPublicPlatformState(
            configPubkeyPin = "RWQplatformA",
            updatePubkeyPin = "RWQupdateA",
            maxSeenConfigSeq = 240,
            maxSeenUpdateSeq = 50,
            maxSeenUpdateSeqPin = "RWQupdateA",
            deviceID = "old",
        )
        // What the enrollment path computes against the previous state.
        assertEquals(0L, platformA.configSeqFloorFor(PUBLIC_KEY))
        val config = PublicPlatformConfigParser.verifyAndParseClientConfig(
            envelopeRaw = envelope(clientConfig(seq = 3), signature = "sig"),
            expectedPublicKey = PUBLIC_KEY,
            maxSeenSeq = platformA.configSeqFloorFor(PUBLIC_KEY),
            verifier = fakeVerifier(ok = true),
            nowMs = 0,
        )
        val updatePin = resolveUpdatePubkeyPin("RWQupdateB", platformA, bootstrap)
        val enrolled = StoredPublicPlatformState(
            configPubkeyPin = PUBLIC_KEY,
            updatePubkeyPin = updatePin,
            maxSeenConfigSeq = maxOf(platformA.configSeqFloorFor(PUBLIC_KEY), config.seq),
            maxSeenUpdateSeq = platformA.updateSeqFloorFor(updatePin),
            maxSeenUpdateSeqPin = updatePin,
            deviceID = "new",
        )

        val merged = mergeEnrolledPublicPlatformState(platformA, enrolled, config.seq, "RWQupdateB", bootstrap)
        assertEquals("new", merged.deviceID)
        assertEquals(PUBLIC_KEY, merged.configPubkeyPin)
        assertEquals("RWQupdateB", merged.updatePubkeyPin)
        assertEquals(3L, merged.maxSeenConfigSeq)
        assertEquals(0L, merged.maxSeenUpdateSeq)
        assertEquals("RWQupdateB", merged.maxSeenUpdateSeqPin)

        // Same platform: the floor still applies and a lower seq is a rollback.
        val sameAsB = merged.copy(maxSeenConfigSeq = 9)
        assertThrows(PublicConfigVerificationException::class.java) {
            mergeEnrolledPublicPlatformState(sameAsB, enrolled, 3, "RWQupdateB", bootstrap)
        }
        assertThrows(PublicConfigVerificationException::class.java) {
            PublicPlatformConfigParser.verifyAndParseClientConfig(
                envelopeRaw = envelope(clientConfig(seq = 3), signature = "sig"),
                expectedPublicKey = PUBLIC_KEY,
                maxSeenSeq = sameAsB.configSeqFloorFor(PUBLIC_KEY),
                verifier = fakeVerifier(ok = true),
                nowMs = 0,
            )
        }
    }

    @Test
    fun updateSeqFloorIsBoundToUpdatePubkeyPin() {
        val state = StoredPublicPlatformState(
            configPubkeyPin = PUBLIC_KEY,
            updatePubkeyPin = "RWQupdateA",
            maxSeenUpdateSeq = 50,
            maxSeenUpdateSeqPin = "RWQupdateA",
        )
        assertEquals(50L, state.updateSeqFloorFor("RWQupdateA"))
        assertEquals(0L, state.updateSeqFloorFor("RWQupdateB"))
        // Unknown owner (blank) keeps the floor: never weaker than before.
        assertEquals(50L, state.copy(maxSeenUpdateSeqPin = "").updateSeqFloorFor("RWQupdateB"))
        // A signed key rotation on the same platform (config poll only changes updatePubkeyPin)
        // leaves the owner behind, so the new key starts from 0.
        val rotated = state.copy(updatePubkeyPin = "RWQupdateB")
        assertEquals(0L, rotated.updateSeqFloorFor(rotated.updatePubkeyPin))
        // Config floor: blank stored pin keeps the floor, other platform resets it.
        val cfg = StoredPublicPlatformState(configPubkeyPin = "RWQa", maxSeenConfigSeq = 7)
        assertEquals(7L, cfg.configSeqFloorFor("RWQa"))
        assertEquals(0L, cfg.configSeqFloorFor("RWQb"))
        assertEquals(7L, cfg.copy(configPubkeyPin = "").configSeqFloorFor("RWQb"))
    }

    @Test
    fun mergeEnrolledStateResetsUpdateFloorWhenSignedUpdateKeyRotates() {
        val bootstrap = PublicPlatformConfigParser.parseBootstrap(bootstrapJson("2035-01-01T00:00:00Z"), nowMs = 0)
        val current = StoredPublicPlatformState(
            configPubkeyPin = PUBLIC_KEY,
            updatePubkeyPin = "RWQupdateA",
            maxSeenConfigSeq = 5,
            maxSeenUpdateSeq = 50,
            maxSeenUpdateSeqPin = "RWQupdateA",
        )
        val enrolled = StoredPublicPlatformState(
            configPubkeyPin = PUBLIC_KEY,
            updatePubkeyPin = "RWQupdateA",
            maxSeenConfigSeq = 6,
            maxSeenUpdateSeq = 50,
            maxSeenUpdateSeqPin = "RWQupdateA",
        )
        val kept = mergeEnrolledPublicPlatformState(current, enrolled, 6, "RWQupdateA", bootstrap)
        assertEquals(50L, kept.maxSeenUpdateSeq)
        val rotated = mergeEnrolledPublicPlatformState(current, enrolled, 6, "RWQupdateB", bootstrap)
        assertEquals("RWQupdateB", rotated.updatePubkeyPin)
        assertEquals(0L, rotated.maxSeenUpdateSeq)
        assertEquals("RWQupdateB", rotated.maxSeenUpdateSeqPin)
        assertEquals(6L, rotated.maxSeenConfigSeq)
    }

    @Test
    fun clientConfigSeqContractAcceptsLargeJumpsAndEqualSeq() {
        // client-config-v1 seq contract: only seq < maxSeen is a rollback. A migration jump
        // (+1_000_000 or an operator floor) is accepted; an equal seq is accepted by verification
        // so the poll can ignore it (seq <= maxSeen) without raising an error.
        fun verify(seq: Long, maxSeen: Long) =
            PublicPlatformConfigParser.verifyAndParseClientConfig(
                envelopeRaw = envelope(clientConfig(seq), signature = "sig"),
                expectedPublicKey = PUBLIC_KEY,
                maxSeenSeq = maxSeen,
                verifier = fakeVerifier(ok = true),
                nowMs = 0,
            )
        val jumped = 240L + 1_000_000L
        assertEquals(jumped, verify(jumped, maxSeen = 240).seq)
        assertEquals(jumped, verify(jumped, maxSeen = jumped).seq)
        assertEquals(jumped + 1, verify(jumped + 1, maxSeen = jumped).seq)
        val huge = 4_000_000_000_000_000_000L
        assertEquals(huge, verify(huge, maxSeen = jumped).seq)
        assertThrows(PublicConfigVerificationException::class.java) { verify(jumped - 1, maxSeen = jumped) }
        assertThrows(PublicConfigVerificationException::class.java) { verify(240, maxSeen = jumped) }
    }

    @Test
    fun clientConfigContractAcceptsEmptyWorkersArray() {
        // ORC-L35 contract: the orchestrator sends workers: [] instead of null.
        val config = PublicPlatformConfigParser.verifyAndParseClientConfig(
            envelopeRaw = envelope(
                """{"schema":1,"ns":"client-config-v1","seq":1000005,"issued_at":"2030-01-01T00:00:00Z","expires_at":"2035-01-01T00:00:00Z","workers":[]}""",
                signature = "sig",
            ),
            expectedPublicKey = PUBLIC_KEY,
            maxSeenSeq = 5,
            verifier = fakeVerifier(ok = true),
            nowMs = 0,
        )
        assertTrue(config.workers.isEmpty())
        assertTrue(PublicPlatformConfigParser.deterministicRouteOrder(config, "device-a").isEmpty())
    }

    @Test
    fun workerOrderDoesNotChangeWhenOnlySeqChanges() {
        // APP-L26: a re-issued bundle (new seq, same workers) must not reshuffle clients.
        val base = parseConfig(clientConfigWithWorkers())
        val reissued = base.copy(seq = base.seq + 1_000_000)
        repeat(200) { index ->
            val deviceId = "device-$index"
            assertEquals(
                PublicPlatformConfigParser.deterministicRouteOrder(base, deviceId),
                PublicPlatformConfigParser.deterministicRouteOrder(reissued, deviceId),
            )
        }
    }

    @Test
    fun discoveryValidationTimeNeverRewindsBelowLocalClock() {
        assertEquals(5_000L, discoveryValidationNowMs(mirrorDateMs = 1_000L, localNowMs = 5_000L))
        assertEquals(9_000L, discoveryValidationNowMs(mirrorDateMs = 9_000L, localNowMs = 5_000L))
        assertEquals(5_000L, discoveryValidationNowMs(mirrorDateMs = null, localNowMs = 5_000L))
    }

    @Test
    fun awgRouteJsonEmitsCanonicalEgressIPForCoreApply() {
        val route = PublicRouteConfig(
            type = "awg",
            enabled = true,
            address = "worker.example",
            port = 51821,
            expectedEgressIp = "198.51.100.44",
            dialectId = "dialect-a",
            params = JSONObject("""{"endpoint":"worker.example:51821","public_key":"awg-pub"}"""),
        )

        val json = PublicPlatformConfigParser.awgRouteJson(route)
        assertEquals("198.51.100.44", json.getString("egress_ip"))
        assertEquals("", json.optString("expected_egress_ip"))
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
        assertEquals(listOf("9.9.9.9", "149.112.112.112"), parsed.dnsServers)
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

        val first = PublicPlatformConfigParser.deterministicWorkerOrder(workers, "device-a")
        val second = PublicPlatformConfigParser.deterministicWorkerOrder(workers, "device-a")
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
                .deterministicWorkerOrder(workers, "device-$index")
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
        assertEquals("xtls-rprx-vision", slots.reality?.flow)
        assertEquals("firefox", slots.reality?.fingerprint)
        assertEquals("awg-server-pub", slots.awgRu?.params?.optString("public_key"))
        assertEquals("dialect-1", slots.awgRu?.dialectId)
    }

    @Test
    fun routeSlotsExposeOptionalOperatorRegionMetadata() {
        val parsed = PublicPlatformConfigParser.verifyAndParseClientConfig(
            envelopeRaw = JSONObject()
                .put("config_json", regionClientConfig())
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

        assertEquals("Operator Edge", parsed.workers.single().routes[0].region)
        assertEquals("Operator Edge", slots.routeRegions["REALITY"])
        assertEquals(null, slots.routeRegions["AWG"])
    }

    @Test
    fun routeSlotsParseXhttpRealityParams() {
        val parsed = PublicPlatformConfigParser.verifyAndParseClientConfig(
            envelopeRaw = JSONObject()
                .put("config_json", xhttpClientConfig())
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
                realityUUID = "33333333-3333-4333-8333-333333333333",
                internalIP = "10.13.13.4/32",
                psk2 = "psk",
                serverAWGPublic = "server-awg",
                awgPrivateKey = "private",
                awgPublicKey = "public",
            ),
        )

        val reality = slots.reality
        assertTrue(reality?.isComplete() == true)
        assertEquals("xhttp", reality?.network)
        assertEquals("", reality?.flow)
        assertEquals("cdn.operator.example", reality?.xhttpHost)
        assertEquals("/operator-path", reality?.xhttpPath)
        assertEquals("auto", reality?.xhttpMode)
        assertEquals("""{"headers":{"X-Test":"1"}}""", reality?.xhttpExtraJson)
    }

    @Test
    fun realityFingerprintIsClampedToXrayUtlsSet() {
        val parsed = PublicPlatformConfigParser.verifyAndParseClientConfig(
            envelopeRaw = JSONObject()
                .put("config_json", nestedParamsClientConfig().replace("\"firefox\"", "\"utls-modern\""))
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

        assertEquals("chrome", slots.reality?.fingerprint)
        assertEquals("chrome", clampRealityFingerprint("typo"))
        assertEquals("android", clampRealityFingerprint(" Android "))
    }

    @Test
    fun discoverySinksUseOnlyOperatorProvidedUrls() {
        val parsed = PublicPlatformConfigParser.verifyAndParseClientConfig(
            envelopeRaw = JSONObject()
                .put("config_json", discoveryClientConfig())
                .put("minisig", "sig")
                .toString(),
            expectedPublicKey = PUBLIC_KEY,
            maxSeenSeq = 0,
            verifier = fakeVerifier(ok = true),
            nowMs = 0,
        )
        val sinks = discoverySinks(
            stored = StoredPublicPlatformState(
                bootstrapRaw = bootstrapJson("2035-01-01T00:00:00Z"),
                configPubkeyPin = PUBLIC_KEY,
            ),
            config = parsed,
            socksListen = "127.0.0.1:18080",
        )

        assertEquals(
            listOf(
                "http://awg-gw:8080/tw",
                "https://worker.example/discovery",
                "https://orch.dev/discovery",
            ),
            sinks.map { it.baseUrl },
        )
        assertEquals("127.0.0.1:18080", sinks[0].socksListen)
        assertEquals("", sinks[1].socksListen)
        assertEquals("", sinks[2].socksListen)
        assertTrue(sinks.none { it.baseUrl.contains("netcloud", ignoreCase = true) })
    }

    @Test
    fun discoveryNextSinksAndRescuePointersAreOperatorControlled() {
        assertEquals(
            listOf("http://worker.local/tw", "https://operator.example/discovery"),
            signedNextSinks(
                """{"next_sinks":["http://worker.local/tw","https://operator.example/discovery","https://operator.example/discovery","ftp://bad"]}""",
            ),
        )
        val parsed = PublicPlatformConfigParser.verifyAndParseClientConfig(
            envelopeRaw = JSONObject()
                .put("config_json", discoveryClientConfigWithRescue())
                .put("minisig", "sig")
                .toString(),
            expectedPublicKey = PUBLIC_KEY,
            maxSeenSeq = 0,
            verifier = fakeVerifier(ok = true),
            nowMs = 0,
        )
        val sinks = discoverySinks(
            stored = StoredPublicPlatformState(
                bootstrapRaw = bootstrapJson("2035-01-01T00:00:00Z"),
                configPubkeyPin = PUBLIC_KEY,
            ),
            config = parsed,
            socksListen = "127.0.0.1:18080",
            rendezvousState = StoredRendezvousState(
                discoverySinks = listOf("http://next.local/tw", "https://next.example/discovery"),
            ),
        )

        assertTrue(sinks.any { it.name == "signed-next-0" && it.baseUrl == "http://next.local/tw" && it.socksListen == "127.0.0.1:18080" })
        assertTrue(sinks.any { it.name == "signed-next-1" && it.baseUrl == "https://next.example/discovery" && it.socksListen.isBlank() })
        assertTrue(sinks.any { it.name == "rescue-pointer-0" && it.pointerUrl == "https://operator.example/rescue-pointer.json" })
    }

    @Test
    fun resolveRealityFlowMatrix() {
        val vision = REALITY_FLOW_VISION
        // Unknown device flow (old enrollment / old orchestrator): params.flow exactly as before.
        for (routeVision in listOf(true, false, null)) {
            assertEquals(vision, resolveRealityFlow("tcp", "", deviceFlowKnown = false, paramsFlow = " $vision ", routeVision = routeVision))
            assertEquals("", resolveRealityFlow("tcp", vision, deviceFlowKnown = false, paramsFlow = "", routeVision = routeVision))
            assertEquals("", resolveRealityFlow("xhttp", vision, deviceFlowKnown = false, paramsFlow = vision, routeVision = routeVision))
        }
        // Known Vision flow: routes marked vision=true get it, vision=false never, no mark -> TCP only.
        assertEquals(vision, resolveRealityFlow("tcp", vision, true, "", routeVision = true))
        assertEquals("", resolveRealityFlow("tcp", vision, true, vision, routeVision = false))
        assertEquals(vision, resolveRealityFlow("tcp", vision, true, "", routeVision = null))
        assertEquals(vision, resolveRealityFlow("", vision, true, "", routeVision = null))
        assertEquals("", resolveRealityFlow("xhttp", vision, true, "", routeVision = true))
        assertEquals("", resolveRealityFlow("xhttp", vision, true, "", routeVision = false))
        assertEquals("", resolveRealityFlow("XHTTP", vision, true, vision, routeVision = null))
        // Known empty flow (app without Vision on the orchestrator): never a flow.
        for (routeVision in listOf(true, false, null)) {
            for (network in listOf("tcp", "xhttp")) {
                assertEquals("", resolveRealityFlow(network, "", true, vision, routeVision = routeVision))
            }
        }
        // Only Vision is supported as a device flow.
        assertEquals("", resolveRealityFlow("tcp", "xtls-rprx-direct", true, "", routeVision = true))
    }

    @Test
    fun realityRouteVisionReadsOptionalMark() {
        assertEquals(null, realityRouteVision(JSONObject()))
        assertEquals(true, realityRouteVision(JSONObject().put("vision", true)))
        assertEquals(false, realityRouteVision(JSONObject().put("vision", false)))
    }

    @Test
    fun realityCohortIndexUsesSha256OfDeviceId() {
        val hash = MessageDigest.getInstance("SHA-256").digest("device-a".toByteArray(Charsets.UTF_8))
        val expected = (
            ((hash[0].toLong() and 0xff) shl 24) or
                ((hash[1].toLong() and 0xff) shl 16) or
                ((hash[2].toLong() and 0xff) shl 8) or
                (hash[3].toLong() and 0xff)
            ) % 16
        assertEquals(expected.toInt(), realityCohortIndex("device-a", 16))
        // Fixed vector: sha256("device-a")[0:4] = dd5e8641 = 3713959489.
        assertEquals(1, realityCohortIndex("device-a", 16))
        assertEquals(6, realityCohortIndex("3f1c2e", 16))
        assertEquals(0, realityCohortIndex("3f1c2e", 3))
    }

    @Test
    fun resolveRealityShortIdPicksCohortSlotWithFallback() {
        val cohorts = org.json.JSONArray((0 until 16).map { "c%02d".format(it) })
        val params = JSONObject().put("short_id", "base").put("cohort_short_ids", cohorts)
        assertEquals("c01", resolveRealityShortId(params, "device-a"))
        assertEquals("c06", resolveRealityShortId(params, "3f1c2e"))
        // Revoked slot -> base short id.
        cohorts.put(1, "")
        assertEquals("base", resolveRealityShortId(params, "device-a"))
        // No list / empty list / unknown device -> base short id (as before).
        assertEquals("base", resolveRealityShortId(JSONObject().put("short_id", "base"), "device-a"))
        assertEquals("sid", resolveRealityShortId(JSONObject().put("shortId", "sid").put("cohort_short_ids", org.json.JSONArray()), "device-a"))
        assertEquals("base", resolveRealityShortId(JSONObject(params.toString()).put("cohort_short_ids", cohorts), ""))
    }

    @Test
    fun routeSlotsWithoutNewFieldsBehaveAsBefore() {
        val slots = PublicPlatformConfigParser.routeSlots(
            config = parseConfig(nestedParamsClientConfig()),
            deviceId = "device-a",
            credentials = credentials(),
        )
        assertEquals(1, slots.realityVariants.size)
        assertEquals(slots.reality, slots.realityVariants.single().config)
        assertEquals("xtls-rprx-vision", slots.reality?.flow)
        assertEquals("short-id", slots.reality?.shortId)
        assertEquals(1, slots.awgRuVariants.size)
        assertEquals(IpFamily.V4, slots.awgRuVariants.single().family)
        assertEquals(emptyList<RealityRouteVariant>(), slots.reality2Variants)
    }

    @Test
    fun routeSlotsApplyEnrollFlowAndCohortShortId() {
        val slots = PublicPlatformConfigParser.routeSlots(
            config = parseConfig(featureClientConfig()),
            deviceId = "device-a",
            credentials = credentials(realityFlow = REALITY_FLOW_VISION, realityFlowKnown = true),
        )
        val primary = slots.reality!!
        assertEquals("primary.example", primary.address)
        assertEquals(443, primary.port)
        assertEquals(REALITY_FLOW_VISION, primary.flow)
        assertEquals("c1", primary.shortId)

        val noVision = PublicPlatformConfigParser.routeSlots(
            config = parseConfig(featureClientConfig()),
            deviceId = "device-a",
            credentials = credentials(realityFlow = "", realityFlowKnown = true),
        )
        assertEquals("", noVision.reality?.flow)
    }

    @Test
    fun fallbackProfileRoutesExtendVariantsWithoutTakingSlots() {
        val slots = PublicPlatformConfigParser.routeSlots(
            config = parseConfig(featureClientConfig()),
            deviceId = "device-a",
            credentials = credentials(realityFlow = REALITY_FLOW_VISION, realityFlowKnown = true),
        )
        // The fallback routes of worker-a must not become REALITY2; worker-b's primary does.
        assertEquals("b.example", slots.reality2?.address)
        assertEquals(1, slots.reality2Variants.size)

        val keys = slots.realityVariants.map { it.key }
        assertEquals(
            listOf(
                "worker-a|reality|tcp|v4|xtls-rprx-vision",
                "worker-a|tcp-alt|tcp|v4|xtls-rprx-vision",
                "worker-a|tcp-novision|tcp|v4|",
                "worker-a|xhttp|xhttp|v4|",
                "worker-a|tcp-alt|tcp|v6|xtls-rprx-vision",
                "worker-a|xhttp|xhttp|v6|",
            ),
            keys,
        )
        val xhttp = slots.realityVariants.first { it.key == "worker-a|xhttp|xhttp|v4|" }.config
        assertEquals(8443, xhttp.port)
        assertEquals("stream-up", xhttp.xhttpMode)
        assertEquals("/xh", xhttp.xhttpPath)
        assertEquals("", xhttp.xhttpHost)
        assertEquals("", xhttp.flow)
        assertEquals("c1", xhttp.shortId)
        assertTrue(xhttp.isComplete())
        val xhttpV6 = slots.realityVariants.first { it.key == "worker-a|xhttp|xhttp|v6|" }.config
        assertEquals("2001:db8::1", xhttpV6.address)

        // No IPv6 on the network: v6 variants are dropped; IPv6-only: they come first.
        val v4Only = RouteVariants.orderForNetwork(slots.realityVariants, RealityRouteVariant::family, NetworkIpFamilies.DEFAULT)
        assertTrue(v4Only.all { it.family == IpFamily.V4 })
        val v6Only = RouteVariants.orderForNetwork(
            slots.realityVariants,
            RealityRouteVariant::family,
            NetworkIpFamilies(ipv4 = false, ipv6 = true),
        )
        assertEquals(IpFamily.V6, v6Only.first().family)
        assertEquals(IpFamily.V4, v6Only.last().family)
    }

    @Test
    fun realityProfilesParamsExpandToVariants() {
        val route = PublicRouteConfig(
            type = "reality",
            enabled = true,
            address = "w.example",
            port = 443,
            expectedEgressIp = "",
            dialectId = "",
            params = JSONObject()
                .put("public_key", "pk")
                .put("short_id", "sid")
                .put("server_name", "sni.example")
                .put("network", "tcp")
                .put(
                    "reality_profiles",
                    org.json.JSONArray()
                        .put(
                            JSONObject().put("name", "reality").put("address", "w.example").put("port", 443)
                                .put("network", "tcp").put("flows", org.json.JSONArray().put("").put(REALITY_FLOW_VISION)),
                        )
                        .put(
                            JSONObject().put("name", "xh").put("address", "w.example").put("address_v6", "2001:db8::5")
                                .put("port", 8443).put("network", "xhttp").put("flows", org.json.JSONArray().put(""))
                                .put("xhttp", JSONObject().put("path", "/p").put("mode", "").put("host", "cdn.example")),
                        ),
                ),
        )
        val worker = PublicWorkerConfig("w", "W", 0, 100, listOf(route))
        val variants = RouteVariants.expandRealityVariants(
            PublicResolvedRoute(worker, route),
            fallbacks = emptyList(),
            credentials = credentials(realityFlow = REALITY_FLOW_VISION, realityFlowKnown = true),
        )
        assertEquals(
            listOf("w|reality|tcp|v4|xtls-rprx-vision", "w|xh|xhttp|v4|", "w|xh|xhttp|v6|"),
            variants.map { it.key },
        )
        assertEquals("stream-up", variants[1].config.xhttpMode)
        assertEquals("", variants[1].config.xhttpHost)
        assertEquals("2001:db8::5", variants[2].config.address)
    }

    @Test
    fun awgVariantsAddIpv6OnlyWithEndpointV6() {
        val slots = PublicPlatformConfigParser.routeSlots(
            config = parseConfig(featureClientConfig()),
            deviceId = "device-a",
            credentials = credentials(),
        )
        val awgRu = slots.awgRuVariants
        assertEquals(listOf(IpFamily.V4, IpFamily.V6), awgRu.map { it.family })
        assertEquals("worker-a|awg-v2|awg|v6|", awgRu[1].key)
        assertEquals(
            listOf(IpFamily.V4),
            RouteVariants.orderForNetwork(awgRu, AwgRouteVariant::family, NetworkIpFamilies.DEFAULT).map { it.family },
        )
        val noV6 = RouteVariants.expandAwgVariants(
            PublicResolvedRoute(
                PublicWorkerConfig("w", "W", 0, 100, emptyList()),
                PublicRouteConfig("awg", true, "w.example", 51820, "", "", params = JSONObject()),
            ),
        )
        assertEquals(1, noV6.size)
    }

    @Test
    fun coreApplyRequestIsBackwardCompatibleAndCarriesNewFields() {
        val config = parseConfig(featureClientConfig())
        val stored = StoredPublicPlatformState(
            deviceID = "device-a",
            realityUUID = "11111111-1111-4111-8111-111111111111",
            internalIP = "10.13.13.2/32",
            psk2 = "psk",
            serverAWGPublic = "server",
            awgPrivateKey = "private",
            awgPublicKey = "public",
        )
        val slots = PublicPlatformConfigParser.routeSlots(config, stored.deviceID, stored.toPublicPlatformCredentials())
        val legacy = publicCoreApplyRequest(stored, config, slots, "127.0.0.1:18082", "127.0.0.1:18084", awgRuFamily = "", awgFamily = "")
        assertEquals(false, legacy.has("awg_profiles"))
        assertEquals(false, legacy.has("rendezvous_public_key"))
        assertEquals(false, legacy.getJSONObject("awg_ru").has("ip_family"))
        assertEquals(1420, legacy.getInt("mtu"))
        assertEquals("127.0.0.1:18082", legacy.getString("socks_listen"))
        assertEquals("127.0.0.1:18084", legacy.getString("awg_ru_socks_listen"))
        assertEquals("private", legacy.getString("awg_private_key"))
        assertEquals("[2001:db8::1]:51821", legacy.getJSONObject("awg_ru").getString("endpoint_v6"))
        assertEquals("awg-v2", legacy.getJSONObject("awg_ru").getString("awg_profile"))
        assertEquals("10.8.0.1", legacy.getJSONObject("awg_ru").getJSONArray("dns").getString(0))

        val profiles = JSONObject().put("awg-v2", JSONObject().put("awg_public_key", "pk2").put("internal_ip", "10.14.0.2/32").put("psk2", "p2"))
        val request = publicCoreApplyRequest(
            stored.copy(awgProfilesJson = profiles.toString()),
            config,
            slots,
            "127.0.0.1:18082",
            "127.0.0.1:18084",
            rendezvousPublicKey = "rv",
            awgRuFamily = "v6",
            awgFamily = "",
        )
        assertEquals("pk2", request.getJSONObject("awg_profiles").getJSONObject("awg-v2").getString("awg_public_key"))
        assertEquals("rv", request.getString("rendezvous_public_key"))
        assertEquals("v6", request.getJSONObject("awg_ru").getString("ip_family"))
        // A slot without endpoint_v6 never asks the core for IPv6.
        val noV6Slots = PublicPlatformConfigParser.routeSlots(parseConfig(nestedParamsClientConfig()), "device-a", stored.toPublicPlatformCredentials())
        val noV6 = publicCoreApplyRequest(stored, parseConfig(nestedParamsClientConfig()), noV6Slots, "a", "b", awgRuFamily = "v6", awgFamily = "")
        assertEquals(false, noV6.getJSONObject("awg_ru").has("ip_family"))
    }

    @Test
    fun enrollmentVersionRefreshTriggersOnAnyVersionChange() {
        assertTrue(publicEnrollmentNeedsVersionRefresh(0, 31))
        assertTrue(publicEnrollmentNeedsVersionRefresh(32, 31))
        assertTrue(publicEnrollmentNeedsVersionRefresh(30, 31))
        assertEquals(false, publicEnrollmentNeedsVersionRefresh(31, 31))
        assertTrue(shouldWaitForPublicVersionReEnroll(needed = true, lastFailureAtMs = 0L, nowMs = 5_000L))
        assertEquals(false, shouldWaitForPublicVersionReEnroll(needed = false, lastFailureAtMs = 0L, nowMs = 5_000L))
        assertEquals(false, shouldWaitForPublicVersionReEnroll(needed = true, lastFailureAtMs = 1_000L, nowMs = 60_000L))
        assertTrue(
            shouldWaitForPublicVersionReEnroll(
                needed = true,
                lastFailureAtMs = 1_000L,
                nowMs = 1_000L + PUBLIC_REENROLL_RETRY_AFTER_MS,
            ),
        )
    }

    @Test
    fun clientCapabilitiesAreTheAgreedSet() {
        assertEquals(
            listOf("reality_vision", "reality_profiles", "reality_short_id", "awg_dialect_wide", "ipv6_endpoints", "tunnel_dns"),
            PUBLIC_CLIENT_CAPABILITIES,
        )
    }

    private fun parseConfig(configJson: String): PublicClientConfig =
        PublicPlatformConfigParser.verifyAndParseClientConfig(
            envelopeRaw = JSONObject().put("config_json", configJson).put("minisig", "sig").toString(),
            expectedPublicKey = PUBLIC_KEY,
            maxSeenSeq = 0,
            verifier = fakeVerifier(ok = true),
            nowMs = 0,
        )

    private fun credentials(realityFlow: String = "", realityFlowKnown: Boolean = false): PublicPlatformCredentials =
        PublicPlatformCredentials(
            deviceID = "device-a",
            realityUUID = "11111111-1111-4111-8111-111111111111",
            internalIP = "10.13.13.2/32",
            psk2 = "psk",
            serverAWGPublic = "server",
            awgPrivateKey = "private",
            awgPublicKey = "public",
            realityFlow = realityFlow,
            realityFlowKnown = realityFlowKnown,
        )

    /**
     * Orchestrator bundle shape (PR #5/#6): worker-a has a primary REALITY route with cohorts and
     * vision=true, fallback routes with "profile" (tcp with/without Vision, xhttp with IPv6) and an
     * AWG profile route with endpoint_v6/dns; worker-b (lower priority) has a primary REALITY route.
     */
    private fun featureClientConfig(): String {
        val cohorts = org.json.JSONArray((0 until 16).map { "c$it" })
        val primary = JSONObject()
            .put("type", "reality").put("enabled", true).put("address", "primary.example").put("port", 443)
            .put("egress_ip", "198.51.100.40").put("vision", true).put("cohort_short_ids", cohorts)
            .put(
                "params",
                JSONObject().put("public_key", "pk").put("short_id", "base").put("server_name", "sni.example")
                    .put("network", "tcp").put("flow", "").put("cohort_short_ids", cohorts),
            )
        val tcpAlt = JSONObject()
            .put("type", "reality").put("enabled", true).put("address", "primary.example").put("port", 2083)
            .put("egress_ip", "198.51.100.40").put("profile", "tcp-alt").put("vision", true)
            .put(
                "params",
                JSONObject().put("name", "tcp-alt").put("public_key", "pk").put("short_id", "base")
                    .put("server_name", "sni.example").put("network", "tcp").put("address_v6", "2001:db8::1")
                    .put("cohort_short_ids", cohorts),
            )
        val tcpNoVision = JSONObject()
            .put("type", "reality").put("enabled", true).put("address", "primary.example").put("port", 2087)
            .put("egress_ip", "198.51.100.40").put("profile", "tcp-novision").put("vision", false)
            .put(
                "params",
                JSONObject().put("public_key", "pk").put("short_id", "base").put("server_name", "sni.example")
                    .put("network", "tcp"),
            )
        val xhttp = JSONObject()
            .put("type", "reality").put("enabled", true).put("address", "primary.example").put("port", 8443)
            .put("egress_ip", "198.51.100.40").put("profile", "xhttp").put("vision", false)
            .put(
                "params",
                JSONObject().put("public_key", "pk").put("short_id", "base").put("server_name", "sni.example")
                    .put("network", "xhttp").put("address_v6", "2001:db8::1").put("cohort_short_ids", cohorts)
                    .put("xhttp", JSONObject().put("path", "/xh").put("mode", "").put("host", "cdn.example")),
            )
        val awg = JSONObject()
            .put("type", "awg").put("enabled", true).put("address", "primary.example").put("port", 51821)
            .put("egress_ip", "198.51.100.40").put("profile", "awg-v2").put("awg_profile", "awg-v2")
            .put("endpoint_v6", "[2001:db8::1]:51821").put("dns", org.json.JSONArray().put("10.8.0.1"))
            .put("params", JSONObject().put("public_key", "awgpk").put("endpoint", "primary.example:51821"))
        val workerA = JSONObject().put("worker_id", "worker-a").put("label", "A").put("priority", 0).put("weight", 100)
            .put("routes", org.json.JSONArray().put(primary).put(xhttp).put(tcpNoVision).put(tcpAlt).put(awg))
        val workerB = JSONObject().put("worker_id", "worker-b").put("label", "B").put("priority", 1).put("weight", 100)
            .put(
                "routes",
                org.json.JSONArray().put(
                    JSONObject().put("type", "reality").put("enabled", true).put("address", "b.example").put("port", 443)
                        .put("egress_ip", "198.51.100.41")
                        .put("params", JSONObject().put("public_key", "pkb").put("short_id", "sb").put("server_name", "sni.example")),
                ),
            )
        return JSONObject()
            .put("schema", 1).put("ns", "client-config-v1").put("seq", 30)
            .put("issued_at", "2030-01-01T00:00:00Z").put("expires_at", "2035-01-01T00:00:00Z")
            .put("workers", org.json.JSONArray().put(workerA).put(workerB))
            .toString()
    }

    private fun fakeVerifier(ok: Boolean): PublicMinisignVerifier =
        object : PublicMinisignVerifier {
            override fun verify(message: String, signature: String, publicKey: String): Boolean =
                ok && signature.isNotBlank() && publicKey == PUBLIC_KEY
        }

    private fun bootstrapJson(expires: String): String =
        """{"orchestrator_url":"https://orch.dev","config_pubkey_pin":"$PUBLIC_KEY","orch_noise_public":"orch-noise","seed_workers":["https://worker-a.dev/tw/v1"],"bootstrap_token":"once-token","expires":"$expires","limits":{"devices":1}}"""

    private fun clientConfig(seq: Long): String =
        """{"schema":1,"ns":"client-config-v1","seq":$seq,"issued_at":"2030-01-01T00:00:00Z","expires_at":"2035-01-01T00:00:00Z","dns_servers":["9.9.9.9","149.112.112.112"],"workers":[{"worker_id":"worker-a","label":"A","priority":0,"weight":100,"routes":[{"type":"reality","enabled":true,"address":"worker-a.dev","port":443,"expected_egress_ip":"198.51.100.10","dialect_id":"dialect-a","publicKey":"pub","shortId":"sid"}]}]}"""

    private fun clientConfigWithWorkers(): String =
        """{"schema":1,"ns":"client-config-v1","seq":11,"issued_at":"2030-01-01T00:00:00Z","expires_at":"2035-01-01T00:00:00Z","workers":[{"worker_id":"a","label":"A","priority":0,"weight":100,"routes":[{"type":"reality","enabled":true,"address":"a.dev","port":443,"expected_egress_ip":"198.51.100.1","dialect_id":"d"}]},{"worker_id":"b","label":"B","priority":0,"weight":40,"routes":[{"type":"reality","enabled":true,"address":"b.dev","port":443,"expected_egress_ip":"198.51.100.2","dialect_id":"d"}]},{"worker_id":"c","label":"C","priority":0,"weight":80,"routes":[{"type":"awg","enabled":true,"address":"c.dev","port":51821,"expected_egress_ip":"198.51.100.3","dialect_id":"d"}]}]}"""

    private fun clientConfigForWeightDistribution(): String =
        """{"schema":1,"ns":"client-config-v1","seq":17,"issued_at":"2030-01-01T00:00:00Z","expires_at":"2035-01-01T00:00:00Z","workers":[{"worker_id":"heavy","label":"Heavy","priority":0,"weight":90,"routes":[{"type":"reality","enabled":true,"address":"heavy.dev","port":443,"expected_egress_ip":"198.51.100.90","dialect_id":"d"}]},{"worker_id":"light","label":"Light","priority":0,"weight":10,"routes":[{"type":"reality","enabled":true,"address":"light.dev","port":443,"expected_egress_ip":"198.51.100.10","dialect_id":"d"}]}]}"""

    private fun legacyP1ClientConfig(): String =
        """{"schema":1,"ns":"client-config-v1","seq":1,"issued_at":"2030-01-01T00:00:00Z","workers":[{"id":"worker-p1","priority":10,"weight":100,"routes":["REALITY","AWG"],"expected_egress_ip":"203.0.113.5","reality":{"address":"203.0.113.5","port":8444,"publicKey":"pub","shortId":"sid"},"awg":{"endpoint":"203.0.113.5:51888","public_key":"awgpub","port":51888}}]}"""

    private fun nestedParamsClientConfig(): String =
        """{"schema":1,"ns":"client-config-v1","seq":2,"issued_at":"2030-01-01T00:00:00Z","expires_at":"2035-01-01T00:00:00Z","workers":[{"worker_id":"worker-nested","label":"Nested","priority":0,"weight":100,"routes":[{"type":"reality","enabled":true,"address":"worker.example","port":2053,"expected_egress_ip":"198.51.100.20","dialect_id":"dialect-1","params":{"public_key":"reality-pub","short_id":"short-id","server_name":"www.microsoft.com","flow":"xtls-rprx-vision","security":"reality","network":"tcp","fingerprint":"firefox"}},{"type":"awg","enabled":true,"address":"worker.example","port":51888,"expected_egress_ip":"198.51.100.20","dialect_id":"dialect-1","params":{"public_key":"awg-server-pub","endpoint":"worker.example:51888","dialect_id":"dialect-1"}}]}]}"""

    private fun regionClientConfig(): String =
        """{"schema":1,"ns":"client-config-v1","seq":12,"issued_at":"2030-01-01T00:00:00Z","expires_at":"2035-01-01T00:00:00Z","workers":[{"worker_id":"worker-region","label":"Region","priority":0,"weight":100,"routes":[{"type":"reality","enabled":true,"address":"worker.example","port":443,"expected_egress_ip":"198.51.100.22","region":"Operator Edge","params":{"public_key":"reality-pub","short_id":"short-id","server_name":"www.microsoft.com","security":"reality","network":"tcp","fingerprint":"chrome"}},{"type":"awg","enabled":true,"address":"worker.example","port":51888,"expected_egress_ip":"198.51.100.22","params":{"public_key":"awg-server-pub","endpoint":"worker.example:51888"}}]}]}"""

    private fun xhttpClientConfig(): String =
        """{"schema":1,"ns":"client-config-v1","seq":3,"issued_at":"2030-01-01T00:00:00Z","expires_at":"2035-01-01T00:00:00Z","workers":[{"worker_id":"worker-xhttp","label":"XHTTP","priority":0,"weight":100,"routes":[{"type":"reality","enabled":true,"address":"worker.example","port":443,"expected_egress_ip":"198.51.100.21","params":{"public_key":"reality-pub","short_id":"short-id","server_name":"www.microsoft.com","flow":"xtls-rprx-vision","security":"reality","network":"xhttp","fingerprint":"chrome","xhttp":{"host":"cdn.operator.example","path":"/operator-path","mode":"auto","extra":{"headers":{"X-Test":"1"}}}}}]}]}"""

    private fun discoveryClientConfig(): String =
        """{"schema":1,"ns":"client-config-v1","seq":9,"issued_at":"2030-01-01T00:00:00Z","expires_at":"2035-01-01T00:00:00Z","discovery_pubkey":"RWQdiscovery","workers":[{"worker_id":"worker-discovery","label":"Discovery","priority":0,"weight":100,"routes":[{"type":"reality","enabled":true,"address":"worker.example","port":443,"expected_egress_ip":"198.51.100.30","params":{"discovery_urls":["https://worker.example/discovery"],"config_url":"http://awg-gw:8080/tw","public_key":"reality-pub","short_id":"sid","server_name":"www.microsoft.com"}}]}]}"""

    private fun discoveryClientConfigWithRescue(): String =
        """{"schema":1,"ns":"client-config-v1","seq":10,"issued_at":"2030-01-01T00:00:00Z","expires_at":"2035-01-01T00:00:00Z","discovery_pubkey":"RWQdiscovery","discovery_rescue_pointers":["https://operator.example/rescue-pointer.json"],"workers":[{"worker_id":"worker-discovery","label":"Discovery","priority":0,"weight":100,"routes":[{"type":"reality","enabled":true,"address":"worker.example","port":443,"expected_egress_ip":"198.51.100.30","params":{"discovery_urls":["https://worker.example/discovery"],"config_url":"http://awg-gw:8080/tw","public_key":"reality-pub","short_id":"sid","server_name":"www.microsoft.com"}}]}]}"""

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
