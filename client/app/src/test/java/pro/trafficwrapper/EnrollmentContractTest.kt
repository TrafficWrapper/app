package pro.trafficwrapper

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException
import java.time.Instant

/**
 * Contract tests for enrollment codes, flow acknowledgement, route alternatives and version gates
 * against static fixtures of an older orchestrator (no code / nested alternatives / pending flow)
 * and of the new one.
 */
class EnrollmentContractTest {
    // ---- Derived version code (units of min_version_code / fingerprint gates) ----

    @Test
    fun derivedVersionCodeComesFromVersionName() {
        assertEquals(131L, derivedClientVersionCode("0.1.31"))
        assertEquals(128L, derivedClientVersionCode("0.1.28"))
        assertEquals(10203L, derivedClientVersionCode("1.2.3-debug"))
        assertEquals(200L, derivedClientVersionCode("0.2"))
        assertEquals(0L, derivedClientVersionCode("dev"))
        // Not the Android versionCode (31 by default).
        assertNotEquals(BuildConfig.VERSION_CODE.toLong(), derivedClientVersionCode(BuildConfig.VERSION_NAME))
    }

    @Test
    fun capabilitiesAnnounceAlternativesAndFlowAck() {
        assertTrue("route_alternatives_v1" in PUBLIC_CLIENT_CAPABILITIES)
        assertTrue("reality_flow_ack" in PUBLIC_CLIENT_CAPABILITIES)
    }

    // ---- Structured enroll codes (APP-L22/L23) ----

    @Test
    fun structuredCodesDecideTheKind() {
        fun kind(code: String, message: String = "public device enrollment rejected: x") =
            publicEnrollmentFailurePolicy(PublicEnrollmentRejectedException(code, authenticated = true, message = message)).kind

        assertEquals(PublicEnrollmentFailureKind.PENDING, kind("device_not_approved"))
        assertEquals(PublicEnrollmentFailureKind.BLOCKED, kind("device_revoked"))
        for (code in listOf("token_invalid", "token_expired", "token_exhausted", "identity_mismatch", "noise_mismatch", "awg_key_mismatch")) {
            assertEquals(code, PublicEnrollmentFailureKind.TERMINAL, kind(code))
        }
        assertEquals(PublicEnrollmentFailureKind.TRANSIENT, kind("no_worker"))
        assertEquals(PublicEnrollmentFailureKind.TRANSIENT, kind("retry", "public device enrollment rejected: bootstrap token race"))
        // Unknown future code: retryable, never TERMINAL.
        assertEquals(PublicEnrollmentFailureKind.TRANSIENT, kind("something_new", "public device enrollment rejected: signature"))
        // Old orchestrator (no code): text fallback, e.g. a revoked device is BLOCKED.
        assertEquals(
            PublicEnrollmentFailureKind.BLOCKED,
            publicEnrollmentFailurePolicy(PublicEnrollmentRejectedException("", true, "public device enrollment rejected: device revoked")).kind,
        )
    }

    @Test
    fun unauthenticatedCarrierTextNeverDecidesTheState() {
        val onPath = IllegalStateException("http 403: unauthenticated server response: device is not approved; device revoked")
        val policy = publicEnrollmentFailurePolicy(onPath)
        assertEquals(PublicEnrollmentFailureKind.TRANSIENT, policy.kind)
        assertTrue(policy.retryAllowed)
        // Even a "code" smuggled outside Noise is ignored.
        val smuggled = PublicEnrollmentRejectedException("device_revoked", authenticated = false, message = "unauthenticated server response: x")
        assertEquals(PublicEnrollmentFailureKind.TRANSIENT, publicEnrollmentFailurePolicy(smuggled).kind)
        assertNull(authenticatedPublicEnrollmentKind(smuggled))
        assertNull(authenticatedPublicEnrollmentKind(IOException("reset")))
        assertEquals(
            PublicEnrollmentFailureKind.PENDING,
            authenticatedPublicEnrollmentKind(PublicEnrollmentRejectedException("device_not_approved", true, "x")),
        )
    }

    // ---- Clock skew (APP-L27) ----

    @Test
    fun bootstrapExpiryToleratesSkewAndIsRetryable() {
        val expires = "2030-01-01T00:00:00Z"
        val expiresMs = Instant.parse(expires).toEpochMilli()
        // Within the tolerance: accepted.
        PublicPlatformConfigParser.parseBootstrap(bootstrap(expires), nowMs = expiresMs + PUBLIC_CLOCK_SKEW_TOLERANCE_MS - 1)
        val error = runCatching {
            PublicPlatformConfigParser.parseBootstrap(bootstrap(expires), nowMs = expiresMs + 25 * 3_600_000L)
        }.exceptionOrNull()
        assertTrue(error is PublicClockSkewException)
        val policy = publicEnrollmentFailurePolicy(error!!)
        assertEquals(PublicEnrollmentFailureKind.TRANSIENT, policy.kind)
        assertTrue(policy.retryAllowed)
        assertEquals(R.string.public_enrollment_error_clock, policy.errorTextRes)
        // nowMs = 0 (re-enrollment of a known device) skips the check as before.
        PublicPlatformConfigParser.parseBootstrap(bootstrap("2000-01-01T00:00:00Z"), nowMs = 0L)
    }

    // ---- Bootstrap SPKI pins (APP-L36) ----

    @Test
    fun bootstrapSpkiPinsAreOptional() {
        assertEquals(emptyList<String>(), PublicPlatformConfigParser.parseBootstrap(bootstrap("2035-01-01T00:00:00Z"), nowMs = 0L).orchTlsSpkiSha256)
        val pinned = JSONObject(bootstrap("2035-01-01T00:00:00Z"))
            .put("orch_tls_spki_sha256", JSONArray().put("aa".repeat(32)).put(" ").put(7).put("bb".repeat(32)))
        assertEquals(
            listOf("aa".repeat(32), "bb".repeat(32)),
            PublicPlatformConfigParser.parseBootstrap(pinned.toString(), nowMs = 0L).orchTlsSpkiSha256,
        )
    }

    // ---- ANDROID_ID hint (APP-L19) ----

    @Test
    fun deviceHintIsPerPlatformAndHidesAndroidId() {
        val a = publicDeviceHint("9774d56d682e549c", "RWQ-platform-a")
        val b = publicDeviceHint("9774d56d682e549c", "RWQ-platform-b")
        assertTrue(a.startsWith("h1_"))
        assertEquals(35, a.length)
        assertFalse(a.contains("9774d56d682e549c"))
        assertNotEquals(a, b)
        assertEquals(a, publicDeviceHint("9774d56d682e549c", "RWQ-platform-a"))
        assertEquals("", publicDeviceHint("", "RWQ-platform-a"))
    }

    // ---- Two-phase Vision flow (X-L13) ----

    @Test
    fun pendingFlowIsAcknowledgedAndNotAppliedEarly() {
        val pending = StoredPublicPlatformState(
            configPubkeyPin = "pin",
            realityFlow = "",
            realityFlowKnown = true,
            realityFlowPending = REALITY_FLOW_VISION,
            realityFlowPendingKnown = true,
        )
        assertEquals(REALITY_FLOW_VISION, publicEnrollFlowAck(pending, "pin"))
        assertNull(publicEnrollFlowAck(pending, "other-platform"))
        assertTrue(publicFlowAckNeeded(pending))
        // Old orchestrator: no pending, no ack.
        val legacy = pending.copy(realityFlowPending = "", realityFlowPendingKnown = false)
        assertNull(publicEnrollFlowAck(legacy, "pin"))
        assertFalse(publicFlowAckNeeded(legacy))
        // Active already equals the pending flow: nothing left to acknowledge.
        assertFalse(publicFlowAckNeeded(pending.copy(realityFlow = REALITY_FLOW_VISION)))

        // The active flow ("") drives the primary variant; the pending flow is only the fallback.
        val slots = PublicPlatformConfigParser.routeSlots(
            parseConfig(newOrchestratorBundle()),
            "device-a",
            pending.copy(deviceID = "device-a", realityUUID = UUID).toPublicPlatformCredentials(),
        )
        assertEquals("", slots.reality?.flow)
        assertEquals(REALITY_FLOW_VISION, slots.realityVariants[1].config.flow)
        val noPending = PublicPlatformConfigParser.routeSlots(
            parseConfig(newOrchestratorBundle()),
            "device-a",
            legacy.copy(deviceID = "device-a", realityUUID = UUID).toPublicPlatformCredentials(),
        )
        assertTrue(noPending.realityVariants.none { it.config.flow == REALITY_FLOW_VISION })
    }

    @Test
    fun storedStateKeepsPendingFlow() {
        val state = StoredPublicPlatformState(realityFlowPending = REALITY_FLOW_VISION, realityFlowPendingKnown = true)
        val restored = publicPlatformStateFromJson(publicPlatformStateToJson(state))
        assertEquals(REALITY_FLOW_VISION, restored.realityFlowPending)
        assertTrue(restored.realityFlowPendingKnown)
        val legacy = publicPlatformStateFromJson(JSONObject().put("device_id", "d"))
        assertFalse(legacy.realityFlowPendingKnown)
    }

    // ---- AWG profiles and nested alternatives (X-M4) ----

    @Test
    fun oldOrchestratorRouteOnForeignProfileIsSkippedWithoutCredentials() {
        val config = parseConfig(oldOrchestratorBundle())
        val withoutProfiles = credentials(awgProfiles = emptySet())
        val slots = PublicPlatformConfigParser.routeSlots(config, "device-a", withoutProfiles)
        // The awg2 route of worker-a is skipped; worker-b's base AWG route takes the slot.
        assertEquals("b.example", slots.awgRu?.address)
        assertEquals(setOf("awg2"), PublicPlatformConfigParser.missingAwgProfileCredentials(config, withoutProfiles))

        val withProfiles = credentials(awgProfiles = setOf("awg2"))
        assertEquals("a.example", PublicPlatformConfigParser.routeSlots(config, "device-a", withProfiles).awgRu?.address)
        assertTrue(PublicPlatformConfigParser.missingAwgProfileCredentials(config, withProfiles).isEmpty())
        // Unknown credentials (legacy callers): unchanged selection, nothing reported missing.
        assertEquals("a.example", PublicPlatformConfigParser.routeSlots(config, "device-a", credentials(awgProfiles = null)).awgRu?.address)
    }

    @Test
    fun nestedAwgAlternativesNeedCredentialsAndVersion() {
        val config = parseConfig(newOrchestratorBundle())
        // Base route only: no credentials for awg2, and awg3 requires a newer build.
        val base = PublicPlatformConfigParser.routeSlots(config, "device-a", credentials(awgProfiles = emptySet(), versionCode = 131))
        assertEquals(listOf("worker-a|awg|awg|v4|"), base.awgRuVariants.map { it.key })
        assertEquals(setOf("awg2"), PublicPlatformConfigParser.missingAwgProfileCredentials(config, credentials(awgProfiles = emptySet(), versionCode = 131)))

        val creds = credentials(awgProfiles = setOf("awg2", "awg3"), versionCode = 131)
        val slots = PublicPlatformConfigParser.routeSlots(config, "device-a", creds)
        assertEquals(
            listOf("worker-a|awg|awg|v4|", "worker-a|awg2|awg|v4|", "worker-a|awg2|awg|v6|"),
            slots.awgRuVariants.map { it.key },
        )
        val alt = slots.awgRuVariants[1].route
        assertEquals(51822, alt.port)
        assertEquals("awg2", alt.params.getString("awg_profile"))
        assertEquals("pk-awg2", alt.params.getString("public_key"))
        assertFalse(alt.params.has("awg_profiles"))
        // The primary route stays byte-for-byte what older apps use.
        assertEquals(51820, slots.awgRu?.port)

        val newer = PublicPlatformConfigParser.routeSlots(config, "device-a", creds.copy(clientVersionCode = 200))
        assertTrue(newer.awgRuVariants.any { it.key == "worker-a|awg3|awg|v4|" })

        // The core request follows the selected alternative, falling back to the primary route.
        val stored = StoredPublicPlatformState(
            deviceID = "device-a", internalIP = "10.0.0.2/32", psk2 = "p", serverAWGPublic = "s", awgPrivateKey = "k",
        )
        val primary = publicCoreApplyRequest(stored, config, slots, "a", "b", awgRuFamily = "", awgFamily = "", awgRuVariantKey = "", awgVariantKey = "")
        assertEquals(51820, primary.getJSONObject("awg_ru").getInt("port"))
        val key = awgVariantSelectionKey(slots.awgRuVariants[1], slots.awgRu)
        val selected = publicCoreApplyRequest(stored, config, slots, "a", "b", awgRuFamily = "", awgFamily = "", awgRuVariantKey = key, awgVariantKey = "")
        assertEquals(51822, selected.getJSONObject("awg_ru").getInt("port"))
        assertEquals("awg2", selected.getJSONObject("awg_ru").getString("awg_profile"))
        assertEquals("", awgVariantSelectionKey(slots.awgRuVariants[0], slots.awgRu))
        val stale = publicCoreApplyRequest(stored, config, slots, "a", "b", awgRuFamily = "", awgFamily = "", awgRuVariantKey = "gone", awgVariantKey = "")
        assertEquals(51820, stale.getJSONObject("awg_ru").getInt("port"))
    }

    @Test
    fun oldOrchestratorBundleWithoutNestedListsKeepsPrimaryOnly() {
        val slots = PublicPlatformConfigParser.routeSlots(parseConfig(oldOrchestratorBundle()), "device-a", credentials(awgProfiles = setOf("awg2")))
        assertEquals(1, slots.awgRuVariants.size)
    }

    @Test
    fun profileCredentialNamesNeedCompleteEntries() {
        val json = JSONObject()
            .put("awg2", JSONObject().put("internal_ip", "10.1.0.2/32").put("psk2", "p"))
            .put("awg3", JSONObject().put("internal_ip", "10.2.0.2/32"))
        assertEquals(setOf("awg2"), publicAwgProfileNames(json.toString()))
        assertEquals(emptySet<String>(), publicAwgProfileNames(""))
        assertEquals(emptySet<String>(), publicAwgProfileNames("{broken"))
    }

    // ---- fingerprint_modern ----

    @Test
    fun modernFingerprintNeedsDerivedVersion() {
        val params = JSONObject().put("fingerprint", "chrome").put("fingerprint_modern", "firefox")
            .put("fingerprint_modern_min_version_code", 131)
        assertEquals("firefox", realityFingerprintFor(params, 131))
        assertEquals("chrome", realityFingerprintFor(params, 130))
        // Units are the derived code: Android versionCode 31 is below the gate.
        assertEquals("chrome", realityFingerprintFor(params, 31))
        assertEquals("chrome", realityFingerprintFor(JSONObject().put("fingerprint_modern", "firefox"), 131))
        assertEquals("chrome", realityFingerprintFor(JSONObject(), 131))
        val slots = PublicPlatformConfigParser.routeSlots(parseConfig(newOrchestratorBundle()), "device-a", credentials(awgProfiles = emptySet(), versionCode = 131))
        assertEquals("firefox", slots.reality?.fingerprint)
        val older = PublicPlatformConfigParser.routeSlots(parseConfig(newOrchestratorBundle()), "device-a", credentials(awgProfiles = emptySet(), versionCode = 128))
        assertEquals("chrome", older.reality?.fingerprint)
    }

    // ---- Backoff, throttle and background plan (APP-M4, APP-L8) ----

    @Test
    fun backoffGrowsAndResets() {
        val backoff = PublicEnrollmentBackoff(minDelayMs = 1_000L, maxDelayMs = 4_000L)
        assertEquals(0L, backoff.remainingMs(100L))
        backoff.onFailure(0L)
        assertEquals(1_000L, backoff.remainingMs(0L))
        backoff.onFailure(1_000L)
        assertEquals(2_000L, backoff.remainingMs(1_000L))
        backoff.onFailure(3_000L)
        backoff.onFailure(7_000L)
        assertEquals(4_000L, backoff.remainingMs(7_000L))
        backoff.onSuccess()
        assertEquals(0L, backoff.remainingMs(7_000L))
    }

    @Test
    fun reauthConfirmationIsThrottled() {
        val throttle = PublicReauthConfirmThrottle(intervalMs = 1_000L)
        assertTrue(throttle.tryAcquire(10_000L))
        assertFalse(throttle.tryAcquire(10_500L))
        assertTrue(throttle.tryAcquire(11_000L))
    }

    @Test
    fun backgroundReEnrollRunsThroughTheTunnelOnly() {
        val version = setOf(PublicReEnrollReason.VERSION_REFRESH)
        assertEquals(PublicReEnrollPlan.Idle, publicReEnrollPlan(emptySet(), tunnelUp = true, backoffRemainingMs = 0))
        assertEquals(PublicReEnrollPlan.Run(viaTunnel = true), publicReEnrollPlan(version, tunnelUp = true, backoffRemainingMs = 0))
        // No tunnel: wait for it instead of going direct.
        assertEquals(PublicReEnrollPlan.Wait(PUBLIC_REENROLL_CHECK_INTERVAL_MS), publicReEnrollPlan(version, tunnelUp = false, backoffRemainingMs = 0))
        assertEquals(PublicReEnrollPlan.Wait(5_000L), publicReEnrollPlan(version, tunnelUp = true, backoffRemainingMs = 5_000L))
        assertEquals(
            PublicReEnrollPlan.Wait(PUBLIC_REENROLL_CHECK_INTERVAL_MS),
            publicReEnrollPlan(setOf(PublicReEnrollReason.FLOW_ACK, PublicReEnrollReason.AWG_PROFILE_CREDENTIALS), tunnelUp = false, backoffRemainingMs = 0),
        )
        // A revoked device has no tunnel: confirming the hint may go direct.
        assertEquals(
            PublicReEnrollPlan.Run(viaTunnel = false),
            publicReEnrollPlan(setOf(PublicReEnrollReason.REAUTH_CONFIRM), tunnelUp = false, backoffRemainingMs = 0),
        )
    }

    // ---- fixtures ----

    private fun credentials(awgProfiles: Set<String>?, versionCode: Long = 131): PublicPlatformCredentials =
        PublicPlatformCredentials(
            deviceID = "device-a",
            realityUUID = UUID,
            internalIP = "10.13.13.2/32",
            psk2 = "psk",
            serverAWGPublic = "server",
            awgPrivateKey = "private",
            awgPublicKey = "public",
            awgProfileNames = awgProfiles,
            clientVersionCode = versionCode,
        )

    private fun parseConfig(configJson: String): PublicClientConfig =
        PublicPlatformConfigParser.verifyAndParseClientConfig(
            envelopeRaw = JSONObject().put("config_json", configJson).put("minisig", "sig").toString(),
            expectedPublicKey = PUBLIC_KEY,
            maxSeenSeq = 0,
            verifier = object : PublicMinisignVerifier {
                override fun verify(message: String, signature: String, publicKey: String): Boolean = true
            },
            nowMs = 0,
        )

    private fun bootstrap(expires: String): String =
        """{"orchestrator_url":"https://orch.dev","config_pubkey_pin":"$PUBLIC_KEY","orch_noise_public":"n","bootstrap_token":"t","expires":"$expires"}"""

    /** Older orchestrator: route-level AWG fallback onto profile awg2, no nested lists, no code. */
    private fun oldOrchestratorBundle(): String {
        val awgA = JSONObject().put("type", "awg").put("enabled", true).put("address", "a.example").put("port", 51821)
            .put("egress_ip", "198.51.100.1")
            .put("params", JSONObject().put("public_key", "pk-a").put("profile", "awg2").put("awg_profile", "awg2"))
        val awgB = JSONObject().put("type", "awg").put("enabled", true).put("address", "b.example").put("port", 51820)
            .put("egress_ip", "198.51.100.2").put("params", JSONObject().put("public_key", "pk-b"))
        return bundle(
            JSONArray()
                .put(JSONObject().put("worker_id", "worker-a").put("priority", 0).put("weight", 100).put("routes", JSONArray().put(awgA)))
                .put(JSONObject().put("worker_id", "worker-b").put("priority", 1).put("weight", 100).put("routes", JSONArray().put(awgB))),
        )
    }

    /** New orchestrator: base AWG + nested params.awg_profiles, REALITY with fingerprint_modern. */
    private fun newOrchestratorBundle(): String {
        val nested = JSONArray()
            .put(JSONObject().put("profile", "awg").put("port", 51820).put("public_key", "pk-base"))
            .put(
                JSONObject().put("profile", "awg2").put("port", 51822).put("endpoint", "a.example:51822")
                    .put("endpoint_v6", "[2001:db8::2]:51822").put("public_key", "pk-awg2")
                    .put("awg_preset", JSONObject().put("jc", 4)).put("min_version_code", 131),
            )
            .put(JSONObject().put("profile", "awg3").put("port", 51823).put("public_key", "pk-awg3").put("min_version_code", 200))
        val awg = JSONObject().put("type", "awg").put("enabled", true).put("address", "a.example").put("port", 51820)
            .put("egress_ip", "198.51.100.1")
            .put("params", JSONObject().put("public_key", "pk-base").put("profile", "awg").put("awg_profiles", nested))
        val reality = JSONObject().put("type", "reality").put("enabled", true).put("address", "a.example").put("port", 443)
            .put("egress_ip", "198.51.100.1")
            .put(
                "params",
                JSONObject().put("public_key", "rpk").put("short_id", "sid").put("server_name", "sni.example")
                    .put("network", "tcp").put("vision", true).put("fingerprint", "chrome")
                    .put("fingerprint_modern", "firefox").put("fingerprint_modern_min_version_code", 131),
            )
        return bundle(
            JSONArray().put(
                JSONObject().put("worker_id", "worker-a").put("priority", 0).put("weight", 100)
                    .put("routes", JSONArray().put(reality).put(awg)),
            ),
        )
    }

    private fun bundle(workers: JSONArray): String =
        JSONObject().put("schema", 1).put("ns", "client-config-v1").put("seq", 7)
            .put("issued_at", "2030-01-01T00:00:00Z").put("expires_at", "2035-01-01T00:00:00Z")
            .put("workers", workers).toString()

    private companion object {
        const val PUBLIC_KEY = "RWQ-test-key"
        const val UUID = "11111111-1111-4111-8111-111111111111"
    }
}
