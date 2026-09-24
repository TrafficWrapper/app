package pro.trafficwrapper

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.lang.reflect.Modifier

class SecureIdentityStoreTest {
    @Test
    fun identityStoreUsesProcessWideLock() {
        // Instances are created ad hoc all over the app, so per-instance @Synchronized is not
        // enough: the store must serialize on a static (companion) lock.
        val lock = SecureIdentityStore::class.java.getDeclaredField("LOCK")
        assertTrue("LOCK must be static", Modifier.isStatic(lock.modifiers))
        val methods = listOf(
            "getOrCreateIdentity",
            "getOrCreateDeviceIdentity",
            "getOrCreateSessionToken",
            "getOrCreatePublicAWGKeyPair",
            "getOrCreateWrappingKey",
        )
        methods.forEach { name ->
            val method = SecureIdentityStore::class.java.declaredMethods.first { it.name == name }
            assertFalse("$name must not rely on the instance monitor", Modifier.isSynchronized(method.modifiers))
        }
    }

    @Test
    fun updatePublicPlatformStateHasAtomicSignature() {
        val method = SecureIdentityStore::class.java.declaredMethods.first { it.name == "updatePublicPlatformState" }
        assertEquals(StoredPublicPlatformState::class.java, method.returnType)
        assertEquals(1, method.parameterTypes.size)
    }

    @Test(expected = IllegalStateException::class)
    fun identityCommitFailureThrows() {
        requireIdentityCommit(committed = false, label = "identity")
    }

    @Test
    fun storedWireGuardKeyPairParsesValidGeneratorOutput() {
        val pair = storedWireGuardKeyPairFromJSON(
            """{"ok":true,"private_key":"priv","public_key":"pub"}""",
            "public awg",
        )

        assertEquals("priv", pair.first)
        assertEquals("pub", pair.second)
    }

    @Test(expected = IllegalStateException::class)
    fun storedWireGuardKeyPairRejectsErrorResult() {
        storedWireGuardKeyPairFromJSON("""{"ok":false,"error":"boom"}""", "public awg")
    }

    @Test(expected = IllegalStateException::class)
    fun storedWireGuardKeyPairRejectsEmptyKeys() {
        storedWireGuardKeyPairFromJSON("""{"ok":true,"private_key":"","public_key":"pub"}""", "public awg")
    }

    @Test
    fun publicAwgKeyPairMigratesLegacyBeforeGenerating() {
        val resolved = resolvePublicAWGKeyPair(
            existing = null,
            legacy = "legacy-private" to "legacy-public",
            generate = { error("generator must not run when legacy keys exist") },
        )

        assertEquals("legacy-private", resolved.privateKey)
        assertEquals("legacy-public", resolved.publicKey)
        assertEquals(PublicAWGKeyPairSource.LEGACY, resolved.source)
        assertTrue(!resolved.newlyCreated)
    }

    @Test
    fun publicAwgKeyPairKeepsExistingSlotOverLegacy() {
        val resolved = resolvePublicAWGKeyPair(
            existing = "new-private" to "new-public",
            legacy = "legacy-private" to "legacy-public",
            generate = { error("generator must not run when existing keys exist") },
        )

        assertEquals("new-private", resolved.privateKey)
        assertEquals("new-public", resolved.publicKey)
        assertEquals(PublicAWGKeyPairSource.EXISTING, resolved.source)
        assertTrue(!resolved.newlyCreated)
    }

    @Test
    fun publicAwgKeyPairGeneratesWhenNoStoredKeysExist() {
        val resolved = resolvePublicAWGKeyPair(
            existing = null,
            legacy = null,
            generate = { "generated-private" to "generated-public" },
        )

        assertEquals("generated-private", resolved.privateKey)
        assertEquals("generated-public", resolved.publicKey)
        assertEquals(PublicAWGKeyPairSource.GENERATED, resolved.source)
        assertTrue(resolved.newlyCreated)
    }

    @Test
    fun publicAwgKeyPairResolutionIsIdempotentAfterMigration() {
        val migrated = resolvePublicAWGKeyPair(
            existing = null,
            legacy = "legacy-private" to "legacy-public",
            generate = { error("generator must not run during migration") },
        )
        val repeated = resolvePublicAWGKeyPair(
            existing = migrated.privateKey to migrated.publicKey,
            legacy = "legacy-private" to "legacy-public",
            generate = { error("generator must not run after migration") },
        )

        assertEquals("legacy-private", repeated.privateKey)
        assertEquals("legacy-public", repeated.publicKey)
        assertEquals(PublicAWGKeyPairSource.EXISTING, repeated.source)
        assertTrue(!repeated.newlyCreated)
    }

    @Test
    fun publicEnrollmentRetryReusesGeneratedAwgKeyPair() {
        val initial = resolvePublicAWGKeyPair(
            existing = null,
            legacy = null,
            generate = { "generated-private" to "generated-public" },
        )
        val retry = resolvePublicAWGKeyPair(
            existing = initial.privateKey to initial.publicKey,
            legacy = null,
            generate = { error("retry must reuse the persisted AWG keypair") },
        )

        assertEquals(initial.privateKey, retry.privateKey)
        assertEquals(initial.publicKey, retry.publicKey)
        assertEquals(PublicAWGKeyPairSource.EXISTING, retry.source)
        assertTrue(!retry.newlyCreated)
    }

    @Test
    fun publicPlatformStateRoundTripsNewFields() {
        val state = StoredPublicPlatformState(
            bootstrapRaw = "{}",
            configPubkeyPin = "pin",
            updatePubkeyPin = "upd",
            maxSeenConfigSeq = 7,
            maxSeenUpdateSeq = 3,
            trustedWallTimeMs = 11,
            trustedElapsedRealtimeMs = 12,
            clientConfigJson = "{\"a\":1}",
            clientBundleJson = "{\"b\":2}",
            deviceID = "device-a",
            realityUUID = "uuid",
            internalIP = "10.0.0.2/32",
            psk2 = "psk",
            serverAWGPublic = "srv",
            awgPrivateKey = "priv",
            awgPublicKey = "pub",
            limitsJson = "{\"devices\":1}",
            awgProfilesJson = "{\"awg-v2\":{\"awg_public_key\":\"k\",\"internal_ip\":\"10.1.0.2/32\",\"psk2\":\"p\"}}",
            realityFlow = REALITY_FLOW_VISION,
            realityFlowKnown = true,
            enrollVersionCode = 42,
        )
        val restored = publicPlatformStateFromJson(org.json.JSONObject(publicPlatformStateToJson(state).toString()))
        assertEquals(state, restored)
        // A known empty flow survives the round trip as "known".
        val emptyFlow = state.copy(realityFlow = "", realityFlowKnown = true)
        assertEquals(emptyFlow, publicPlatformStateFromJson(publicPlatformStateToJson(emptyFlow)))
    }

    @Test
    fun publicPlatformStateReadsJsonWrittenByOlderVersions() {
        val legacy = org.json.JSONObject(
            """{"bootstrap_raw":"{}","config_pubkey_pin":"pin","update_pubkey_pin":"upd","max_seen_config_seq":5,""" +
                """"max_seen_update_seq":2,"trusted_wall_time_ms":1,"trusted_elapsed_realtime_ms":2,""" +
                """"client_config_json":"","client_bundle_json":"bundle","device_id":"device-a","reality_uuid":"uuid",""" +
                """"internal_ip":"10.0.0.2/32","psk2":"psk","server_awg_public":"srv","awg_private_key":"priv",""" +
                """"awg_public_key":"pub","limits_json":""}""",
        )
        val state = publicPlatformStateFromJson(legacy)
        assertEquals("device-a", state.deviceID)
        assertEquals("bundle", state.clientBundleJson)
        assertEquals(5L, state.maxSeenConfigSeq)
        assertEquals("", state.awgProfilesJson)
        assertEquals("", state.realityFlow)
        assertFalse(state.realityFlowKnown)
        assertEquals(0L, state.enrollVersionCode)
        // The old reader's keys are unchanged, so an older app still reads what we write.
        val written = publicPlatformStateToJson(state)
        legacy.keys().forEach { key -> assertTrue(key, written.has(key)) }
    }
}
