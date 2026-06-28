package pro.trafficwrapper

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.lang.reflect.Modifier

class SecureIdentityStoreTest {
    @Test
    fun identityCreationMethodsAreSynchronized() {
        val methods = listOf(
            "getOrCreateIdentity",
            "getOrCreateDeviceIdentity",
            "getOrCreateSessionToken",
            "getOrCreatePublicAWGKeyPair",
            "getOrCreateWrappingKey",
        )

        methods.forEach { name ->
            val method = SecureIdentityStore::class.java.declaredMethods.first { it.name == name }
            assertTrue("$name must be synchronized", Modifier.isSynchronized(method.modifiers))
        }
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
}
