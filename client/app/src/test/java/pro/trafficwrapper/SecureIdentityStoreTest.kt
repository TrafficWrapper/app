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
}
