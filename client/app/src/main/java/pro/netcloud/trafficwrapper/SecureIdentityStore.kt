package pro.netcloud.trafficwrapper

import android.content.Context
import android.content.SharedPreferences
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.util.Base64
import org.json.JSONObject
import java.security.KeyStore
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

data class StoredIdentity(
    val privateKey: String,
    val publicKey: String,
    val newlyCreated: Boolean,
    val strongBoxBacked: Boolean,
)

data class StoredDeviceIdentity(
    val publicKey: String,
    val keyType: String,
    val newlyCreated: Boolean,
    val strongBoxBacked: Boolean,
)

data class StoredReleaseState(
    val maxSeenVersionCode: Long = 0,
    val maxMinSupportedVersion: Long = 0,
    val trustedWallTimeMs: Long = 0,
    val trustedElapsedRealtimeMs: Long = 0,
)

data class StoredRendezvousState(
    val maxSeenRendezvousSeq: Long = 0,
    val trustedWallTimeMs: Long = 0,
    val trustedElapsedRealtimeMs: Long = 0,
    val lastValidIssuedAtMs: Long = 0,
)

data class StoredPublicPlatformState(
    val bootstrapRaw: String = "",
    val configPubkeyPin: String = "",
    val updatePubkeyPin: String = "",
    val maxSeenConfigSeq: Long = 0,
    val maxSeenUpdateSeq: Long = 0,
    val clientConfigJson: String = "",
    val clientBundleJson: String = "",
    val deviceID: String = "",
    val realityUUID: String = "",
    val internalIP: String = "",
    val psk2: String = "",
    val serverAWGPublic: String = "",
    val awgPrivateKey: String = "",
    val awgPublicKey: String = "",
)

const val TELEMETRY_SIGNATURE_DOMAIN = "TrafficWrapper telemetry v1"

class SecureIdentityStore(context: Context) {
    private val appContext = context.applicationContext
    private val prefs: SharedPreferences =
        appContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    fun getOrCreateIdentity(generateIdentityJson: () -> String): StoredIdentity {
        val keyState = getOrCreateWrappingKey()
        val sealed = prefs.getString(KEY_IDENTITY, null)
        if (sealed != null) {
            val opened = runCatching { open(sealed, keyState.key) }.getOrNull()
            if (opened != null) {
                val root = JSONObject(opened)
                return StoredIdentity(
                    privateKey = root.getString(JSON_PRIVATE_KEY),
                    publicKey = root.getString(JSON_PUBLIC_KEY),
                    newlyCreated = false,
                    strongBoxBacked = keyState.strongBoxBacked,
                )
            }
            prefs.edit().remove(KEY_IDENTITY).apply()
        }

        val generated = JSONObject(generateIdentityJson())
        if (!generated.optBoolean(JSON_OK, false)) {
            throw IllegalStateException("identity generation failed")
        }
        val identity = JSONObject()
            .put(JSON_PRIVATE_KEY, generated.getString(JSON_PRIVATE_KEY))
            .put(JSON_PUBLIC_KEY, generated.getString(JSON_PUBLIC_KEY))
        prefs.edit()
            .putString(KEY_IDENTITY, seal(identity.toString(), keyState.key))
            .apply()
        return StoredIdentity(
            privateKey = identity.getString(JSON_PRIVATE_KEY),
            publicKey = identity.getString(JSON_PUBLIC_KEY),
            newlyCreated = true,
            strongBoxBacked = keyState.strongBoxBacked,
        )
    }

    fun getOrCreateDeviceIdentity(): StoredDeviceIdentity {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
        keyStore.load(null)
        val existing = keyStore.getKey(KEY_DEVICE_IDENTITY_ALIAS, null) as? PrivateKey
        if (existing != null) {
            val certificate = keyStore.getCertificate(KEY_DEVICE_IDENTITY_ALIAS)
                ?: throw IllegalStateException("device identity certificate missing")
            return StoredDeviceIdentity(
                publicKey = Base64.encodeToString(certificate.publicKey.encoded, Base64.NO_WRAP),
                keyType = DEVICE_IDENTITY_TYPE,
                newlyCreated = false,
                strongBoxBacked = prefs.getBoolean(KEY_DEVICE_STRONGBOX, false),
            )
        }
        val generated = if (Build.VERSION.SDK_INT >= 28) {
            runCatching { generateDeviceIdentity(strongBoxBacked = true) }
                .recoverCatching { error ->
                    if (error is StrongBoxUnavailableException || error.cause is StrongBoxUnavailableException) {
                        generateDeviceIdentity(strongBoxBacked = false)
                    } else {
                        throw error
                    }
                }
                .getOrThrow()
        } else {
            generateDeviceIdentity(strongBoxBacked = false)
        }
        prefs.edit().putBoolean(KEY_DEVICE_STRONGBOX, generated.strongBoxBacked).apply()
        return generated
    }

    fun signDeviceEnrollment(canonicalPayload: String): String {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
        keyStore.load(null)
        val privateKey = keyStore.getKey(KEY_DEVICE_IDENTITY_ALIAS, null) as? PrivateKey
            ?: throw IllegalStateException("device identity key missing")
        val signature = Signature.getInstance(ECDSA_SHA256)
        signature.initSign(privateKey)
        signature.update(canonicalPayload.toByteArray(Charsets.UTF_8))
        return Base64.encodeToString(signature.sign(), Base64.NO_WRAP)
    }

    fun signTelemetry(canonical: String): String {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
        keyStore.load(null)
        val privateKey = keyStore.getKey(KEY_DEVICE_IDENTITY_ALIAS, null) as? PrivateKey
            ?: throw IllegalStateException("device identity key missing")
        val signature = Signature.getInstance(ECDSA_SHA256)
        signature.initSign(privateKey)
        signature.update(canonical.toByteArray(Charsets.UTF_8))
        return Base64.encodeToString(signature.sign(), Base64.NO_WRAP)
    }

    fun deviceIdentityPublicKey(): String =
        getOrCreateDeviceIdentity().publicKey

    fun getOrCreateSessionToken(): String {
        val keyState = getOrCreateWrappingKey()
        val sealed = prefs.getString(KEY_SESSION, null)
        if (sealed != null) {
            val opened = runCatching { open(sealed, keyState.key) }.getOrNull()
            if (opened != null) return opened
            prefs.edit().remove(KEY_SESSION).apply()
        }
        val tokenBytes = ByteArray(SESSION_TOKEN_BYTES)
        SecureRandom().nextBytes(tokenBytes)
        val token = Base64.encodeToString(tokenBytes, Base64.NO_WRAP)
        prefs.edit().putString(KEY_SESSION, seal(token, keyState.key)).apply()
        return token
    }

    fun readReleaseState(): StoredReleaseState {
        val keyState = getOrCreateWrappingKey()
        val sealed = prefs.getString(KEY_RELEASE_STATE, null) ?: return StoredReleaseState()
        val opened = runCatching { open(sealed, keyState.key) }.getOrNull() ?: return StoredReleaseState()
        val root = runCatching { JSONObject(opened) }.getOrNull() ?: return StoredReleaseState()
        return StoredReleaseState(
            maxSeenVersionCode = root.optLong(JSON_MAX_SEEN_VERSION_CODE, 0),
            maxMinSupportedVersion = root.optLong(JSON_MAX_MIN_SUPPORTED_VERSION, 0),
            trustedWallTimeMs = root.optLong(JSON_TRUSTED_WALL_TIME_MS, 0),
            trustedElapsedRealtimeMs = root.optLong(JSON_TRUSTED_ELAPSED_REALTIME_MS, 0),
        )
    }

    fun writeReleaseState(state: StoredReleaseState) {
        val keyState = getOrCreateWrappingKey()
        val root = JSONObject()
            .put(JSON_MAX_SEEN_VERSION_CODE, state.maxSeenVersionCode)
            .put(JSON_MAX_MIN_SUPPORTED_VERSION, state.maxMinSupportedVersion)
            .put(JSON_TRUSTED_WALL_TIME_MS, state.trustedWallTimeMs)
            .put(JSON_TRUSTED_ELAPSED_REALTIME_MS, state.trustedElapsedRealtimeMs)
        prefs.edit().putString(KEY_RELEASE_STATE, seal(root.toString(), keyState.key)).apply()
    }

    @Synchronized
    fun readPublicPlatformState(): StoredPublicPlatformState {
        val keyState = getOrCreateWrappingKey()
        val sealed = prefs.getString(KEY_PUBLIC_PLATFORM_STATE, null) ?: return StoredPublicPlatformState()
        val opened = runCatching { open(sealed, keyState.key) }.getOrNull() ?: return StoredPublicPlatformState()
        val root = runCatching { JSONObject(opened) }.getOrNull() ?: return StoredPublicPlatformState()
        return StoredPublicPlatformState(
            bootstrapRaw = root.optString(JSON_BOOTSTRAP_RAW),
            configPubkeyPin = root.optString(JSON_CONFIG_PUBKEY_PIN),
            updatePubkeyPin = root.optString(JSON_UPDATE_PUBKEY_PIN),
            maxSeenConfigSeq = root.optLong(JSON_MAX_SEEN_CONFIG_SEQ, 0),
            maxSeenUpdateSeq = root.optLong(JSON_MAX_SEEN_UPDATE_SEQ, 0),
            clientConfigJson = root.optString(JSON_CLIENT_CONFIG_JSON),
            clientBundleJson = root.optString(JSON_CLIENT_BUNDLE_JSON),
            deviceID = root.optString(JSON_DEVICE_ID),
            realityUUID = root.optString(JSON_REALITY_UUID),
            internalIP = root.optString(JSON_INTERNAL_IP),
            psk2 = root.optString(JSON_PSK2),
            serverAWGPublic = root.optString(JSON_SERVER_AWG_PUBLIC),
            awgPrivateKey = root.optString(JSON_AWG_PRIVATE_KEY),
            awgPublicKey = root.optString(JSON_AWG_PUBLIC_KEY),
        )
    }

    @Synchronized
    fun writePublicPlatformState(state: StoredPublicPlatformState) {
        val keyState = getOrCreateWrappingKey()
        val root = JSONObject()
            .put(JSON_BOOTSTRAP_RAW, state.bootstrapRaw)
            .put(JSON_CONFIG_PUBKEY_PIN, state.configPubkeyPin)
            .put(JSON_UPDATE_PUBKEY_PIN, state.updatePubkeyPin)
            .put(JSON_MAX_SEEN_CONFIG_SEQ, state.maxSeenConfigSeq)
            .put(JSON_MAX_SEEN_UPDATE_SEQ, state.maxSeenUpdateSeq)
            .put(JSON_CLIENT_CONFIG_JSON, state.clientConfigJson)
            .put(JSON_CLIENT_BUNDLE_JSON, state.clientBundleJson)
            .put(JSON_DEVICE_ID, state.deviceID)
            .put(JSON_REALITY_UUID, state.realityUUID)
            .put(JSON_INTERNAL_IP, state.internalIP)
            .put(JSON_PSK2, state.psk2)
            .put(JSON_SERVER_AWG_PUBLIC, state.serverAWGPublic)
            .put(JSON_AWG_PRIVATE_KEY, state.awgPrivateKey)
            .put(JSON_AWG_PUBLIC_KEY, state.awgPublicKey)
        if (!prefs.edit().putString(KEY_PUBLIC_PLATFORM_STATE, seal(root.toString(), keyState.key)).commit()) {
            throw IllegalStateException("failed to persist public platform state")
        }
    }

    @Synchronized
    fun readRendezvousState(): StoredRendezvousState {
        val keyState = getOrCreateWrappingKey()
        return readRendezvousState(keyState.key)
    }

    @Synchronized
    fun recordVerifiedRendezvous(
        seq: Long,
        trustedWallTimeMs: Long,
        trustedElapsedRealtimeMs: Long,
        issuedAtMs: Long,
    ): StoredRendezvousState {
        val keyState = getOrCreateWrappingKey()
        val current = readRendezvousState(keyState.key)
        if (current.maxSeenRendezvousSeq > 0 && seq < current.maxSeenRendezvousSeq) {
            throw IllegalStateException("rendezvous rollback")
        }
        val next = StoredRendezvousState(
            maxSeenRendezvousSeq = maxOf(current.maxSeenRendezvousSeq, seq),
            trustedWallTimeMs = maxOf(current.trustedWallTimeMs, trustedWallTimeMs, issuedAtMs),
            trustedElapsedRealtimeMs = trustedElapsedRealtimeMs,
            lastValidIssuedAtMs = maxOf(current.lastValidIssuedAtMs, issuedAtMs),
        )
        val root = JSONObject()
            .put(JSON_MAX_SEEN_RENDEZVOUS_SEQ, next.maxSeenRendezvousSeq)
            .put(JSON_TRUSTED_WALL_TIME_MS, next.trustedWallTimeMs)
            .put(JSON_TRUSTED_ELAPSED_REALTIME_MS, next.trustedElapsedRealtimeMs)
            .put(JSON_LAST_VALID_ISSUED_AT_MS, next.lastValidIssuedAtMs)
        if (!prefs.edit().putString(KEY_RENDEZVOUS_STATE, seal(root.toString(), keyState.key)).commit()) {
            throw IllegalStateException("failed to persist rendezvous state")
        }
        return next
    }

    private fun readRendezvousState(key: SecretKey): StoredRendezvousState {
        val sealed = prefs.getString(KEY_RENDEZVOUS_STATE, null) ?: return StoredRendezvousState()
        val opened = runCatching { open(sealed, key) }.getOrNull() ?: return StoredRendezvousState()
        val root = runCatching { JSONObject(opened) }.getOrNull() ?: return StoredRendezvousState()
        return StoredRendezvousState(
            maxSeenRendezvousSeq = root.optLong(JSON_MAX_SEEN_RENDEZVOUS_SEQ, 0),
            trustedWallTimeMs = root.optLong(JSON_TRUSTED_WALL_TIME_MS, 0),
            trustedElapsedRealtimeMs = root.optLong(JSON_TRUSTED_ELAPSED_REALTIME_MS, 0),
            lastValidIssuedAtMs = root.optLong(JSON_LAST_VALID_ISSUED_AT_MS, 0),
        )
    }

    private fun getOrCreateWrappingKey(): KeyState {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
        keyStore.load(null)
        val existing = keyStore.getKey(KEY_ALIAS, null) as? SecretKey
        if (existing != null) {
            return KeyState(existing, prefs.getBoolean(KEY_STRONGBOX, false))
        }
        val strongBoxKey = if (Build.VERSION.SDK_INT >= 28) {
            runCatching { generateKey(strongBoxBacked = true) }
                .recoverCatching { error ->
                    if (error is StrongBoxUnavailableException || error.cause is StrongBoxUnavailableException) {
                        generateKey(strongBoxBacked = false)
                    } else {
                        throw error
                    }
                }
                .getOrThrow()
        } else {
            generateKey(strongBoxBacked = false)
        }
        prefs.edit().putBoolean(KEY_STRONGBOX, strongBoxKey.strongBoxBacked).apply()
        return strongBoxKey
    }

    private fun generateKey(strongBoxBacked: Boolean): KeyState {
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        val builder = KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setRandomizedEncryptionRequired(true)
        if (Build.VERSION.SDK_INT >= 28) {
            builder.setIsStrongBoxBacked(strongBoxBacked)
        }
        generator.init(builder.build())
        return KeyState(generator.generateKey(), strongBoxBacked)
    }

    private fun generateDeviceIdentity(strongBoxBacked: Boolean): StoredDeviceIdentity {
        val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE)
        val builder = KeyGenParameterSpec.Builder(
            KEY_DEVICE_IDENTITY_ALIAS,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY,
        )
            .setAlgorithmParameterSpec(ECGenParameterSpec(EC_P256))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setUserAuthenticationRequired(false)
        if (Build.VERSION.SDK_INT >= 28) {
            builder.setIsStrongBoxBacked(strongBoxBacked)
        }
        val pair = generator.run {
            initialize(builder.build())
            generateKeyPair()
        }
        return StoredDeviceIdentity(
            publicKey = Base64.encodeToString(pair.public.encoded, Base64.NO_WRAP),
            keyType = DEVICE_IDENTITY_TYPE,
            newlyCreated = true,
            strongBoxBacked = strongBoxBacked,
        )
    }

    private fun seal(plain: String, key: SecretKey): String {
        val cipher = Cipher.getInstance(AES_GCM)
        cipher.init(Cipher.ENCRYPT_MODE, key)
        val encrypted = cipher.doFinal(plain.toByteArray(Charsets.UTF_8))
        return JSONObject()
            .put(JSON_IV, Base64.encodeToString(cipher.iv, Base64.NO_WRAP))
            .put(JSON_CIPHERTEXT, Base64.encodeToString(encrypted, Base64.NO_WRAP))
            .toString()
    }

    private fun open(sealed: String, key: SecretKey): String {
        val root = JSONObject(sealed)
        val iv = Base64.decode(root.getString(JSON_IV), Base64.NO_WRAP)
        val ciphertext = Base64.decode(root.getString(JSON_CIPHERTEXT), Base64.NO_WRAP)
        val cipher = Cipher.getInstance(AES_GCM)
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, iv))
        return String(cipher.doFinal(ciphertext), Charsets.UTF_8)
    }

    private data class KeyState(
        val key: SecretKey,
        val strongBoxBacked: Boolean,
    )

    private companion object {
        private const val PREFS_NAME = "trafficwrapper_secure"
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val KEY_ALIAS = "trafficwrapper_identity_wrap_v1"
        private const val KEY_DEVICE_IDENTITY_ALIAS = "trafficwrapper_device_identity_ec_p256_v1"
        private const val KEY_IDENTITY = "identity"
        private const val KEY_SESSION = "session"
        private const val KEY_RELEASE_STATE = "update_state"
        private const val KEY_RENDEZVOUS_STATE = "rendezvous_state"
        private const val KEY_PUBLIC_PLATFORM_STATE = "public_platform_state"
        private const val KEY_STRONGBOX = "strongbox"
        private const val KEY_DEVICE_STRONGBOX = "device_strongbox"
        private const val AES_GCM = "AES/GCM/NoPadding"
        private const val ECDSA_SHA256 = "SHA256withECDSA"
        private const val EC_P256 = "secp256r1"
        private const val DEVICE_IDENTITY_TYPE = "ecdsa-p256-sha256"
        private const val GCM_TAG_BITS = 128
        private const val SESSION_TOKEN_BYTES = 32

        private const val JSON_OK = "ok"
        private const val JSON_PRIVATE_KEY = "private_key"
        private const val JSON_PUBLIC_KEY = "public_key"
        private const val JSON_IV = "iv"
        private const val JSON_CIPHERTEXT = "ciphertext"
        private const val JSON_MAX_SEEN_VERSION_CODE = "max_seen_version_code"
        private const val JSON_MAX_MIN_SUPPORTED_VERSION = "max_min_supported_version"
        private const val JSON_MAX_SEEN_RENDEZVOUS_SEQ = "max_seen_rendezvous_seq"
        private const val JSON_MAX_SEEN_CONFIG_SEQ = "max_seen_config_seq"
        private const val JSON_MAX_SEEN_UPDATE_SEQ = "max_seen_update_seq"
        private const val JSON_TRUSTED_WALL_TIME_MS = "trusted_wall_time_ms"
        private const val JSON_TRUSTED_ELAPSED_REALTIME_MS = "trusted_elapsed_realtime_ms"
        private const val JSON_LAST_VALID_ISSUED_AT_MS = "last_valid_issued_at_ms"
        private const val JSON_BOOTSTRAP_RAW = "bootstrap_raw"
        private const val JSON_CONFIG_PUBKEY_PIN = "config_pubkey_pin"
        private const val JSON_UPDATE_PUBKEY_PIN = "update_pubkey_pin"
        private const val JSON_CLIENT_CONFIG_JSON = "client_config_json"
        private const val JSON_CLIENT_BUNDLE_JSON = "client_bundle_json"
        private const val JSON_DEVICE_ID = "device_id"
        private const val JSON_REALITY_UUID = "reality_uuid"
        private const val JSON_INTERNAL_IP = "internal_ip"
        private const val JSON_PSK2 = "psk2"
        private const val JSON_SERVER_AWG_PUBLIC = "server_awg_public"
        private const val JSON_AWG_PRIVATE_KEY = "awg_private_key"
        private const val JSON_AWG_PUBLIC_KEY = "awg_public_key"
    }
}
