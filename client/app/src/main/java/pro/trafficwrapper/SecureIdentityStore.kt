package pro.trafficwrapper

import android.content.Context
import android.content.SharedPreferences
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.util.Base64
import android.util.Log
import org.json.JSONArray
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
    /** Boot the trusted-time anchor belongs to (-1/0 = unknown: the anchor is not reused). */
    val trustedBootCount: Int = -1,
    val trustedBootWallMs: Long = 0,
) {
    /** Update trusted-time anchor (signed manifest time + monotonic delta), or null if unset. */
    val trustedAnchor: TrustedTimeAnchor?
        get() = if (trustedWallTimeMs > 0 && trustedElapsedRealtimeMs > 0) {
            TrustedTimeAnchor(
                wallTimeMs = trustedWallTimeMs,
                elapsedRealtimeMs = trustedElapsedRealtimeMs,
                boot = BootIdentity(trustedBootCount, trustedBootWallMs),
            )
        } else {
            null
        }

    fun withTrustedAnchor(anchor: TrustedTimeAnchor): StoredReleaseState =
        copy(
            trustedWallTimeMs = anchor.wallTimeMs,
            trustedElapsedRealtimeMs = anchor.elapsedRealtimeMs,
            trustedBootCount = anchor.boot.bootCount,
            trustedBootWallMs = anchor.boot.bootWallMs,
        )
}

data class StoredRendezvousState(
    val maxSeenRendezvousSeq: Long = 0,
    val trustedWallTimeMs: Long = 0,
    val trustedElapsedRealtimeMs: Long = 0,
    val lastValidIssuedAtMs: Long = 0,
    val discoverySinks: List<String> = emptyList(),
    /** seq of the signed rendezvous feed that carried [discoverySinks]; 0 = unknown (legacy state). */
    val discoverySinksSeq: Long = 0,
    /** expires_at of that feed; the sinks expire with it. 0 = unknown (legacy state). */
    val discoverySinksExpiresAtMs: Long = 0,
    val trustedBootCount: Int = -1,
    val trustedBootWallMs: Long = 0,
) {
    val trustedAnchor: TrustedTimeAnchor?
        get() = if (trustedWallTimeMs > 0 && trustedElapsedRealtimeMs > 0) {
            TrustedTimeAnchor(
                wallTimeMs = trustedWallTimeMs,
                elapsedRealtimeMs = trustedElapsedRealtimeMs,
                boot = BootIdentity(trustedBootCount, trustedBootWallMs),
            )
        } else {
            null
        }
}

/**
 * Next persisted rendezvous state after a verified bundle. The trusted-time anchor is advanced
 * only from the signed issued_at and the same-boot monotonic extrapolation of the previous
 * anchor; the caller's SNTP-derived wall time is not persisted (APP-M6/M23). Sinks follow
 * [mergeRendezvousSinks] (APP-L25).
 */
internal fun nextRendezvousState(
    current: StoredRendezvousState,
    seq: Long,
    issuedAtMs: Long,
    elapsedRealtimeMs: Long,
    boot: BootIdentity,
    systemNowMs: Long,
    discoverySinks: List<String>,
    discoverySinksExpiresAtMs: Long = 0,
): StoredRendezvousState {
    val anchor = nextTrustedTimeAnchor(
        current = current.trustedAnchor,
        signedIssuedAtMs = issuedAtMs,
        currentBoot = boot,
        currentElapsedRealtimeMs = elapsedRealtimeMs,
        systemNowMs = systemNowMs,
    )
    val (sinks, sinksSeq, sinksExpiresAtMs) =
        mergeRendezvousSinks(current, seq, discoverySinks, discoverySinksExpiresAtMs)
    return StoredRendezvousState(
        maxSeenRendezvousSeq = maxOf(current.maxSeenRendezvousSeq, seq),
        trustedWallTimeMs = anchor.wallTimeMs,
        trustedElapsedRealtimeMs = anchor.elapsedRealtimeMs,
        lastValidIssuedAtMs = maxOf(current.lastValidIssuedAtMs, issuedAtMs),
        discoverySinks = sinks,
        discoverySinksSeq = sinksSeq,
        discoverySinksExpiresAtMs = sinksExpiresAtMs,
        trustedBootCount = anchor.boot.bootCount,
        trustedBootWallMs = anchor.boot.bootWallMs,
    )
}

/**
 * next_sinks inherit seq and expires_at of the signed feed that carried them (APP-L25). A feed
 * with a higher seq is authoritative and replaces the stored list even when it is empty, so the
 * operator can withdraw a sink; re-reading the same seq keeps the stored list. Legacy state (no
 * recorded seq/expiry) is always replaced by the next verified feed.
 */
internal fun mergeRendezvousSinks(
    current: StoredRendezvousState,
    feedSeq: Long,
    feedSinks: List<String>,
    feedExpiresAtMs: Long,
): Triple<List<String>, Long, Long> {
    val legacy = current.discoverySinksExpiresAtMs <= 0L
    return if (legacy || feedSeq > current.discoverySinksSeq) {
        Triple(feedSinks, feedSeq, feedExpiresAtMs)
    } else {
        Triple(current.discoverySinks, current.discoverySinksSeq, current.discoverySinksExpiresAtMs)
    }
}

data class StoredPublicPlatformState(
    val bootstrapRaw: String = "",
    val configPubkeyPin: String = "",
    val updatePubkeyPin: String = "",
    val maxSeenConfigSeq: Long = 0,
    val maxSeenUpdateSeq: Long = 0,
    /**
     * update_pubkey pin that [maxSeenUpdateSeq] was recorded under; the counter does not apply to
     * any other key. Legacy state without the field is read as owned by [updatePubkeyPin]; blank = unknown owner.
     */
    val maxSeenUpdateSeqPin: String = "",
    val trustedWallTimeMs: Long = 0,
    val trustedElapsedRealtimeMs: Long = 0,
    val clientConfigJson: String = "",
    val clientBundleJson: String = "",
    val deviceID: String = "",
    val realityUUID: String = "",
    val internalIP: String = "",
    val psk2: String = "",
    val serverAWGPublic: String = "",
    val awgPrivateKey: String = "",
    val awgPublicKey: String = "",
    val limitsJson: String = "",
    /** Enroll-response awg_profiles (name -> {awg_public_key, internal_ip, psk2}) as JSON. */
    val awgProfilesJson: String = "",
    /** Enroll-response reality_flow; meaningful only when [realityFlowKnown]. */
    val realityFlow: String = "",
    /** True when the enroll response carried reality_flow (an empty flow is still known). */
    val realityFlowKnown: Boolean = false,
    /** BuildConfig.VERSION_CODE of the app that performed the last enrollment (0 = unknown). */
    val enrollVersionCode: Long = 0,
    /**
     * Enroll-response reality_flow_pending (two-phase Vision switch): acknowledged by the next
     * enrollment, applied only once a response reports it as the active reality_flow.
     */
    val realityFlowPending: String = "",
    val realityFlowPendingKnown: Boolean = false,
    /**
     * A bootstrap the user imported, confirmed or refreshed that is not enrolled yet (APP-M12);
     * [bootstrapRaw] stays the bootstrap of the last successful enrollment. Sealed like the rest
     * of the state: no plain SharedPreferences copy is kept (APP-L20).
     */
    val pendingBootstrapRaw: String = "",
    /** The orchestrator confirmed that this device needs approval again (APP-M14). */
    val reauthRequired: Boolean = false,
)

internal fun publicPlatformStateToJson(state: StoredPublicPlatformState): JSONObject =
    JSONObject()
        .put(PPS_BOOTSTRAP_RAW, state.bootstrapRaw)
        .put(PPS_CONFIG_PUBKEY_PIN, state.configPubkeyPin)
        .put(PPS_UPDATE_PUBKEY_PIN, state.updatePubkeyPin)
        .put(PPS_MAX_SEEN_CONFIG_SEQ, state.maxSeenConfigSeq)
        .put(PPS_MAX_SEEN_UPDATE_SEQ, state.maxSeenUpdateSeq)
        .put(PPS_MAX_SEEN_UPDATE_SEQ_PIN, state.maxSeenUpdateSeqPin)
        .put(PPS_TRUSTED_WALL_TIME_MS, state.trustedWallTimeMs)
        .put(PPS_TRUSTED_ELAPSED_REALTIME_MS, state.trustedElapsedRealtimeMs)
        .put(PPS_CLIENT_CONFIG_JSON, state.clientConfigJson)
        .put(PPS_CLIENT_BUNDLE_JSON, state.clientBundleJson)
        .put(PPS_DEVICE_ID, state.deviceID)
        .put(PPS_REALITY_UUID, state.realityUUID)
        .put(PPS_INTERNAL_IP, state.internalIP)
        .put(PPS_PSK2, state.psk2)
        .put(PPS_SERVER_AWG_PUBLIC, state.serverAWGPublic)
        .put(PPS_AWG_PRIVATE_KEY, state.awgPrivateKey)
        .put(PPS_AWG_PUBLIC_KEY, state.awgPublicKey)
        .put(PPS_LIMITS_JSON, state.limitsJson)
        .put(PPS_AWG_PROFILES_JSON, state.awgProfilesJson)
        .put(PPS_REALITY_FLOW, state.realityFlow)
        .put(PPS_REALITY_FLOW_KNOWN, state.realityFlowKnown)
        .put(PPS_ENROLL_VERSION_CODE, state.enrollVersionCode)
        .put(PPS_REALITY_FLOW_PENDING, state.realityFlowPending)
        .put(PPS_REALITY_FLOW_PENDING_KNOWN, state.realityFlowPendingKnown)
        .put(PPS_PENDING_BOOTSTRAP_RAW, state.pendingBootstrapRaw)
        .put(PPS_REAUTH_REQUIRED, state.reauthRequired)

/** Reads a stored public platform state; fields missing in older JSON keep their defaults. */
internal fun publicPlatformStateFromJson(root: JSONObject): StoredPublicPlatformState {
    val updatePubkeyPin = root.optString(PPS_UPDATE_PUBKEY_PIN)
    return StoredPublicPlatformState(
        bootstrapRaw = root.optString(PPS_BOOTSTRAP_RAW),
        configPubkeyPin = root.optString(PPS_CONFIG_PUBKEY_PIN),
        updatePubkeyPin = updatePubkeyPin,
        maxSeenConfigSeq = root.optLong(PPS_MAX_SEEN_CONFIG_SEQ, 0),
        maxSeenUpdateSeq = root.optLong(PPS_MAX_SEEN_UPDATE_SEQ, 0),
        // Legacy state has no owner: the counter was recorded under the key pinned at that time.
        // Fixing the owner on read makes a later in-memory change of updatePubkeyPin (e.g. a signed
        // key rotation in the config poll) reset the rollback floor for the new key.
        maxSeenUpdateSeqPin = if (root.has(PPS_MAX_SEEN_UPDATE_SEQ_PIN)) {
            root.optString(PPS_MAX_SEEN_UPDATE_SEQ_PIN)
        } else {
            updatePubkeyPin
        },
        trustedWallTimeMs = root.optLong(PPS_TRUSTED_WALL_TIME_MS, 0),
        trustedElapsedRealtimeMs = root.optLong(PPS_TRUSTED_ELAPSED_REALTIME_MS, 0),
        clientConfigJson = root.optString(PPS_CLIENT_CONFIG_JSON),
        clientBundleJson = root.optString(PPS_CLIENT_BUNDLE_JSON),
        deviceID = root.optString(PPS_DEVICE_ID),
        realityUUID = root.optString(PPS_REALITY_UUID),
        internalIP = root.optString(PPS_INTERNAL_IP),
        psk2 = root.optString(PPS_PSK2),
        serverAWGPublic = root.optString(PPS_SERVER_AWG_PUBLIC),
        awgPrivateKey = root.optString(PPS_AWG_PRIVATE_KEY),
        awgPublicKey = root.optString(PPS_AWG_PUBLIC_KEY),
        limitsJson = root.optString(PPS_LIMITS_JSON),
        awgProfilesJson = root.optString(PPS_AWG_PROFILES_JSON),
        realityFlow = root.optString(PPS_REALITY_FLOW),
        realityFlowKnown = root.optBoolean(PPS_REALITY_FLOW_KNOWN, false),
        enrollVersionCode = root.optLong(PPS_ENROLL_VERSION_CODE, 0),
        realityFlowPending = root.optString(PPS_REALITY_FLOW_PENDING),
        realityFlowPendingKnown = root.optBoolean(PPS_REALITY_FLOW_PENDING_KNOWN, false),
        pendingBootstrapRaw = root.optString(PPS_PENDING_BOOTSTRAP_RAW),
        reauthRequired = root.optBoolean(PPS_REAUTH_REQUIRED, false),
    )
}

private const val PPS_BOOTSTRAP_RAW = "bootstrap_raw"
private const val PPS_CONFIG_PUBKEY_PIN = "config_pubkey_pin"
private const val PPS_UPDATE_PUBKEY_PIN = "update_pubkey_pin"
private const val PPS_MAX_SEEN_CONFIG_SEQ = "max_seen_config_seq"
private const val PPS_MAX_SEEN_UPDATE_SEQ = "max_seen_update_seq"
private const val PPS_MAX_SEEN_UPDATE_SEQ_PIN = "max_seen_update_seq_pin"
private const val PPS_TRUSTED_WALL_TIME_MS = "trusted_wall_time_ms"
private const val PPS_TRUSTED_ELAPSED_REALTIME_MS = "trusted_elapsed_realtime_ms"
private const val PPS_CLIENT_CONFIG_JSON = "client_config_json"
private const val PPS_CLIENT_BUNDLE_JSON = "client_bundle_json"
private const val PPS_DEVICE_ID = "device_id"
private const val PPS_REALITY_UUID = "reality_uuid"
private const val PPS_INTERNAL_IP = "internal_ip"
private const val PPS_PSK2 = "psk2"
private const val PPS_SERVER_AWG_PUBLIC = "server_awg_public"
private const val PPS_AWG_PRIVATE_KEY = "awg_private_key"
private const val PPS_AWG_PUBLIC_KEY = "awg_public_key"
private const val PPS_LIMITS_JSON = "limits_json"
private const val PPS_AWG_PROFILES_JSON = "awg_profiles_json"
private const val PPS_REALITY_FLOW = "reality_flow"
private const val PPS_REALITY_FLOW_KNOWN = "reality_flow_known"
private const val PPS_ENROLL_VERSION_CODE = "enroll_version_code"
private const val PPS_REALITY_FLOW_PENDING = "reality_flow_pending"
private const val PPS_REALITY_FLOW_PENDING_KNOWN = "reality_flow_pending_known"
private const val PPS_PENDING_BOOTSTRAP_RAW = "pending_bootstrap_raw"
private const val PPS_REAUTH_REQUIRED = "reauth_required"

data class StoredPublicAWGKeyPair(
    val privateKey: String,
    val publicKey: String,
    val newlyCreated: Boolean,
)

internal enum class PublicAWGKeyPairSource {
    EXISTING,
    LEGACY,
    GENERATED,
}

private fun JSONArray?.toStringList(): List<String> {
    if (this == null) return emptyList()
    return List(length()) { index -> optString(index).trim() }.filter { it.isNotBlank() }
}

internal data class PublicAWGKeyPairResolution(
    val privateKey: String,
    val publicKey: String,
    val source: PublicAWGKeyPairSource,
) {
    val newlyCreated: Boolean
        get() = source == PublicAWGKeyPairSource.GENERATED
}

const val TELEMETRY_SIGNATURE_DOMAIN = "TrafficWrapper telemetry v1"

internal fun requireIdentityCommit(committed: Boolean, label: String) {
    if (!committed) {
        throw IllegalStateException("failed to persist $label")
    }
}

internal fun storedWireGuardKeyPairFromJSON(generatedJSON: String, label: String): Pair<String, String> {
    val generated = JSONObject(generatedJSON)
    if (!generated.optBoolean("ok", false)) {
        throw IllegalStateException("$label key generation failed: ${generated.optString("error")}")
    }
    val privateKey = generated.optString("private_key")
    val publicKey = generated.optString("public_key")
    if (privateKey.isBlank() || publicKey.isBlank()) {
        throw IllegalStateException("$label key generation returned empty key")
    }
    return privateKey to publicKey
}

internal fun nonBlankWireGuardKeyPair(privateKey: String, publicKey: String): Pair<String, String>? {
    val normalizedPrivate = privateKey.trim()
    val normalizedPublic = publicKey.trim()
    return if (normalizedPrivate.isNotBlank() && normalizedPublic.isNotBlank()) {
        normalizedPrivate to normalizedPublic
    } else {
        null
    }
}

internal fun resolvePublicAWGKeyPair(
    existing: Pair<String, String>?,
    legacy: Pair<String, String>?,
    generate: () -> Pair<String, String>,
): PublicAWGKeyPairResolution {
    existing?.let {
        return PublicAWGKeyPairResolution(
            privateKey = it.first,
            publicKey = it.second,
            source = PublicAWGKeyPairSource.EXISTING,
        )
    }
    legacy?.let {
        return PublicAWGKeyPairResolution(
            privateKey = it.first,
            publicKey = it.second,
            source = PublicAWGKeyPairSource.LEGACY,
        )
    }
    val generated = generate()
    return PublicAWGKeyPairResolution(
        privateKey = generated.first,
        publicKey = generated.second,
        source = PublicAWGKeyPairSource.GENERATED,
    )
}

/** Why a sealed value could not be opened. */
internal enum class SealedOpenFailure {
    /** Sealed with another wrapping key (AEAD tag mismatch): the state is unreadable for good. */
    FOREIGN_KEY,

    /** The stored envelope itself is broken (not JSON, bad base64, bad IV). */
    MALFORMED,

    /** Anything else (Keystore/StrongBox busy or failing): retry, never reset. */
    TRANSIENT,
}

internal fun classifySealedOpenFailure(error: Throwable): SealedOpenFailure {
    var current: Throwable? = error
    var depth = 0
    while (current != null && depth < 8) {
        if (current is javax.crypto.AEADBadTagException) return SealedOpenFailure.FOREIGN_KEY
        if (current is android.security.keystore.KeyPermanentlyInvalidatedException) return SealedOpenFailure.FOREIGN_KEY
        current = current.cause
        depth++
    }
    return when (error) {
        is org.json.JSONException,
        is IllegalArgumentException,
        is java.security.InvalidAlgorithmParameterException,
        -> SealedOpenFailure.MALFORMED
        else -> SealedOpenFailure.TRANSIENT
    }
}

/** A sealed value exists but cannot be opened right now; the stored state is left untouched. */
class SealedStateUnavailableException(message: String, cause: Throwable?) : IllegalStateException(message, cause)

class SecureIdentityStore(context: Context) {
    private val appContext = context.applicationContext
    private val prefs: SharedPreferences =
        appContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    fun getOrCreateIdentity(generateIdentityJson: () -> String): StoredIdentity {
        return synchronized(LOCK) {
            val keyState = getOrCreateWrappingKey()
            val sealed = prefs.getString(KEY_IDENTITY, null)
            if (sealed != null) {
                val opened = openOrNull(sealed, keyState.key, "identity")
                if (opened != null) {
                    val root = JSONObject(opened)
                    return StoredIdentity(
                        privateKey = root.getString(JSON_PRIVATE_KEY),
                        publicKey = root.getString(JSON_PUBLIC_KEY),
                        newlyCreated = false,
                        strongBoxBacked = keyState.strongBoxBacked,
                    )
                }
                requireIdentityCommit(prefs.edit().remove(KEY_IDENTITY).commit(), "identity reset")
            }

            val generated = JSONObject(generateIdentityJson())
            if (!generated.optBoolean(JSON_OK, false)) {
                throw IllegalStateException("identity generation failed")
            }
            val identity = JSONObject()
                .put(JSON_PRIVATE_KEY, generated.getString(JSON_PRIVATE_KEY))
                .put(JSON_PUBLIC_KEY, generated.getString(JSON_PUBLIC_KEY))
            requireIdentityCommit(
                prefs.edit()
                    .putString(KEY_IDENTITY, seal(identity.toString(), keyState.key))
                    .commit(),
                "identity",
            )
            return StoredIdentity(
                privateKey = identity.getString(JSON_PRIVATE_KEY),
                publicKey = identity.getString(JSON_PUBLIC_KEY),
                newlyCreated = true,
                strongBoxBacked = keyState.strongBoxBacked,
            )
        }
    }

    fun getOrCreateDeviceIdentity(): StoredDeviceIdentity {
        return synchronized(LOCK) {
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
            requireIdentityCommit(
                prefs.edit().putBoolean(KEY_DEVICE_STRONGBOX, generated.strongBoxBacked).commit(),
                "device identity strongbox flag",
            )
            return generated
        }
    }

    fun signDeviceEnrollment(canonicalPayload: String): String = synchronized(LOCK) {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
        keyStore.load(null)
        val privateKey = keyStore.getKey(KEY_DEVICE_IDENTITY_ALIAS, null) as? PrivateKey
            ?: throw IllegalStateException("device identity key missing")
        val signature = Signature.getInstance(ECDSA_SHA256)
        signature.initSign(privateKey)
        signature.update(canonicalPayload.toByteArray(Charsets.UTF_8))
        Base64.encodeToString(signature.sign(), Base64.NO_WRAP)
    }

    /** Serialized with every other Keystore/StrongBox use of the process (StrongBox is single-slot). */
    fun signTelemetry(canonical: String): String = synchronized(LOCK) {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
        keyStore.load(null)
        val privateKey = keyStore.getKey(KEY_DEVICE_IDENTITY_ALIAS, null) as? PrivateKey
            ?: throw IllegalStateException("device identity key missing")
        val signature = Signature.getInstance(ECDSA_SHA256)
        signature.initSign(privateKey)
        signature.update(canonical.toByteArray(Charsets.UTF_8))
        Base64.encodeToString(signature.sign(), Base64.NO_WRAP)
    }

    fun deviceIdentityPublicKey(): String =
        getOrCreateDeviceIdentity().publicKey

    fun getOrCreateSessionToken(): String {
        return synchronized(LOCK) {
            val keyState = getOrCreateWrappingKey()
            val sealed = prefs.getString(KEY_SESSION, null)
            if (sealed != null) {
                val opened = openOrNull(sealed, keyState.key, "session")
                if (opened != null) return opened
                requireIdentityCommit(prefs.edit().remove(KEY_SESSION).commit(), "session reset")
            }
            val tokenBytes = ByteArray(SESSION_TOKEN_BYTES)
            SecureRandom().nextBytes(tokenBytes)
            val token = Base64.encodeToString(tokenBytes, Base64.NO_WRAP)
            requireIdentityCommit(
                prefs.edit().putString(KEY_SESSION, seal(token, keyState.key)).commit(),
                "session",
            )
            return token
        }
    }

    fun getOrCreatePublicAWGKeyPair(generateWireGuardKeyPairJson: () -> String): StoredPublicAWGKeyPair {
        return synchronized(LOCK) {
            val keyState = getOrCreateWrappingKey()
            val sealed = prefs.getString(KEY_PUBLIC_AWG_KEYPAIR, null)
            var existingKeyPair: Pair<String, String>? = null
            if (sealed != null) {
                val opened = openOrNull(sealed, keyState.key, "public awg keypair")
                val existing = opened?.let { runCatching { JSONObject(it) }.getOrNull() }
                if (existing != null) {
                    existingKeyPair = nonBlankWireGuardKeyPair(
                        existing.optString(JSON_PRIVATE_KEY),
                        existing.optString(JSON_PUBLIC_KEY),
                    )
                }
                if (existingKeyPair == null) {
                    requireIdentityCommit(
                        prefs.edit().remove(KEY_PUBLIC_AWG_KEYPAIR).commit(),
                        "public awg keypair reset",
                    )
                }
            }
            val resolved = resolvePublicAWGKeyPair(
                existing = existingKeyPair,
                legacy = readLegacyPublicAWGKeyPair(keyState.key),
                generate = { storedWireGuardKeyPairFromJSON(generateWireGuardKeyPairJson(), "public awg") },
            )
            if (resolved.source != PublicAWGKeyPairSource.EXISTING) {
                writePublicAWGKeyPair(
                    keyState = keyState,
                    privateKey = resolved.privateKey,
                    publicKey = resolved.publicKey,
                    label = if (resolved.source == PublicAWGKeyPairSource.LEGACY) {
                        "public awg keypair migration"
                    } else {
                        "public awg keypair"
                    },
                )
            }
            return StoredPublicAWGKeyPair(
                privateKey = resolved.privateKey,
                publicKey = resolved.publicKey,
                newlyCreated = resolved.newlyCreated,
            )
        }
    }

    fun readReleaseState(): StoredReleaseState = synchronized(LOCK) {
        readReleaseStateLocked(getOrCreateWrappingKey().key)
    }

    fun writeReleaseState(state: StoredReleaseState) {
        synchronized(LOCK) {
            writeReleaseStateLocked(getOrCreateWrappingKey().key, state)
        }
    }

    /** Atomic (process-wide) read-modify-write of the release state; returns the written state. */
    fun updateReleaseState(transform: (StoredReleaseState) -> StoredReleaseState): StoredReleaseState =
        synchronized(LOCK) {
            val key = getOrCreateWrappingKey().key
            val next = transform(readReleaseStateLocked(key))
            writeReleaseStateLocked(key, next)
            next
        }

    fun readPublicPlatformState(): StoredPublicPlatformState = synchronized(LOCK) {
        readPublicPlatformStateLocked(getOrCreateWrappingKey().key)
    }

    fun writePublicPlatformState(state: StoredPublicPlatformState) {
        synchronized(LOCK) {
            writePublicPlatformStateLocked(getOrCreateWrappingKey().key, state)
        }
    }

    /**
     * Atomic read-modify-write of the public platform state. The lock is shared by every
     * SecureIdentityStore instance in the process, so concurrent updaters (activity, service,
     * update worker) cannot lose each other's writes. Returns the state that was persisted.
     */
    fun updatePublicPlatformState(
        transform: (StoredPublicPlatformState) -> StoredPublicPlatformState,
    ): StoredPublicPlatformState = synchronized(LOCK) {
        val key = getOrCreateWrappingKey().key
        val next = transform(readPublicPlatformStateLocked(key))
        writePublicPlatformStateLocked(key, next)
        next
    }

    private fun readReleaseStateLocked(key: SecretKey): StoredReleaseState {
        val sealed = prefs.getString(KEY_RELEASE_STATE, null) ?: return StoredReleaseState()
        val opened = openOrNull(sealed, key, "release state") ?: return StoredReleaseState()
        val root = runCatching { JSONObject(opened) }.getOrNull() ?: return StoredReleaseState()
        return StoredReleaseState(
            maxSeenVersionCode = root.optLong(JSON_MAX_SEEN_VERSION_CODE, 0),
            maxMinSupportedVersion = root.optLong(JSON_MAX_MIN_SUPPORTED_VERSION, 0),
            trustedWallTimeMs = root.optLong(JSON_TRUSTED_WALL_TIME_MS, 0),
            trustedElapsedRealtimeMs = root.optLong(JSON_TRUSTED_ELAPSED_REALTIME_MS, 0),
            trustedBootCount = root.optInt(JSON_TRUSTED_BOOT_COUNT, -1),
            trustedBootWallMs = root.optLong(JSON_TRUSTED_BOOT_WALL_MS, 0),
        )
    }

    private fun writeReleaseStateLocked(key: SecretKey, state: StoredReleaseState) {
        val root = JSONObject()
            .put(JSON_MAX_SEEN_VERSION_CODE, state.maxSeenVersionCode)
            .put(JSON_MAX_MIN_SUPPORTED_VERSION, state.maxMinSupportedVersion)
            .put(JSON_TRUSTED_WALL_TIME_MS, state.trustedWallTimeMs)
            .put(JSON_TRUSTED_ELAPSED_REALTIME_MS, state.trustedElapsedRealtimeMs)
            .put(JSON_TRUSTED_BOOT_COUNT, state.trustedBootCount)
            .put(JSON_TRUSTED_BOOT_WALL_MS, state.trustedBootWallMs)
        if (!prefs.edit().putString(KEY_RELEASE_STATE, seal(root.toString(), key)).commit()) {
            throw IllegalStateException("failed to persist release state")
        }
    }

    private fun readPublicPlatformStateLocked(key: SecretKey): StoredPublicPlatformState {
        val sealed = prefs.getString(KEY_PUBLIC_PLATFORM_STATE, null) ?: return StoredPublicPlatformState()
        val opened = openOrNull(sealed, key, "public platform state") ?: return StoredPublicPlatformState()
        val root = runCatching { JSONObject(opened) }.getOrNull() ?: return StoredPublicPlatformState()
        return publicPlatformStateFromJson(root)
    }

    private fun writePublicPlatformStateLocked(key: SecretKey, state: StoredPublicPlatformState) {
        val root = publicPlatformStateToJson(state)
        if (!prefs.edit().putString(KEY_PUBLIC_PLATFORM_STATE, seal(root.toString(), key)).commit()) {
            throw IllegalStateException("failed to persist public platform state")
        }
    }

    fun readRendezvousState(): StoredRendezvousState {
        return synchronized(LOCK) {
            val keyState = getOrCreateWrappingKey()
            return readRendezvousState(keyState.key)
        }
    }

    /**
     * Persists a verified rendezvous. [trustedWallTimeMs] is accepted for source compatibility
     * but not persisted: it may come from unauthenticated SNTP (APP-M6). The stored anchor is the
     * signed [issuedAtMs] plus the same-boot monotonic delta, see [nextRendezvousState].
     */
    @Suppress("UNUSED_PARAMETER")
    fun recordVerifiedRendezvous(
        seq: Long,
        trustedWallTimeMs: Long,
        trustedElapsedRealtimeMs: Long,
        issuedAtMs: Long,
        discoverySinks: List<String> = emptyList(),
        discoverySinksExpiresAtMs: Long = 0,
    ): StoredRendezvousState {
        return synchronized(LOCK) {
            val keyState = getOrCreateWrappingKey()
            val current = readRendezvousState(keyState.key)
            if (current.maxSeenRendezvousSeq > 0 && seq < current.maxSeenRendezvousSeq) {
                throw IllegalStateException("rendezvous rollback")
            }
            val next = nextRendezvousState(
                current = current,
                seq = seq,
                issuedAtMs = issuedAtMs,
                elapsedRealtimeMs = trustedElapsedRealtimeMs,
                boot = ClockDiagnostics.currentBoot(appContext),
                systemNowMs = System.currentTimeMillis(),
                discoverySinks = discoverySinks,
                discoverySinksExpiresAtMs = discoverySinksExpiresAtMs,
            )
            val root = JSONObject()
                .put(JSON_MAX_SEEN_RENDEZVOUS_SEQ, next.maxSeenRendezvousSeq)
                .put(JSON_TRUSTED_WALL_TIME_MS, next.trustedWallTimeMs)
                .put(JSON_TRUSTED_ELAPSED_REALTIME_MS, next.trustedElapsedRealtimeMs)
                .put(JSON_TRUSTED_BOOT_COUNT, next.trustedBootCount)
                .put(JSON_TRUSTED_BOOT_WALL_MS, next.trustedBootWallMs)
                .put(JSON_LAST_VALID_ISSUED_AT_MS, next.lastValidIssuedAtMs)
                .put(JSON_DISCOVERY_SINKS, JSONArray(next.discoverySinks))
                .put(JSON_DISCOVERY_SINKS_SEQ, next.discoverySinksSeq)
                .put(JSON_DISCOVERY_SINKS_EXPIRES_AT_MS, next.discoverySinksExpiresAtMs)
            if (!prefs.edit().putString(KEY_RENDEZVOUS_STATE, seal(root.toString(), keyState.key)).commit()) {
                throw IllegalStateException("failed to persist rendezvous state")
            }
            return next
        }
    }

    private fun readRendezvousState(key: SecretKey): StoredRendezvousState {
        val sealed = prefs.getString(KEY_RENDEZVOUS_STATE, null) ?: return StoredRendezvousState()
        val opened = openOrNull(sealed, key, "rendezvous state") ?: return StoredRendezvousState()
        val root = runCatching { JSONObject(opened) }.getOrNull() ?: return StoredRendezvousState()
        return StoredRendezvousState(
            maxSeenRendezvousSeq = root.optLong(JSON_MAX_SEEN_RENDEZVOUS_SEQ, 0),
            trustedWallTimeMs = root.optLong(JSON_TRUSTED_WALL_TIME_MS, 0),
            trustedElapsedRealtimeMs = root.optLong(JSON_TRUSTED_ELAPSED_REALTIME_MS, 0),
            lastValidIssuedAtMs = root.optLong(JSON_LAST_VALID_ISSUED_AT_MS, 0),
            discoverySinks = root.optJSONArray(JSON_DISCOVERY_SINKS).toStringList(),
            discoverySinksSeq = root.optLong(JSON_DISCOVERY_SINKS_SEQ, 0),
            discoverySinksExpiresAtMs = root.optLong(JSON_DISCOVERY_SINKS_EXPIRES_AT_MS, 0),
            trustedBootCount = root.optInt(JSON_TRUSTED_BOOT_COUNT, -1),
            trustedBootWallMs = root.optLong(JSON_TRUSTED_BOOT_WALL_MS, 0),
        )
    }

    private fun readLegacyPublicAWGKeyPair(key: SecretKey): Pair<String, String>? {
        val sealed = prefs.getString(KEY_PUBLIC_PLATFORM_STATE, null) ?: return null
        val opened = openOrNull(sealed, key, "legacy public platform state") ?: return null
        val root = runCatching { JSONObject(opened) }.getOrNull() ?: return null
        return nonBlankWireGuardKeyPair(
            root.optString(JSON_AWG_PRIVATE_KEY),
            root.optString(JSON_AWG_PUBLIC_KEY),
        )
    }

    private fun writePublicAWGKeyPair(
        keyState: KeyState,
        privateKey: String,
        publicKey: String,
        label: String,
    ) {
        val root = JSONObject()
            .put(JSON_PRIVATE_KEY, privateKey)
            .put(JSON_PUBLIC_KEY, publicKey)
        requireIdentityCommit(
            prefs.edit()
                .putString(KEY_PUBLIC_AWG_KEYPAIR, seal(root.toString(), keyState.key))
                .commit(),
            label,
        )
    }

    private fun getOrCreateWrappingKey(): KeyState {
        return synchronized(LOCK) {
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
            keyStore.load(null)
            val existing = keyStore.getKey(KEY_ALIAS, null) as? SecretKey
            if (existing != null) {
                return KeyState(existing, prefs.getBoolean(KEY_STRONGBOX, false))
            }
            val orphaned = SEALED_KEYS.filter { prefs.contains(it) }
            if (orphaned.isNotEmpty()) {
                // Sealed data without its Keystore key: the prefs were restored or transferred
                // from another install/device. Everything sealed with the old key is unreadable.
                Log.e(TAG, "wrapping key is missing but sealed state exists (${orphaned.joinToString()}); identity will be regenerated")
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
            requireIdentityCommit(
                prefs.edit().putBoolean(KEY_STRONGBOX, strongBoxKey.strongBoxBacked).commit(),
                "wrapping key strongbox flag",
            )
            return strongBoxKey
        }
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

    /**
     * Opens a sealed value. Returns null only when the value can never be opened: it was sealed
     * with another (foreign or lost) wrapping key (AEAD tag mismatch) or it is malformed; callers
     * then fall back to a fresh state. Any other failure (a transient Keystore/StrongBox error) is
     * retried and then thrown as [SealedStateUnavailableException], so real state is never
     * replaced because of a hiccup.
     */
    private fun openOrNull(sealed: String, key: SecretKey, label: String): String? {
        var lastError: Throwable? = null
        repeat(SEALED_OPEN_ATTEMPTS) { attempt ->
            try {
                return open(sealed, key)
            } catch (error: Exception) {
                when (classifySealedOpenFailure(error)) {
                    SealedOpenFailure.FOREIGN_KEY -> {
                        Log.e(TAG, "failed to decrypt $label: wrapping key missing or foreign; state will be reset", error)
                        return null
                    }
                    SealedOpenFailure.MALFORMED -> {
                        Log.e(TAG, "sealed $label is malformed; state will be reset", error)
                        return null
                    }
                    SealedOpenFailure.TRANSIENT -> {
                        lastError = error
                        Log.w(TAG, "transient failure opening $label (attempt ${attempt + 1}): ${error.javaClass.simpleName}")
                        if (attempt + 1 < SEALED_OPEN_ATTEMPTS) {
                            Thread.sleep(SEALED_OPEN_RETRY_DELAY_MS * (attempt + 1))
                        }
                    }
                }
            }
        }
        throw SealedStateUnavailableException("sealed $label is temporarily unavailable", lastError)
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
        /** Process-wide lock: instances are created ad hoc, so per-instance monitors are not enough. */
        private val LOCK = Any()
        private const val TAG = "SecureIdentityStore"
        private const val PREFS_NAME = "trafficwrapper_secure"
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val KEY_ALIAS = "trafficwrapper_identity_wrap_v1"
        private const val KEY_DEVICE_IDENTITY_ALIAS = "trafficwrapper_device_identity_ec_p256_v1"
        private const val KEY_IDENTITY = "identity"
        private const val KEY_SESSION = "session"
        private const val KEY_RELEASE_STATE = "update_state"
        private const val KEY_RENDEZVOUS_STATE = "rendezvous_state"
        private const val KEY_PUBLIC_PLATFORM_STATE = "public_platform_state"
        private const val KEY_PUBLIC_AWG_KEYPAIR = "public_awg_keypair"
        private const val KEY_STRONGBOX = "strongbox"
        private const val KEY_DEVICE_STRONGBOX = "device_strongbox"
        private val SEALED_KEYS = listOf(
            KEY_IDENTITY,
            KEY_SESSION,
            KEY_RELEASE_STATE,
            KEY_RENDEZVOUS_STATE,
            KEY_PUBLIC_PLATFORM_STATE,
            KEY_PUBLIC_AWG_KEYPAIR,
        )
        private const val AES_GCM = "AES/GCM/NoPadding"
        private const val ECDSA_SHA256 = "SHA256withECDSA"
        private const val EC_P256 = "secp256r1"
        private const val DEVICE_IDENTITY_TYPE = "ecdsa-p256-sha256"
        private const val GCM_TAG_BITS = 128
        private const val SEALED_OPEN_ATTEMPTS = 3
        private const val SEALED_OPEN_RETRY_DELAY_MS = 150L
        private const val SESSION_TOKEN_BYTES = 32

        private const val JSON_OK = "ok"
        private const val JSON_PRIVATE_KEY = "private_key"
        private const val JSON_PUBLIC_KEY = "public_key"
        private const val JSON_IV = "iv"
        private const val JSON_CIPHERTEXT = "ciphertext"
        private const val JSON_MAX_SEEN_VERSION_CODE = "max_seen_version_code"
        private const val JSON_MAX_MIN_SUPPORTED_VERSION = "max_min_supported_version"
        private const val JSON_MAX_SEEN_RENDEZVOUS_SEQ = "max_seen_rendezvous_seq"
        private const val JSON_DISCOVERY_SINKS = "discovery_sinks"
        private const val JSON_DISCOVERY_SINKS_SEQ = "discovery_sinks_seq"
        private const val JSON_DISCOVERY_SINKS_EXPIRES_AT_MS = "discovery_sinks_expires_at_ms"
        private const val JSON_TRUSTED_WALL_TIME_MS = "trusted_wall_time_ms"
        private const val JSON_TRUSTED_ELAPSED_REALTIME_MS = "trusted_elapsed_realtime_ms"
        private const val JSON_LAST_VALID_ISSUED_AT_MS = "last_valid_issued_at_ms"
        private const val JSON_TRUSTED_BOOT_COUNT = "trusted_boot_count"
        private const val JSON_TRUSTED_BOOT_WALL_MS = "trusted_boot_wall_ms"
        private const val JSON_AWG_PRIVATE_KEY = "awg_private_key"
        private const val JSON_AWG_PUBLIC_KEY = "awg_public_key"
    }
}
