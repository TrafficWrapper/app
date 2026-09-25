package pro.trafficwrapper

import android.content.Context
import android.content.pm.PackageInfo
import android.os.Build
import android.os.SystemClock
import android.util.Log
import com.android.apksig.ApkVerifier
import org.json.JSONObject
import pro.trafficwrapper.go.transport.Transport
import java.io.File
import java.security.MessageDigest
import java.time.Instant
import kotlin.math.max
import kotlin.math.min

internal const val UPDATE_MAX_FUTURE_TIMESTAMP_MS = 24 * 60 * 60 * 1000L

internal fun selectTrustedUpdateTime(
    monotonic: TrustedTimeResult?,
    sntp: TrustedTimeResult?,
    maxSntpForwardMs: Long = UPDATE_MAX_FUTURE_TIMESTAMP_MS,
): TrustedTimeResult? {
    if (sntp == null) return monotonic
    if (monotonic == null) return sntp
    if (sntp.wallTimeMs <= monotonic.wallTimeMs) return monotonic
    val clampedWallTimeMs = min(sntp.wallTimeMs, monotonic.wallTimeMs + maxSntpForwardMs)
    return sntp.copy(wallTimeMs = clampedWallTimeMs)
}

/**
 * Canonical form of a certificate SHA-256 pin: no colons or whitespace, lower-case hex. Accepts
 * the keytool form (`AB:CD:...`) so a pin copied from keytool does not break self-update.
 */
internal fun normalizeCertSha256(value: String): String =
    value.filterNot { it == ':' || it.isWhitespace() }.lowercase()

/**
 * Parses an `apk-update-v1` manifest (snake_case as written by the orchestrator's
 * buildAPKManifest and make-manifest.sh, camelCase kept for older manifests). A missing or empty
 * `signing_cert_sha256` means "the certificate pinned into this build" ([pinnedSigningCertSha256]).
 */
internal fun parseUpdateManifest(raw: String, pinnedSigningCertSha256: String): UpdateManifest {
    val root = try {
        JSONObject(raw)
    } catch (_: Throwable) {
        throw UpdateVerificationException(R.string.update_error_manifest)
    }
    return try {
        val versionCode = root.optLong(JSON_VERSION_CODE).takeIf { it > 0 }
            ?: root.getLong(JSON_VERSION_CODE_CAMEL)
        val signingCert = if (root.isNull(JSON_SIGNING_CERT_SHA256)) {
            ""
        } else {
            normalizeCertSha256(root.optString(JSON_SIGNING_CERT_SHA256))
        }
        UpdateManifest(
            schema = root.getInt(JSON_SCHEMA),
            namespace = root.getString(JSON_NS),
            seq = root.getLong(JSON_SEQ),
            versionCode = versionCode,
            versionName = root.optString(JSON_VERSION_NAME).ifBlank {
                root.getString(JSON_VERSION_NAME_CAMEL)
            },
            apkUrl = root.optString(JSON_APK_URL).ifBlank {
                root.optString(JSON_APK_NAME, "app-public-$versionCode.apk")
            },
            apkSize = root.optLong(JSON_APK_SIZE).takeIf { it > 0 }
                ?: root.getLong(JSON_APK_SIZE_CAMEL),
            sha256 = root.optString(JSON_APK_SHA256).ifBlank {
                root.getString(JSON_SHA256)
            },
            signingCertSha256 = signingCert.ifBlank { normalizeCertSha256(pinnedSigningCertSha256) },
            minSupportedVersion = root.optLong(JSON_MIN_VERSION, 0),
            mandatory = root.optBoolean(JSON_MANDATORY, false),
            changelogRu = root.optString(JSON_NOTES).ifBlank {
                root.optJSONObject(JSON_CHANGELOG)?.optString(JSON_RU).orEmpty()
            },
            releasedAt = root.optString(JSON_RELEASED_AT).ifBlank {
                root.optString(JSON_ISSUED_AT)
            },
            timestamp = root.optString(JSON_TIMESTAMP).ifBlank {
                root.optString(JSON_ISSUED_AT)
            },
            expiresAt = root.optString(JSON_EXPIRES_AT).ifBlank {
                root.getString(JSON_EXPIRES_AT_CAMEL)
            },
        )
    } catch (_: Throwable) {
        throw UpdateVerificationException(R.string.update_error_manifest)
    }
}

internal fun parseUpdateInstant(value: String): Long =
    try {
        Instant.parse(value).toEpochMilli()
    } catch (_: Throwable) {
        throw UpdateVerificationException(R.string.update_error_manifest)
    }

/**
 * Policy checks of a signature-verified manifest (everything except minisign). [trustedNowMs] is
 * the time used for the expiry check; [futureReferenceMs] is the latest clock available (a signed
 * timestamp is "from the future" only if it is ahead of every clock we have, so a lagging anchor
 * cannot lock updates out).
 */
internal fun evaluateUpdateManifest(
    manifest: UpdateManifest,
    pinnedSigningCertSha256: String,
    trustedNowMs: Long,
    futureReferenceMs: Long,
    currentVersionCode: Long,
    maxSeenUpdateSeq: Long,
): ManifestDecision {
    if (manifest.schema != 1 || manifest.namespace != "apk-update-v1") {
        throw UpdateVerificationException(R.string.update_error_manifest)
    }
    if (normalizeCertSha256(manifest.signingCertSha256) != normalizeCertSha256(pinnedSigningCertSha256)) {
        throw UpdateVerificationException(R.string.update_error_signer)
    }
    val manifestTimestampMs = parseUpdateInstant(manifest.timestamp)
    val expiresAtMs = parseUpdateInstant(manifest.expiresAt)
    if (manifestTimestampMs > max(trustedNowMs, futureReferenceMs) + UPDATE_MAX_FUTURE_TIMESTAMP_MS) {
        throw UpdateVerificationException(R.string.update_error_time_untrusted)
    }
    if (expiresAtMs <= trustedNowMs) {
        throw UpdateVerificationException(R.string.update_error_expired)
    }
    if (manifest.versionCode < currentVersionCode) {
        throw UpdateVerificationException(R.string.update_error_downgrade)
    }
    if (maxSeenUpdateSeq > 0 && manifest.seq < maxSeenUpdateSeq) {
        throw UpdateVerificationException(R.string.update_error_downgrade)
    }
    return if (manifest.versionCode <= currentVersionCode) {
        ManifestDecision.Latest(manifest)
    } else {
        ManifestDecision.Available(manifest)
    }
}

/**
 * APP-L5: the downloaded APK must be this app and exactly the version the signed manifest
 * announced; otherwise installing it would not satisfy the update (endless "update available").
 */
internal fun updateApkIdentityMatches(
    archivePackageName: String?,
    archiveVersionCode: Long?,
    expectedPackageName: String,
    manifestVersionCode: Long,
): Boolean =
    archivePackageName != null &&
        archivePackageName == expectedPackageName &&
        archiveVersionCode != null &&
        archiveVersionCode == manifestVersionCode

class UpdateVerifier(private val context: Context) {
    private val store = SecureIdentityStore(context)

    fun verifyManifest(bundle: ManifestBundle): ManifestDecision {
        val stored = store.readPublicPlatformState()
        val updatePubkey = stored.updatePubkeyPin
        if (updatePubkey.isBlank()) {
            Log.w(TAG, "public update rejected: update_pubkey is not pinned")
            throw UpdateVerificationException(R.string.update_error_signer)
        }
        verifyMinisign(bundle.manifestJson, bundle.minisig, updatePubkey)
        val manifest = parseUpdateManifest(bundle.manifestJson, PUBLIC_UPDATE_SIGNING_CERT_SHA256)
        Log.i(
            TAG,
            "public update manifest candidate seq=${manifest.seq} vc=${manifest.versionCode} maxSeen=${stored.maxSeenUpdateSeq} key=${updatePubkey.take(8)}...",
        )
        val boot = ClockDiagnostics.currentBoot(context)
        val elapsed = SystemClock.elapsedRealtime()
        val systemNowMs = System.currentTimeMillis()
        val release = store.readReleaseState()
        val trustedTime = trustedNow(release, boot, elapsed, systemNowMs)
        val decision = try {
            evaluateUpdateManifest(
                manifest = manifest,
                pinnedSigningCertSha256 = PUBLIC_UPDATE_SIGNING_CERT_SHA256,
                trustedNowMs = trustedTime.wallTimeMs,
                futureReferenceMs = max(trustedTime.wallTimeMs, systemNowMs),
                currentVersionCode = BuildConfig.VERSION_CODE.toLong(),
                maxSeenUpdateSeq = stored.maxSeenUpdateSeq,
            )
        } catch (error: UpdateVerificationException) {
            Log.w(
                TAG,
                "public update rejected: ${error.textRes} seq=${manifest.seq} vc=${manifest.versionCode} " +
                    "issued=${manifest.timestamp} expires=${manifest.expiresAt} " +
                    "cert=${manifest.signingCertSha256.take(12)}",
            )
            throw error
        }
        val manifestTimestampMs = parseUpdateInstant(manifest.timestamp)
        // Atomic read-modify-write: re-check the pin and the rollback floor against the freshest
        // state so a concurrent writer (service, activity) can neither be overwritten nor race us.
        store.updatePublicPlatformState { current ->
            if (current.updatePubkeyPin != updatePubkey) {
                Log.w(TAG, "public update rejected: update_pubkey pin changed during verification")
                throw UpdateVerificationException(R.string.update_error_signer)
            }
            if (current.maxSeenUpdateSeq > 0 && manifest.seq < current.maxSeenUpdateSeq) {
                Log.w(TAG, "public update rejected: rollback seq=${manifest.seq} maxSeen=${current.maxSeenUpdateSeq}")
                throw UpdateVerificationException(R.string.update_error_downgrade)
            }
            current.copy(maxSeenUpdateSeq = max(current.maxSeenUpdateSeq, manifest.seq))
        }
        // Persist only signed time (issued_at) plus the same-boot monotonic delta; SNTP is used
        // for this decision only and never stored (APP-M6/M23).
        runCatching {
            store.updateReleaseState { current ->
                current.withTrustedAnchor(
                    nextTrustedTimeAnchor(
                        current = current.trustedAnchor,
                        signedIssuedAtMs = manifestTimestampMs,
                        currentBoot = boot,
                        currentElapsedRealtimeMs = elapsed,
                        systemNowMs = systemNowMs,
                    ),
                )
            }
        }.onFailure { Log.w(TAG, "public update trusted time anchor not persisted", it) }
        return decision
    }

    fun verifyApk(apkFile: File, manifest: UpdateManifest) {
        try {
            if (!sha256File(apkFile).equals(manifest.sha256, ignoreCase = true)) {
                apkFile.delete()
                throw UpdateVerificationException(R.string.update_error_apk_hash)
            }
            val result = ApkVerifier.Builder(apkFile).build().verify()
            if (!result.isVerified || !result.isVerifiedUsingV2Scheme) {
                apkFile.delete()
                throw UpdateVerificationException(R.string.update_error_signer)
            }
            val pinned = normalizeCertSha256(PUBLIC_UPDATE_SIGNING_CERT_SHA256)
            val certMatches = pinned.isNotEmpty() && result.signerCertificates.any { cert ->
                sha256Bytes(cert.encoded) == pinned
            }
            if (!certMatches) {
                apkFile.delete()
                throw UpdateVerificationException(R.string.update_error_signer)
            }
            val archive = archiveInfo(apkFile)
            if (
                !updateApkIdentityMatches(
                    archivePackageName = archive?.packageName,
                    archiveVersionCode = archive?.let(::longVersionCode),
                    expectedPackageName = context.packageName,
                    manifestVersionCode = manifest.versionCode,
                )
            ) {
                Log.w(
                    TAG,
                    "public update APK identity mismatch package=${archive?.packageName} " +
                        "vc=${archive?.let(::longVersionCode)} manifestVc=${manifest.versionCode}",
                )
                apkFile.delete()
                throw UpdateVerificationException(R.string.update_error_apk_identity)
            }
        } catch (error: UpdateVerificationException) {
            throw error
        } catch (_: Throwable) {
            apkFile.delete()
            throw UpdateVerificationException(R.string.update_error_signer)
        }
    }

    @Suppress("DEPRECATION")
    private fun archiveInfo(apkFile: File): PackageInfo? =
        context.packageManager.getPackageArchiveInfo(apkFile.absolutePath, 0)

    @Suppress("DEPRECATION")
    private fun longVersionCode(info: PackageInfo): Long =
        if (Build.VERSION.SDK_INT >= 28) info.longVersionCode else info.versionCode.toLong()

    private fun verifyMinisign(manifestJson: String, minisig: String, publicKey: String) {
        val result = JSONObject(Transport.verifyMinisign(manifestJson, minisig, publicKey))
        if (!result.optBoolean(JSON_OK, false)) {
            Log.w(TAG, "public update rejected: minisign verification failed")
            throw UpdateVerificationException(R.string.update_error_signature)
        }
    }

    private fun trustedNow(
        release: StoredReleaseState,
        boot: BootIdentity,
        elapsed: Long,
        systemNowMs: Long,
    ): TrustedTimeResult {
        val monotonic = anchoredTrustedNowMs(release.trustedAnchor, boot, elapsed)?.let {
            TrustedTimeResult(wallTimeMs = it, elapsedRealtimeMs = elapsed, sntpAvailable = false)
        }
        val sntp = runCatching { ClockDiagnostics.trustedTime() }
            .onFailure { Log.w(TAG, "public update trusted SNTP unavailable", it) }
            .getOrNull()
        return selectTrustedUpdateTime(monotonic, sntp)
            ?: TrustedTimeResult(
                wallTimeMs = systemNowMs,
                elapsedRealtimeMs = elapsed,
                sntpAvailable = false,
            )
    }

    private fun sha256File(file: File): String {
        val digest = MessageDigest.getInstance("SHA-256")
        file.inputStream().use { input ->
            val buffer = ByteArray(HASH_BUFFER_BYTES)
            while (true) {
                val read = input.read(buffer)
                if (read < 0) break
                digest.update(buffer, 0, read)
            }
        }
        return hex(digest.digest())
    }

    private fun sha256Bytes(bytes: ByteArray): String =
        hex(MessageDigest.getInstance("SHA-256").digest(bytes))

    private fun hex(bytes: ByteArray): String =
        bytes.joinToString("") { "%02x".format(it.toInt() and 0xff) }

    private companion object {
        private const val JSON_OK = "ok"
        private const val HASH_BUFFER_BYTES = 64 * 1024
        private const val TAG = "TWPublicUpdate"
    }
}

private const val JSON_SCHEMA = "schema"
private const val JSON_NS = "ns"
private const val JSON_SEQ = "seq"
private const val JSON_VERSION_CODE = "version_code"
private const val JSON_VERSION_CODE_CAMEL = "versionCode"
private const val JSON_VERSION_NAME = "version_name"
private const val JSON_VERSION_NAME_CAMEL = "versionName"
private const val JSON_APK_URL = "apk_url"
private const val JSON_APK_NAME = "apk_name"
private const val JSON_APK_SIZE = "apk_size"
private const val JSON_APK_SIZE_CAMEL = "apkSize"
private const val JSON_APK_SHA256 = "apk_sha256"
private const val JSON_SHA256 = "sha256"
private const val JSON_SIGNING_CERT_SHA256 = "signing_cert_sha256"
private const val JSON_MIN_VERSION = "min_version"
private const val JSON_MANDATORY = "mandatory"
private const val JSON_NOTES = "notes"
private const val JSON_CHANGELOG = "changelog"
private const val JSON_RU = "ru"
private const val JSON_ISSUED_AT = "issued_at"
private const val JSON_RELEASED_AT = "releasedAt"
private const val JSON_TIMESTAMP = "timestamp"
private const val JSON_EXPIRES_AT = "expires_at"
private const val JSON_EXPIRES_AT_CAMEL = "expiresAt"
