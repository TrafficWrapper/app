package pro.netcloud.trafficwrapper

import android.content.Context
import android.util.Log
import com.android.apksig.ApkVerifier
import org.json.JSONObject
import pro.netcloud.trafficwrapper.go.transport.Transport
import java.io.File
import java.security.MessageDigest

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
        val manifest = parseManifest(bundle.manifestJson)
        Log.i(
            TAG,
            "public update manifest candidate seq=${manifest.seq} vc=${manifest.versionCode} maxSeen=${stored.maxSeenUpdateSeq} key=${updatePubkey.take(8)}...",
        )
        if (manifest.schema != 1 || manifest.namespace != "apk-update-v1") {
            Log.w(TAG, "public update rejected: invalid schema/ns ${manifest.schema}/${manifest.namespace}")
            throw UpdateVerificationException(R.string.update_error_manifest)
        }
        if (!manifest.signingCertSha256.equals(PUBLIC_UPDATE_SIGNING_CERT_SHA256, ignoreCase = true)) {
            Log.w(TAG, "public update rejected: signing cert ${manifest.signingCertSha256.take(12)}")
            throw UpdateVerificationException(R.string.update_error_signer)
        }
        if (manifest.versionCode < BuildConfig.VERSION_CODE.toLong()) {
            Log.w(TAG, "public update rejected: downgrade vc=${manifest.versionCode} current=${BuildConfig.VERSION_CODE}")
            throw UpdateVerificationException(R.string.update_error_downgrade)
        }
        if (stored.maxSeenUpdateSeq > 0 && manifest.seq < stored.maxSeenUpdateSeq) {
            Log.w(TAG, "public update rejected: rollback seq=${manifest.seq} maxSeen=${stored.maxSeenUpdateSeq}")
            throw UpdateVerificationException(R.string.update_error_downgrade)
        }
        if (manifest.seq > stored.maxSeenUpdateSeq) {
            store.writePublicPlatformState(stored.copy(maxSeenUpdateSeq = manifest.seq))
        }
        return if (manifest.versionCode <= BuildConfig.VERSION_CODE.toLong()) {
            ManifestDecision.Latest(manifest)
        } else {
            ManifestDecision.Available(manifest)
        }
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
            val certMatches = result.signerCertificates.any { cert ->
                sha256Bytes(cert.encoded).equals(PUBLIC_UPDATE_SIGNING_CERT_SHA256, ignoreCase = true)
            }
            if (!certMatches) {
                apkFile.delete()
                throw UpdateVerificationException(R.string.update_error_signer)
            }
        } catch (error: UpdateVerificationException) {
            throw error
        } catch (_: Throwable) {
            apkFile.delete()
            throw UpdateVerificationException(R.string.update_error_signer)
        }
    }

    private fun verifyMinisign(manifestJson: String, minisig: String, publicKey: String) {
        val result = JSONObject(Transport.verifyMinisign(manifestJson, minisig, publicKey))
        if (!result.optBoolean(JSON_OK, false)) {
            Log.w(TAG, "public update rejected: minisign verification failed")
            throw UpdateVerificationException(R.string.update_error_signature)
        }
    }

    private fun parseManifest(raw: String): UpdateManifest {
        val root = try {
            JSONObject(raw)
        } catch (_: Throwable) {
            throw UpdateVerificationException(R.string.update_error_manifest)
        }
        return try {
            val versionCode = root.optLong(JSON_VERSION_CODE).takeIf { it > 0 }
                ?: root.getLong(JSON_VERSION_CODE_CAMEL)
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
                signingCertSha256 = root.optString(JSON_SIGNING_CERT_SHA256, PUBLIC_UPDATE_SIGNING_CERT_SHA256),
                minSupportedVersion = root.optLong(JSON_MIN_VERSION, 0),
                mandatory = root.optBoolean(JSON_MANDATORY, false),
                changelogRu = root.optString(JSON_NOTES).ifBlank {
                    root.optJSONObject(JSON_CHANGELOG)?.optString(JSON_RU).orEmpty()
                },
                releasedAt = root.optString(JSON_ISSUED_AT),
                timestamp = root.optString(JSON_ISSUED_AT),
                expiresAt = "9999-12-31T23:59:59Z",
            )
        } catch (_: Throwable) {
            throw UpdateVerificationException(R.string.update_error_manifest)
        }
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
        private const val HASH_BUFFER_BYTES = 64 * 1024
        private const val TAG = "TWPublicUpdate"
    }
}
