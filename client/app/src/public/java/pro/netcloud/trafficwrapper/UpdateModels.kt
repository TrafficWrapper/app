package pro.netcloud.trafficwrapper

import androidx.annotation.StringRes
import java.io.File

data class UpdateManifest(
    val schema: Int,
    val namespace: String,
    val seq: Long,
    val versionCode: Long,
    val versionName: String,
    val apkUrl: String,
    val apkSize: Long,
    val sha256: String,
    val signingCertSha256: String,
    val minSupportedVersion: Long,
    val mandatory: Boolean,
    val changelogRu: String,
    val releasedAt: String,
    val timestamp: String,
    val expiresAt: String,
)

fun UpdateManifest.requiresInstalledUpdate(): Boolean =
    mandatory || minSupportedVersion > BuildConfig.VERSION_CODE.toLong()

data class ManifestBundle(
    val manifestJson: String,
    val minisig: String,
    val source: UpdateSource,
    val baseUrl: String = PUBLIC_PLATFORM_UPDATE_BASE_URL,
    val socksListen: String = UPDATE_ROUTER_SOCKS_LISTEN,
)

enum class UpdateSource {
    PLATFORM,
}

sealed class ManifestDecision {
    data class Latest(val manifest: UpdateManifest) : ManifestDecision()
    data class Available(val manifest: UpdateManifest) : ManifestDecision()
}

data class UpdateCheckOutcome(
    val status: UpdateCheckStatus,
    val manifest: UpdateManifest? = null,
    val source: UpdateSource? = null,
    val baseUrl: String = PUBLIC_PLATFORM_UPDATE_BASE_URL,
    val apkFile: File? = null,
    val downloadedBytes: Long = 0,
    val totalBytes: Long = 0,
    val mandatoryDegraded: Boolean = false,
    @StringRes val errorTextRes: Int? = null,
)

enum class UpdateCheckStatus {
    LATEST,
    AVAILABLE,
    ERROR,
}

class UpdateVerificationException(@StringRes val textRes: Int) : Exception()

val PUBLIC_UPDATE_SIGNING_CERT_SHA256: String
    get() = BuildConfig.PUBLIC_UPDATE_SIGNING_CERT_SHA256
const val PUBLIC_PLATFORM_UPDATE_BASE_URL = "http://awg-gw:8080/tw"
const val UPDATE_AWG_BASE_URL = PUBLIC_PLATFORM_UPDATE_BASE_URL
const val UPDATE_ROUTER_SOCKS_LISTEN = "127.0.0.1:18080"
const val UPDATE_AWG_SOCKS_LISTEN = UPDATE_ROUTER_SOCKS_LISTEN

internal fun updateApkDownloadUrl(baseUrl: String, manifestApkUrl: String, versionCode: Long): String {
    val apkName = manifestApkUrl.substringAfterLast('/').ifBlank {
        "app-public-$versionCode.apk"
    }
    return baseUrl.trimEnd('/') + "/" + apkName.trimStart('/')
}
