package pro.netcloud.trafficwrapper

import android.graphics.drawable.Drawable
import androidx.annotation.StringRes
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue

data class TransportUiState(
    @StringRes val stateTextRes: Int = R.string.state_idle,
    @StringRes val clockTextRes: Int = R.string.clock_status_unknown,
    val clockSkewSeconds: Long? = null,
    val handshakeEstablished: Boolean = false,
    val tunnelStable: Boolean = false,
    val activeTransport: String = "",
    val socksListen: String = "",
    val rxBytes: Long = 0,
    val txBytes: Long = 0,
    val outboundIp: String = "",
    val lastExchangeAgeSeconds: Long? = null,
    val stableSinceElapsedRealtimeMs: Long? = null,
)

enum class TransportChoice {
    AUTO,
    AWG_RU,
    AWG,
    REALITY,
    REALITY2,
}

data class AwgUiConfig(
    val internalIP: String = "",
    val endpoint: String = "",
    val serverPublicKey: String = "",
) {
    fun isComplete(): Boolean =
        internalIP.isNotBlank() &&
            endpoint.isNotBlank() &&
            serverPublicKey.isNotBlank()
}

data class RealityUiConfig(
    val transport: String = "",
    val address: String = "",
    val ip: String = "",
    val port: Int = 0,
    val uuid: String = "",
    val email: String = "",
    val flow: String = "",
    val security: String = "",
    val network: String = "",
    val serverName: String = "",
    val publicKey: String = "",
    val shortId: String = "",
    val fingerprint: String = "",
    val spiderX: String = "",
    val dest: String = "",
) {
    fun isComplete(): Boolean =
        transport.isNotBlank() &&
            address.isNotBlank() &&
            port > 0 &&
            uuid.isNotBlank() &&
            security.isNotBlank() &&
            network.isNotBlank() &&
            serverName.isNotBlank() &&
            publicKey.isNotBlank() &&
            shortId.isNotBlank() &&
            fingerprint.isNotBlank() &&
            spiderX.isNotBlank()
}

data class AuthUiState(
    val authorized: Boolean = false,
    val inProgress: Boolean = false,
    @StringRes val statusTextRes: Int = R.string.enrollment_status_starting,
    @StringRes val errorTextRes: Int? = null,
    @StringRes val keystoreTextRes: Int = R.string.keystore_status_unknown,
    val deviceIdentityPublicSuffix: String = "",
    val noiseIdentityPublicSuffix: String = "",
    val deviceID: String = "",
    val androidID: String = "",
    val model: String = "",
    val alias: String = "",
    val message: String = "",
    val internalIP: String = "",
    val endpoint: String = "",
    val provisionedSOCKS: String = "",
    val awgRu: AwgUiConfig? = null,
    val reality: RealityUiConfig? = null,
    val reality2: RealityUiConfig? = null,
)

enum class ProxySupport {
    AUTO_TELEGRAM,
    MANUAL_PROXY,
    UNSUPPORTED,
}

data class InstalledAppInfo(
    val packageName: String,
    val label: String,
    val support: ProxySupport,
    val icon: Drawable?,
)

data class AppSelectionState(
    val loading: Boolean = true,
    val apps: List<InstalledAppInfo> = emptyList(),
    val selectedPackage: String = TELEGRAM_PACKAGE,
)

data class DistributionUiState(
    val inProgress: Boolean = false,
    val downloadInProgress: Boolean = false,
    @StringRes val statusTextRes: Int = R.string.update_status_never_checked,
    @StringRes val errorTextRes: Int? = null,
    val availableVersionName: String = "",
    val availableVersionCode: Long = 0,
    val source: String = "",
    val baseUrl: String = "",
    val downloadedBytes: Long = 0,
    val totalBytes: Long = 0,
    val apkPath: String = "",
    val changelog: String = "",
    val mandatoryRequired: Boolean = false,
    val mandatoryDegraded: Boolean = false,
    val showAvailableSheet: Boolean = false,
    val snoozedUntilMs: Long = 0,
    val installInProgress: Boolean = false,
    @StringRes val installStatusTextRes: Int? = null,
    @StringRes val installErrorTextRes: Int? = null,
    val lastCheckedAt: String = "",
)

object TransportRuntime {
    var state by mutableStateOf(TransportUiState())
    var auth by mutableStateOf(AuthUiState())
    var apps by mutableStateOf(AppSelectionState())
    var updates by mutableStateOf(DistributionUiState())
    var batteryRestriction by mutableStateOf(BatteryRestrictionState())
    var showBatteryGuide by mutableStateOf(false)
    var selectedTransport by mutableStateOf(TransportChoice.AUTO)
    var discoveredRealityEgressIp by mutableStateOf(DEFAULT_REALITY_EGRESS_IP)
    var publicPlatformConfig by mutableStateOf<PublicClientConfig?>(null)
    var publicPlatformRouteSlots by mutableStateOf(PublicPlatformRouteSlots())
    var publicRealityEgressIp by mutableStateOf("")
    var publicReality2EgressIp by mutableStateOf("")
    @Volatile
    var appliedReality2Uuid: String = ""
    var debugClockSkewSeconds: Long? = null
}

const val TELEGRAM_PACKAGE = "org.telegram.messenger"
val DEFAULT_REALITY_EGRESS_IP: String get() = DeploymentConfig.DEFAULT_REALITY_EGRESS_IP
val DEFAULT_REALITY2_EGRESS_IP: String get() = DeploymentConfig.DEFAULT_REALITY2_EGRESS_IP
