package pro.trafficwrapper

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.os.Build

enum class UpdateNetworkKind {
    WIFI,
    CELLULAR,
    ETHERNET,
    METERED,
    OTHER,
    NONE,
}

data class UpdateAutoDownloadPolicy(
    val autoDownloadEnabled: Boolean,
    val wifiEnabled: Boolean,
    val mobileEnabled: Boolean,
)

internal fun shouldAutoDownloadUpdate(policy: UpdateAutoDownloadPolicy, network: UpdateNetworkKind): Boolean {
    if (!policy.autoDownloadEnabled) return false
    return when (network) {
        UpdateNetworkKind.WIFI, UpdateNetworkKind.ETHERNET -> policy.wifiEnabled
        UpdateNetworkKind.CELLULAR, UpdateNetworkKind.METERED -> policy.mobileEnabled
        UpdateNetworkKind.OTHER -> policy.wifiEnabled
        UpdateNetworkKind.NONE -> false
    }
}

internal fun shouldAutoDownloadUpdateWithCarry(
    policy: UpdateAutoDownloadPolicy,
    network: UpdateNetworkKind,
    carrying: Boolean,
    mandatory: Boolean,
): Boolean = shouldAutoDownloadUpdate(policy, network) && (carrying || mandatory)

object UpdateNetworkPolicy {
    fun currentPolicy(context: Context): UpdateAutoDownloadPolicy =
        UpdateAutoDownloadPolicy(
            autoDownloadEnabled = TransportLifecycleStore.autoDownloadUpdatesEnabled(context),
            wifiEnabled = TransportLifecycleStore.autoDownloadWifiEnabled(context),
            mobileEnabled = TransportLifecycleStore.autoDownloadMobileEnabled(context),
        )

    fun underlyingNetworkKind(context: Context): UpdateNetworkKind =
        runCatching {
            val connectivity = context.getSystemService(ConnectivityManager::class.java)
            val activeCaps = connectivity.activeNetwork?.let { connectivity.getNetworkCapabilities(it) }
            val activeKind = activeCaps.toUpdateNetworkKind()
            val underlyingKinds = activeCaps.underlyingNetworksCompat()
                .mapNotNull { network -> connectivity.getNetworkCapabilities(network).toUpdateNetworkKind() }
            val fallbackKinds = connectivity.allNetworks
                .mapNotNull { network -> connectivity.getNetworkCapabilities(network).toUpdateNetworkKind() }
            chooseUpdateNetworkKind(activeKind, underlyingKinds, fallbackKinds)
        }.getOrDefault(UpdateNetworkKind.OTHER)
}

internal fun classifyUpdateNetworkCapabilities(
    wifi: Boolean,
    cellular: Boolean,
    ethernet: Boolean,
    vpn: Boolean,
    internet: Boolean,
    notMetered: Boolean,
): UpdateNetworkKind? {
    if (!internet || vpn) return null
    if (cellular) return UpdateNetworkKind.CELLULAR
    if (!notMetered) return UpdateNetworkKind.METERED
    return when {
        wifi -> UpdateNetworkKind.WIFI
        ethernet -> UpdateNetworkKind.ETHERNET
        else -> UpdateNetworkKind.OTHER
    }
}

internal fun chooseUpdateNetworkKind(
    activeKind: UpdateNetworkKind?,
    underlyingKinds: List<UpdateNetworkKind>,
    fallbackKinds: List<UpdateNetworkKind>,
): UpdateNetworkKind {
    activeKind?.let { return it }
    reduceUpdateNetworkKinds(underlyingKinds)?.let { return it }
    reduceUpdateNetworkKinds(fallbackKinds)?.let { return it }
    return UpdateNetworkKind.NONE
}

private fun reduceUpdateNetworkKinds(kinds: List<UpdateNetworkKind>): UpdateNetworkKind? {
    if (kinds.isEmpty()) return null
    if (UpdateNetworkKind.CELLULAR in kinds) return UpdateNetworkKind.CELLULAR
    if (UpdateNetworkKind.METERED in kinds) return UpdateNetworkKind.METERED
    if (UpdateNetworkKind.WIFI in kinds) return UpdateNetworkKind.WIFI
    if (UpdateNetworkKind.ETHERNET in kinds) return UpdateNetworkKind.ETHERNET
    if (UpdateNetworkKind.OTHER in kinds) return UpdateNetworkKind.OTHER
    return null
}

private fun NetworkCapabilities?.toUpdateNetworkKind(): UpdateNetworkKind? =
    this?.let {
        classifyUpdateNetworkCapabilities(
            wifi = it.hasTransport(NetworkCapabilities.TRANSPORT_WIFI),
            cellular = it.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR),
            ethernet = it.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET),
            vpn = it.hasTransport(NetworkCapabilities.TRANSPORT_VPN),
            internet = it.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET),
            notMetered = it.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED),
        )
    }

@Suppress("UNCHECKED_CAST")
private fun NetworkCapabilities?.underlyingNetworksCompat(): List<Network> {
    if (this == null || Build.VERSION.SDK_INT < Build.VERSION_CODES.S) return emptyList()
    return runCatching {
        NetworkCapabilities::class.java
            .getMethod("getUnderlyingNetworks")
            .invoke(this) as? List<Network>
    }.getOrNull().orEmpty()
}
