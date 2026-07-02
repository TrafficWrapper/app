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
        UpdateNetworkKind.CELLULAR -> policy.mobileEnabled
        UpdateNetworkKind.OTHER -> policy.wifiEnabled
        UpdateNetworkKind.NONE -> false
    }
}

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
            val underlying = activeCaps.underlyingNetworksCompat()
            val candidates = (underlying + connectivity.allNetworks.toList())
                .distinct()
                .mapNotNull { network ->
                    val caps = connectivity.getNetworkCapabilities(network) ?: return@mapNotNull null
                    if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) return@mapNotNull null
                    if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) return@mapNotNull null
                    caps
                }
            val caps = candidates.firstOrNull()
                ?: activeCaps?.takeUnless { it.hasTransport(NetworkCapabilities.TRANSPORT_VPN) }
                ?: return@runCatching UpdateNetworkKind.NONE
            when {
                caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> UpdateNetworkKind.WIFI
                caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> UpdateNetworkKind.ETHERNET
                caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> UpdateNetworkKind.CELLULAR
                else -> UpdateNetworkKind.OTHER
            }
        }.getOrDefault(UpdateNetworkKind.OTHER)
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
