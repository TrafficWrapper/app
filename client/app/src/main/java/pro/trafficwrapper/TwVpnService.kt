package pro.trafficwrapper

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.os.SystemClock
import android.util.Log
import org.json.JSONObject
import pro.trafficwrapper.go.transport.Transport
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

class TwVpnService : VpnService() {
    private val mainHandler = Handler(Looper.getMainLooper())
    private val vpnExecutor = Executors.newSingleThreadExecutor()
    private var bridgeStarted = false
    private var blackholePfd: ParcelFileDescriptor? = null
    private var activeNetworkCallback: ConnectivityManager.NetworkCallback? = null
    private var currentUnderlyingNetwork: Network? = null
    private var blackholeNetworkCallback: ConnectivityManager.NetworkCallback? = null
    private var blackholeReconnectRunnable: Runnable? = null
    private var blackholeReconnectDelayMs = BLACKHOLE_RECONNECT_MIN_MS
    private val blackholeReconnectInFlight = AtomicBoolean(false)
    private val activeRebindInFlight = AtomicBoolean(false)
    private val blackholeRecoveryGate = NetworkRecoveryGate<Network>()

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val kind = vpnStartKindForIntent(hasIntent = intent != null, action = intent?.action)
        when (kind) {
            VpnStartKind.APP_START -> {
                if (TransportLifecycleStore.vpnEnabled(applicationContext)) {
                    startVpnForeground()
                    vpnExecutor.execute { establishAndStart() }
                } else {
                    stopStartRequestAfterForeground(startId, "vpn_disabled")
                }
            }
            VpnStartKind.SYSTEM_START -> {
                // Always-on VPN (or a system restart of the VPN): the system starts the service
                // with action android.net.VpnService (or no action) and expects it to come up
                // without the app UI. Promote to foreground first, then do the checks off-thread.
                startVpnForeground()
                vpnExecutor.execute { startFromSystem(startId) }
            }
            VpnStartKind.STOP -> {
                TransportLifecycleStore.setVpnEnabled(applicationContext, false)
                notifyVpnConfigChanged()
                vpnExecutor.execute { stopVpn() }
            }
            VpnStartKind.STICKY_RESTART -> {
                // The process died while the VPN was up (crash or system kill). Bring the tunnel
                // back if the user still wants it; never re-enable a VPN the user switched off.
                val appContext = applicationContext
                if (shouldRestoreVpnOnStickyRestart(
                        vpnFeatureEnabled = BuildConfig.VPN_ENABLED,
                        vpnPreferenceEnabled = TransportLifecycleStore.vpnEnabled(appContext),
                        transportKeepAlive = TransportLifecycleStore.shouldKeepAlive(appContext),
                        vpnPermissionGranted = runCatching { VpnService.prepare(appContext) == null }.getOrDefault(false),
                    )
                ) {
                    Log.i(LOG_TAG, "VPN sticky restart: restoring tunnel")
                    Telemetry.event(appContext, "vpn_state", "action" to "sticky_restore")
                    val promoted = runCatching { startVpnForeground() }
                        .onFailure { Log.w(LOG_TAG, "VPN sticky restart foreground failed", it) }
                        .isSuccess
                    if (promoted) {
                        vpnExecutor.execute { startFromSystem(startId) }
                    } else {
                        stopSelf(startId)
                    }
                } else {
                    Log.i(LOG_TAG, "VPN sticky restart ignored: VPN not requested")
                    stopSelf(startId)
                }
            }
            VpnStartKind.IGNORE -> Unit
        }
        // Sticky, so that a process death while the VPN is up restarts the service (null intent)
        // instead of silently leaving traffic outside the tunnel until the next reboot.
        return if (kind == VpnStartKind.STOP) START_NOT_STICKY else START_STICKY
    }

    private fun startFromSystem(startId: Int) {
        val appContext = applicationContext
        if (!isEnrolledForSystemStart()) {
            Log.w(LOG_TAG, "system VPN start without enrollment; stopping")
            Telemetry.event(appContext, "vpn_state", "action" to "always_on_not_enrolled")
            showEnrollmentRequiredNotification()
            stopVpnBridgeOnly()
            stopVpnForeground()
            unbindFromUnderlyingNetwork()
            stopSelf(startId)
            return
        }
        Log.i(LOG_TAG, "system VPN start (always-on)")
        TransportLifecycleStore.setVpnEnabled(appContext, true)
        val transportWasRequested = TransportLifecycleStore.shouldKeepAlive(appContext)
        if (!transportWasRequested) {
            // The VPN bridge forwards into the local router, so the transport must run as well.
            TransportLifecycleStore.rememberActiveTransport(appContext, TransportLifecycleStore.preferredMode(appContext))
        }
        mainHandler.post {
            TransportRuntime.state = TransportRuntime.state.copy(
                vpnEnabled = BuildConfig.VPN_ENABLED,
                vpnTransition = VpnTransition.STARTING,
            )
        }
        establishAndStart()
        if (bridgeStarted || blackholePfd != null) {
            startTransportForSystemVpn()
        } else if (!transportWasRequested) {
            // VPN could not be established (establishAndStart already stopped the service):
            // do not leave a keep-alive request behind that the user never made.
            TransportLifecycleStore.rememberStopped(appContext)
        }
    }

    private fun isEnrolledForSystemStart(): Boolean {
        val appContext = applicationContext
        if (TransportRuntime.auth.authorized) return true
        if (!DeploymentConfig.IS_PUBLIC_PLATFORM) {
            return TransportLifecycleStore.shouldKeepAlive(appContext)
        }
        val stored = runCatching { SecureIdentityStore(appContext).readPublicPlatformState() }
            .onFailure { Log.w(LOG_TAG, "enrollment state unavailable: ${it.message}") }
            .getOrNull()
            ?: return false
        return stored.clientBundleJson.isNotBlank() &&
            stored.configPubkeyPin.isNotBlank() &&
            stored.realityUUID.isNotBlank() &&
            stored.awgPrivateKey.isNotBlank()
    }

    private fun startTransportForSystemVpn() {
        val appContext = applicationContext
        val intent = Intent(appContext, AutoTransportService::class.java)
            .setAction(AutoTransportService.ACTION_START)
            .putExtra(AutoTransportService.EXTRA_MODE, TransportLifecycleStore.preferredMode(appContext).name)
        runCatching {
            if (Build.VERSION.SDK_INT >= 26) {
                appContext.startForegroundService(intent)
            } else {
                appContext.startService(intent)
            }
        }.onFailure {
            Log.w(LOG_TAG, "Unable to start transport for system VPN start", it)
        }
    }

    private fun showEnrollmentRequiredNotification() {
        runCatching {
            val manager = getSystemService(NotificationManager::class.java) ?: return
            manager.createNotificationChannel(
                NotificationChannel(
                    SERVICE_ALERT_CHANNEL_ID,
                    getString(R.string.service_alert_channel),
                    NotificationManager.IMPORTANCE_DEFAULT,
                ),
            )
            val text = getString(R.string.vpn_always_on_enrollment_required_text)
            val notification = Notification.Builder(this, SERVICE_ALERT_CHANNEL_ID)
                .setSmallIcon(R.drawable.ic_notification)
                .setContentTitle(getString(R.string.vpn_always_on_enrollment_required_title))
                .setContentText(text)
                .setStyle(Notification.BigTextStyle().bigText(text))
                .setContentIntent(mainActivityLaunchPendingIntent(this))
                .setAutoCancel(true)
                .build()
            manager.notify(ENROLLMENT_REQUIRED_NOTIFICATION_ID, notification)
        }.onFailure {
            Log.w(LOG_TAG, "enrollment notification failed: ${it.message}")
        }
    }

    override fun onRevoke() {
        Log.i(LOG_TAG, "VPN revoked by system")
        TransportLifecycleStore.setVpnEnabled(applicationContext, false)
        notifyVpnConfigChanged()
        Telemetry.event(applicationContext, "vpn_revoked")
        vpnExecutor.execute { stopVpn() }
        super.onRevoke()
    }

    override fun onDestroy() {
        vpnExecutor.execute {
            stopVpnBridgeOnly()
            unbindFromUnderlyingNetwork()
        }
        vpnExecutor.shutdown()
        super.onDestroy()
    }

    private fun establishAndStart() {
        if (bridgeStarted) {
            // Make-before-break: the running bridge keeps its TUN until the replacement interface
            // is established and handed to Go (StartVpnBridge replaces the old instance), so
            // traffic never leaves the tunnel while the VPN is rebuilt.
            Log.i(LOG_TAG, "VPN config changed, rebuilding TUN")
            unregisterActiveNetworkCallback()
            activeRebindInFlight.set(false)
        }
        var detachedFd = -1
        var fdHandedToGo = false
        try {
            val underlying = bindToUnderlyingNetwork()
            blackholeRecoveryGate.onAttempt(underlying)
            if (underlying == null && shouldFailClosedWithoutUnderlying()) {
                establishBlackholeVpn("no_underlying")
                notifyVpnConfigChanged()
                return
            }
            val pfd = Builder()
                .setSession("TrafficWrapper")
                .addAddress(VPN_ADDRESS, 32)
                .addRoute("0.0.0.0", 0)
                .captureIPv6()
                .addDnsServer(VPN_DNS_SERVER)
                .setMtu(VPN_MTU)
                .applyTrafficMode()
                .apply {
                    if (underlying != null) {
                        setUnderlyingNetworks(arrayOf(underlying))
                    }
                }
                .establish() ?: throw IllegalStateException("VpnService establish returned null")

            detachedFd = pfd.detachFd()
            fdHandedToGo = true
            val result = JSONObject(Transport.startVpnBridge(detachedFd.toLong(), VPN_MTU.toLong(), VPN_DNS_TARGET))
            if (!result.optBoolean("ok", false)) {
                throw IllegalStateException(result.optString("error", "StartVpnBridge failed"))
            }
            bridgeStarted = true
            // The new interface is live; only now drop the kill-switch blackhole (if any).
            closeBlackholeVpn()
            currentUnderlyingNetwork = underlying
            registerActiveNetworkCallback()
            pushLastUdpRoute()
            publishVpnActive(true)
            Log.i(LOG_TAG, "VPN bridge started")
        } catch (error: Throwable) {
            Log.w(LOG_TAG, "VPN start failed", error)
            if (detachedFd >= 0 && !fdHandedToGo) {
                runCatching { ParcelFileDescriptor.adoptFd(detachedFd).close() }
                    .onFailure { Log.w(LOG_TAG, "Unable to close detached VPN fd", it) }
            }
            if (shouldFailClosedWithoutUnderlying()) {
                runCatching {
                    establishBlackholeVpn("establish_failed")
                }.onSuccess {
                    notifyVpnConfigChanged()
                    return
                }.onFailure { blackholeError ->
                    Log.w(LOG_TAG, "VPN kill-switch blackhole fallback failed", blackholeError)
                }
            }
            TransportLifecycleStore.setVpnEnabled(applicationContext, false)
            notifyVpnConfigChanged()
            stopVpnBridgeOnly()
            stopVpnForeground()
            unbindFromUnderlyingNetwork()
            stopSelf()
        }
    }

    private fun shouldFailClosedWithoutUnderlying(): Boolean =
        TransportLifecycleStore.vpnMode(applicationContext) == VpnTrafficMode.FULL &&
            TransportLifecycleStore.vpnKillSwitchEnabled(applicationContext)

    private fun establishBlackholeVpn(reason: String) {
        unregisterActiveNetworkCallback()
        val pfd = Builder()
            .setSession("TrafficWrapper (blocked)")
            .addAddress(VPN_ADDRESS, 32)
            .addRoute("0.0.0.0", 0)
            .captureIPv6()
            .addDnsServer(VPN_DNS_SERVER)
            .setMtu(VPN_MTU)
            .establish() ?: throw IllegalStateException("VpnService blackhole establish returned null")
        // Make-before-break: the blackhole interface is up before the previous bridge / blackhole
        // is released, so there is no window without a VPN interface.
        val previousBlackhole = blackholePfd
        blackholePfd = pfd
        if (bridgeStarted) {
            runCatching { Transport.stopVpnBridge() }
                .onFailure { Log.w(LOG_TAG, "VPN bridge stop failed", it) }
            bridgeStarted = false
        }
        previousBlackhole?.let { old ->
            runCatching { old.close() }
                .onFailure { Log.w(LOG_TAG, "VPN blackhole close failed", it) }
        }
        cancelBlackholeReconnect(resetDelay = false)
        blackholeReconnectInFlight.set(false)
        publishVpnActive(true)
        Log.w(LOG_TAG, "VPN kill-switch fail-closed active reason=$reason")
        Telemetry.event(
            applicationContext,
            "vpn_kill_switch_block",
            "reason" to reason,
        )
        Telemetry.flush(applicationContext)
        ensureBlackholeRecovery()
    }

    private fun ensureBlackholeRecovery() {
        registerBlackholeNetworkCallback()
        scheduleBlackholeReconnect("blackhole_active", blackholeReconnectDelayMs)
    }

    private fun registerBlackholeNetworkCallback() {
        if (blackholeNetworkCallback != null) return
        val connectivity = getSystemService(ConnectivityManager::class.java) ?: return
        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .build()
        // Callbacks only trigger an out-of-schedule attempt for a network not tried yet; repeated
        // callbacks for the same network (signal strength, link properties...) wait for the
        // backoff schedule instead of rebuilding the interface each time.
        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                if (blackholeRecoveryGate.shouldReconnectNow(network)) {
                    requestBlackholeReconnect("underlying_available")
                }
            }

            override fun onCapabilitiesChanged(network: Network, networkCapabilities: NetworkCapabilities) {
                if (
                    networkCapabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
                    networkCapabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN) &&
                    !networkCapabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN) &&
                    blackholeRecoveryGate.shouldReconnectNow(network)
                ) {
                    requestBlackholeReconnect("underlying_capable")
                }
            }

            override fun onLost(network: Network) {
                blackholeRecoveryGate.onLost(network)
            }
        }
        runCatching {
            connectivity.registerNetworkCallback(request, callback)
            blackholeNetworkCallback = callback
        }.onFailure {
            Log.w(LOG_TAG, "Unable to register VPN blackhole recovery callback", it)
        }
    }

    private fun unregisterBlackholeNetworkCallback() {
        blackholeRecoveryGate.reset()
        val callback = blackholeNetworkCallback ?: return
        blackholeNetworkCallback = null
        runCatching {
            getSystemService(ConnectivityManager::class.java)?.unregisterNetworkCallback(callback)
        }.onFailure {
            Log.w(LOG_TAG, "Unable to unregister VPN blackhole recovery callback", it)
        }
    }

    private fun scheduleBlackholeReconnect(reason: String, delayMs: Long) {
        blackholeReconnectRunnable?.let { mainHandler.removeCallbacks(it) }
        val runnable = Runnable { requestBlackholeReconnect(reason) }
        blackholeReconnectRunnable = runnable
        mainHandler.postDelayed(runnable, delayMs)
    }

    private fun cancelBlackholeReconnect(resetDelay: Boolean) {
        blackholeReconnectRunnable?.let { mainHandler.removeCallbacks(it) }
        blackholeReconnectRunnable = null
        if (resetDelay) {
            blackholeReconnectDelayMs = BLACKHOLE_RECONNECT_MIN_MS
        }
    }

    private fun requestBlackholeReconnect(reason: String) {
        if (!blackholeReconnectInFlight.compareAndSet(false, true)) {
            return
        }
        vpnExecutor.execute {
            try {
                if (blackholePfd == null || !TransportLifecycleStore.vpnEnabled(applicationContext)) {
                    return@execute
                }
                Log.i(LOG_TAG, "VPN blackhole recovery attempt reason=$reason delay_ms=$blackholeReconnectDelayMs")
                val startedAt = SystemClock.elapsedRealtime()
                establishAndStart()
                if (blackholePfd != null && TransportLifecycleStore.vpnEnabled(applicationContext)) {
                    val elapsed = SystemClock.elapsedRealtime() - startedAt
                    blackholeReconnectDelayMs = (blackholeReconnectDelayMs * 2).coerceAtMost(BLACKHOLE_RECONNECT_MAX_MS)
                    Log.w(
                        LOG_TAG,
                        "VPN blackhole recovery did not restore tunnel reason=$reason elapsed_ms=$elapsed next_delay_ms=$blackholeReconnectDelayMs",
                    )
                    scheduleBlackholeReconnect("retry_after_$reason", blackholeReconnectDelayMs)
                }
            } finally {
                blackholeReconnectInFlight.set(false)
            }
        }
    }

    private fun bindToUnderlyingNetwork(): Network? {
        val connectivity = getSystemService(ConnectivityManager::class.java) ?: return null
        val active = connectivity.activeNetwork
        val network = active
            ?.takeIf { isUsableUnderlyingNetwork(connectivity, it) }
            ?: connectivity.allNetworks.firstOrNull { candidate ->
                isUsableUnderlyingNetwork(connectivity, candidate)
            }
        if (network == null) {
            Log.w(LOG_TAG, "No NOT_VPN underlying network available for VPN bind")
            currentUnderlyingNetwork = null
            return null
        }
        if (!connectivity.bindProcessToNetwork(network)) {
            Log.w(LOG_TAG, "Unable to bind process to underlying network")
            currentUnderlyingNetwork = null
            return null
        }
        currentUnderlyingNetwork = network
        Log.i(LOG_TAG, "Process bound to underlying network for VPN")
        return network
    }

    private fun isUsableUnderlyingNetwork(connectivity: ConnectivityManager, network: Network): Boolean {
        val caps = connectivity.getNetworkCapabilities(network) ?: return false
        return caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
            caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN) &&
            !caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
    }

    private fun registerActiveNetworkCallback() {
        if (activeNetworkCallback != null) return
        val connectivity = getSystemService(ConnectivityManager::class.java) ?: return
        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .build()
        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                requestActiveNetworkRebind("underlying_available")
            }

            override fun onLost(network: Network) {
                if (network == currentUnderlyingNetwork) {
                    requestActiveNetworkRebind("underlying_lost")
                }
            }

            override fun onCapabilitiesChanged(network: Network, networkCapabilities: NetworkCapabilities) {
                if (
                    networkCapabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
                    networkCapabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN) &&
                    !networkCapabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
                ) {
                    requestActiveNetworkRebind("underlying_capable")
                } else if (network == currentUnderlyingNetwork) {
                    requestActiveNetworkRebind("underlying_no_longer_capable")
                }
            }
        }
        runCatching {
            connectivity.registerNetworkCallback(request, callback)
            activeNetworkCallback = callback
        }.onFailure {
            Log.w(LOG_TAG, "Unable to register VPN active network callback", it)
        }
    }

    private fun unregisterActiveNetworkCallback() {
        val callback = activeNetworkCallback ?: return
        activeNetworkCallback = null
        runCatching {
            getSystemService(ConnectivityManager::class.java)?.unregisterNetworkCallback(callback)
        }.onFailure {
            Log.w(LOG_TAG, "Unable to unregister VPN active network callback", it)
        }
    }

    private fun requestActiveNetworkRebind(reason: String) {
        if (!activeRebindInFlight.compareAndSet(false, true)) return
        vpnExecutor.execute {
            try {
                if (!bridgeStarted || blackholePfd != null || !TransportLifecycleStore.vpnEnabled(applicationContext)) {
                    return@execute
                }
                val network = bindToUnderlyingNetwork()
                if (network == null) {
                    if (shouldFailClosedWithoutUnderlying()) {
                        Log.w(LOG_TAG, "VPN active underlying lost; entering blackhole reason=$reason")
                        currentUnderlyingNetwork = null
                        runCatching { establishBlackholeVpn("underlying_lost") }
                            .onSuccess { notifyVpnConfigChanged() }
                            .onFailure { Log.w(LOG_TAG, "VPN kill-switch blackhole failed", it) }
                    }
                    return@execute
                }
                runCatching { setUnderlyingNetworks(arrayOf(network)) }
                    .onFailure { Log.w(LOG_TAG, "Unable to update VPN underlying networks", it) }
                pushLastUdpRoute()
                Log.i(LOG_TAG, "VPN rebound to underlying network reason=$reason")
            } finally {
                activeRebindInFlight.set(false)
            }
        }
    }

    private fun unbindFromUnderlyingNetwork() {
        runCatching {
            getSystemService(ConnectivityManager::class.java)?.bindProcessToNetwork(null)
        }.onFailure {
            Log.w(LOG_TAG, "Unable to clear underlying network bind", it)
        }
        currentUnderlyingNetwork = null
    }

    private fun Builder.captureIPv6(): Builder {
        try {
            addAddress(VPN_IPV6_ADDRESS, 128)
        } catch (error: Throwable) {
            Log.w(LOG_TAG, "Unable to add IPv6 VPN address", error)
        }
        addRoute("::", 0)
        return this
    }

    private fun Builder.applyTrafficMode(): Builder {
        when (TransportLifecycleStore.vpnMode(applicationContext)) {
            VpnTrafficMode.FULL -> disallowSelf()
            VpnTrafficMode.SPLIT -> allowSplitApps()
        }
        return this
    }

    private fun Builder.disallowSelf() {
        try {
            addDisallowedApplication(packageName)
        } catch (error: PackageManager.NameNotFoundException) {
            Log.w(LOG_TAG, "Unable to disallow self from VPN", error)
        }
    }

    private fun Builder.allowSplitApps() {
        val requested = TransportLifecycleStore.vpnAllowedApps(applicationContext)
            .filter { it != packageName }
            .distinct()
        if (requested.isEmpty()) {
            throw IllegalStateException("VPN split mode has no selected apps")
        }
        var applied = 0
        requested.forEach { packageName ->
            try {
                addAllowedApplication(packageName)
                applied += 1
            } catch (error: PackageManager.NameNotFoundException) {
                Log.w(LOG_TAG, "Skipping missing split VPN app: $packageName", error)
            }
        }
        if (applied == 0) {
            throw IllegalStateException("VPN split mode has no installed selected apps")
        }
        Log.i(LOG_TAG, "VPN split mode allowed apps=$applied requested=${requested.size}")
    }

    private fun pushLastUdpRoute() {
        val route = TransportLifecycleStore.lastVpnUdpRoute(applicationContext).ifBlank { "disabled" }
        runCatching { Transport.setVpnBridgeUDPRoute(route) }
            .onFailure { Log.w(LOG_TAG, "VPN UDP route repush failed: ${it.message}") }
            .onSuccess { Log.i(LOG_TAG, "VPN UDP route repushed: $route") }
    }

    private fun notifyVpnConfigChanged() {
        runCatching {
            val intent = Intent(applicationContext, AutoTransportService::class.java)
                .setAction(AutoTransportService.ACTION_VPN_CONFIG_CHANGED)
            if (Build.VERSION.SDK_INT >= 26) {
                applicationContext.startForegroundService(intent)
            } else {
                applicationContext.startService(intent)
            }
        }.onFailure {
            Log.w(LOG_TAG, "Unable to notify transport about VPN config change", it)
        }
    }

    private fun stopVpn() {
        stopVpnBridgeOnly()
        stopVpnForeground()
        unbindFromUnderlyingNetwork()
        stopSelf()
    }

    private fun stopVpnBridgeOnly(publishInactive: Boolean = true) {
        unregisterActiveNetworkCallback()
        currentUnderlyingNetwork = null
        activeRebindInFlight.set(false)
        if (bridgeStarted) {
            runCatching { Transport.stopVpnBridge() }
                .onFailure { Log.w(LOG_TAG, "VPN bridge stop failed", it) }
            bridgeStarted = false
        }
        closeBlackholeVpn()
        if (publishInactive) {
            publishVpnActive(false)
        }
    }

    private fun closeBlackholeVpn(resetRecovery: Boolean = true) {
        blackholePfd?.let { pfd ->
            runCatching { pfd.close() }
                .onFailure { Log.w(LOG_TAG, "VPN blackhole close failed", it) }
            blackholePfd = null
        }
        if (resetRecovery) {
            unregisterBlackholeNetworkCallback()
        }
        cancelBlackholeReconnect(resetRecovery)
        blackholeReconnectInFlight.set(false)
    }

    private fun publishVpnActive(active: Boolean) {
        mainHandler.post {
            TransportRuntime.state = TransportRuntime.state.copy(
                vpnEnabled = BuildConfig.VPN_ENABLED && TransportLifecycleStore.vpnEnabled(applicationContext),
                vpnActive = active,
                vpnTransition = VpnTransition.NONE,
            )
            Telemetry.event(
                applicationContext,
                "vpn_state",
                "action" to if (active) "active" else "inactive",
            )
            Telemetry.flush(applicationContext)
        }
    }

    private fun startVpnForeground() {
        createNotificationChannel()
        val notification = buildNotification()
        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(
                NOTIFICATION_ID,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE,
            )
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    private fun stopStartRequestAfterForeground(startId: Int, reason: String) {
        Log.i(LOG_TAG, "VPN start request ignored after foreground promotion: $reason")
        startVpnForeground()
        stopVpnForeground()
        stopSelf(startId)
    }

    private fun stopVpnForeground() {
        mainHandler.post {
            if (Build.VERSION.SDK_INT >= 24) {
                stopForeground(STOP_FOREGROUND_REMOVE)
            } else {
                @Suppress("DEPRECATION")
                stopForeground(true)
            }
        }
    }

    private fun createNotificationChannel() {
        val channel = NotificationChannel(
            CHANNEL_ID,
            getString(R.string.vpn_notification_channel),
            NotificationManager.IMPORTANCE_LOW,
        )
        getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
    }

    private fun buildNotification(): Notification =
        Notification.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle(getString(R.string.vpn_notification_title))
            .setContentText(getString(R.string.vpn_notification_text))
            .setContentIntent(mainActivityLaunchPendingIntent(this))
            .setOngoing(true)
            .build()

    companion object {
        const val ACTION_VPN_START = "pro.trafficwrapper.action.VPN_START"
        const val ACTION_VPN_STOP = "pro.trafficwrapper.action.VPN_STOP"

        private const val LOG_TAG = "TwVpnService"
        private const val CHANNEL_ID = "tw_vpn"
        private const val SERVICE_ALERT_CHANNEL_ID = "service-alerts"

        // Distinct from AutoTransportService alert ids (1313-1315): an alert must never replace
        // the VPN foreground notification.
        private const val NOTIFICATION_ID = 1316
        private const val ENROLLMENT_REQUIRED_NOTIFICATION_ID = 1317
        private const val VPN_ADDRESS = "10.111.0.2"
        private const val VPN_IPV6_ADDRESS = "fd00:1111::1"
        private const val VPN_DNS_SERVER = "1.1.1.1"
        private const val VPN_DNS_TARGET = "1.1.1.1:53"
        private const val VPN_MTU = 1500
        private const val BLACKHOLE_RECONNECT_MIN_MS = 5_000L
        private const val BLACKHOLE_RECONNECT_MAX_MS = 60_000L
    }
}

internal enum class VpnStartKind {
    APP_START,
    SYSTEM_START,
    STOP,

    /** START_STICKY restart after the process died: the system redelivers a null intent. */
    STICKY_RESTART,
    IGNORE,
}

/** Action android.net.VpnService, used by the system for always-on VPN starts. */
internal const val VPN_SERVICE_INTERFACE_ACTION = "android.net.VpnService"

internal fun vpnStartKind(action: String?): VpnStartKind =
    when (action) {
        TwVpnService.ACTION_VPN_START -> VpnStartKind.APP_START
        TwVpnService.ACTION_VPN_STOP -> VpnStartKind.STOP
        null, VPN_SERVICE_INTERFACE_ACTION -> VpnStartKind.SYSTEM_START
        else -> VpnStartKind.IGNORE
    }

/**
 * Like [vpnStartKind], but distinguishes a sticky restart (no intent at all) from an always-on
 * system start (an intent with action android.net.VpnService or no action).
 */
internal fun vpnStartKindForIntent(hasIntent: Boolean, action: String?): VpnStartKind =
    if (!hasIntent) VpnStartKind.STICKY_RESTART else vpnStartKind(action)

/** A sticky restart restores the tunnel only when the user still has VPN mode (and the transport) on. */
internal fun shouldRestoreVpnOnStickyRestart(
    vpnFeatureEnabled: Boolean,
    vpnPreferenceEnabled: Boolean,
    transportKeepAlive: Boolean,
    vpnPermissionGranted: Boolean,
): Boolean = vpnFeatureEnabled && vpnPreferenceEnabled && transportKeepAlive && vpnPermissionGranted

/**
 * Rate-limits network-callback driven reconnects of the kill-switch blackhole: a callback triggers
 * an immediate attempt only for a network that has not been tried (or seen) since it last
 * appeared. Everything else is left to the exponential backoff schedule.
 */
internal class NetworkRecoveryGate<T : Any> {
    private val seen = HashSet<T>()

    /** Records the network an attempt is being made on (null: no usable network). */
    @Synchronized
    fun onAttempt(network: T?) {
        if (network != null) seen.add(network)
    }

    /** True when [network] was not seen before; it is then remembered. */
    @Synchronized
    fun shouldReconnectNow(network: T): Boolean = seen.add(network)

    /** A lost network counts as new again when it comes back. */
    @Synchronized
    fun onLost(network: T) {
        seen.remove(network)
    }

    @Synchronized
    fun reset() {
        seen.clear()
    }
}
