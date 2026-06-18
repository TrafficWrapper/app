package pro.netcloud.trafficwrapper

import android.annotation.SuppressLint
import android.app.AlarmManager
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.PowerManager
import android.os.SystemClock
import android.util.Log
import org.json.JSONArray
import org.json.JSONObject
import pro.netcloud.trafficwrapper.go.transport.Transport
import java.io.EOFException
import java.io.File
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.URI
import java.net.ServerSocket
import java.net.Socket
import java.net.URL
import java.util.ArrayDeque
import java.util.Collections
import java.util.concurrent.CountDownLatch
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference
import javax.net.ssl.HttpsURLConnection
import kotlin.random.Random

internal fun shouldFastFailActiveAwg(
    handshakeEstablished: Boolean,
    carrying: Boolean,
    rxStalled: Boolean,
    activeEndToEndProbeFailed: Boolean,
): Boolean =
    handshakeEstablished &&
        !carrying &&
        rxStalled &&
        activeEndToEndProbeFailed

internal fun shouldReleaseWakeLockForAllDeadSleep(
    routeHealthy: Boolean,
    hasUsableRoute: Boolean,
    consecutiveAllDeadCycles: Int,
    sleepMs: Long,
): Boolean =
    !routeHealthy &&
        !hasUsableRoute &&
        consecutiveAllDeadCycles >= ALL_DEAD_WAKELOCK_RELEASE_CYCLES &&
        sleepMs >= ALL_DEAD_WAKELOCK_MIN_SLEEP_MS

internal fun awgCarryingEvidence(
    handshakeEstablished: Boolean,
    nowMs: Long,
    lastRxProgressAtMs: Long,
    lastEndToEndProbeAtMs: Long,
    allowEndToEndProbe: Boolean,
    requireEndToEndProbe: Boolean,
): Boolean {
    if (!handshakeEstablished) return false
    if (requireEndToEndProbe) {
        return allowEndToEndProbe && isRecentTimestamp(nowMs, lastEndToEndProbeAtMs, AWG_CARRYING_EVIDENCE_MAX_AGE_MS)
    }
    if (isRecentTimestamp(nowMs, lastRxProgressAtMs, AWG_CARRYING_EVIDENCE_MAX_AGE_MS)) return true
    return allowEndToEndProbe && isRecentTimestamp(nowMs, lastEndToEndProbeAtMs, AWG_CARRYING_EVIDENCE_MAX_AGE_MS)
}

internal fun isRecentTimestamp(nowMs: Long, timestampMs: Long, maxAgeMs: Long): Boolean =
    timestampMs > 0L && nowMs - timestampMs in 0..maxAgeMs

internal fun <T> selectRouteWithFallbackPolicy(
    mode: TransportChoice,
    preferred: T,
    fallback: () -> T,
): T =
    if (mode == TransportChoice.AUTO) fallback() else preferred

internal fun shouldRestartReality2ForUuid(
    appliedUuid: String,
    desiredUuid: String,
    sidecarAlive: Boolean,
): Boolean =
    sidecarAlive &&
        appliedUuid.isNotBlank() &&
        desiredUuid.isNotBlank() &&
        !appliedUuid.trim().equals(desiredUuid.trim(), ignoreCase = true)

internal fun realityUuid8(uuid: String): String {
    val hex = buildString {
        uuid.trim().forEach { ch ->
            val c = ch.lowercaseChar()
            if (c in '0'..'9' || c in 'a'..'f') append(c)
        }
    }
    return hex.take(8).takeIf { it.length == 8 }.orEmpty()
}

internal data class SocksConnectAddressPolicy(
    val openUpstream: Boolean,
    val rejectReply: ByteArray? = null,
)

internal fun socksConnectAddressPolicy(atyp: Int): SocksConnectAddressPolicy =
    if (atyp == SOCKS5_ATYP_IPV6) {
        SocksConnectAddressPolicy(
            openUpstream = false,
            rejectReply = byteArrayOf(
                SOCKS5_VERSION.toByte(),
                SOCKS5_REP_ADDRESS_TYPE_NOT_SUPPORTED.toByte(),
                0,
                SOCKS5_ATYP_IPV4.toByte(),
                0,
                0,
                0,
                0,
                0,
                0,
            ),
        )
    } else {
        SocksConnectAddressPolicy(openUpstream = true)
    }

internal fun shouldPromoteRecoveredPriorityRoute(
    inactiveHealthySinceMs: Long,
    lastHealthLostAtMs: Long,
    recentHealthLostCount: Int,
    nowMs: Long,
    promoteDwellMs: Long = TCP_PRIORITY_PROMOTE_DWELL_MS,
    flapThreshold: Int = TCP_ROUTE_FLAP_THRESHOLD,
): Boolean {
    if (inactiveHealthySinceMs <= 0L || nowMs - inactiveHealthySinceMs < promoteDwellMs) return false
    if (lastHealthLostAtMs > 0L && nowMs - lastHealthLostAtMs < promoteDwellMs) return false
    return recentHealthLostCount < flapThreshold
}

internal fun tcpRouteFlapDemotionMs(
    recentHealthLostCount: Int,
    threshold: Int = TCP_ROUTE_FLAP_THRESHOLD,
    baseMs: Long = TCP_ROUTE_FLAP_DEMOTE_BASE_MS,
    maxMs: Long = TCP_ROUTE_FLAP_DEMOTE_MAX_MS,
): Long {
    if (recentHealthLostCount < threshold) return 0L
    var backoffMs = baseMs
    repeat((recentHealthLostCount - threshold).coerceAtLeast(0).coerceAtMost(TCP_ROUTE_FLAP_DEMOTE_MAX_SHIFT)) {
        backoffMs = (backoffMs * 2).coerceAtMost(maxMs)
    }
    return backoffMs
}

internal fun shouldRetryRealityProbe(
    attemptIndex: Int,
    maxAttempts: Int = REALITY_PROBE_ATTEMPTS,
): Boolean =
    attemptIndex + 1 < maxAttempts

internal const val ALL_DEAD_WAKELOCK_RELEASE_CYCLES = 3
internal const val ALL_DEAD_WAKELOCK_MIN_SLEEP_MS = 15_000L
internal const val HEALTH_PROBE_TIMEOUT_MS = 7_000
internal const val AWG_CARRYING_EVIDENCE_MAX_AGE_MS = 7_000L
internal const val REALITY_PROBE_ATTEMPTS = 2
internal const val TCP_PRIORITY_PROMOTE_DWELL_MS = 45_000L
internal const val TCP_ROUTE_FLAP_WINDOW_MS = 2 * 60 * 1000L
internal const val TCP_ROUTE_FLAP_THRESHOLD = 3
internal const val TCP_ROUTE_FLAP_DEMOTE_BASE_MS = 60_000L
internal const val TCP_ROUTE_FLAP_DEMOTE_MAX_MS = 5 * 60 * 1000L
internal const val TCP_ROUTE_FLAP_DEMOTE_MAX_SHIFT = 4
internal const val SOCKS5_VERSION = 5
internal const val SOCKS5_ATYP_IPV4 = 1
internal const val SOCKS5_ATYP_DOMAIN = 3
internal const val SOCKS5_ATYP_IPV6 = 4
internal const val SOCKS5_REP_ADDRESS_TYPE_NOT_SUPPORTED = 8

class AutoTransportService : Service() {
    private val mainHandler = Handler(Looper.getMainLooper())
    private val executor: ExecutorService = Executors.newSingleThreadExecutor()
    private val upstreamRef = AtomicReference(AWG_RU_UPSTREAM)
    private val networkEvent = AtomicReference<NetworkEvent?>(null)
    private val defaultNetwork = AtomicReference<Network?>(null)
    private val realityRxBytes = AtomicLong(0)
    private val realityTxBytes = AtomicLong(0)
    private val reality2RxBytes = AtomicLong(0)
    private val reality2TxBytes = AtomicLong(0)
    private val routeHealthSnapshot = AtomicReference<RouteHealthSnapshot?>(null)
    private val awgRuDemotionLevel = AtomicLong(0)
    private val awgRuRetryAfterElapsedMs = AtomicLong(0)
    private val awgRuCarryingSinceElapsedMs = AtomicLong(0)
    private val awgDemotionLevel = AtomicLong(0)
    private val awgRetryAfterElapsedMs = AtomicLong(0)
    private val awgCarryingSinceElapsedMs = AtomicLong(0)
    @Suppress("PLATFORM_CLASS_MAPPED_TO_KOTLIN")
    private val resyncSignal = Object()

    @Volatile
    private var networkCallback: ConnectivityManager.NetworkCallback? = null

    @Volatile
    private var screenReceiver: BroadcastReceiver? = null

    @Volatile
    private var wakeLock: PowerManager.WakeLock? = null
    private val wakeLockMonitor = Any()

    private val workerActive = AtomicBoolean(false)

    @Volatile
    private var xrayProcess: Process? = null

    @Volatile
    private var xray2Process: Process? = null

    @Volatile
    private var appliedReality2Uuid: String = ""

    @Volatile
    private var router: SocksRouter? = null

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        activeService.set(this)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val action = intent?.action
        createNotificationChannel()
        startTransportForeground()
        if (action == ACTION_STOP) {
            val keepAliveAfterStop = intent.getBooleanExtra(EXTRA_KEEP_ALIVE_AFTER_STOP, false)
            if (!keepAliveAfterStop) {
                TransportLifecycleStore.rememberStopped(this)
            }
            stopAuto(cancelBackstop = !keepAliveAfterStop)
            stopSelf()
            return if (keepAliveAfterStop) START_STICKY else START_NOT_STICKY
        }
        if ((action == ACTION_BACKSTOP || action == ACTION_RESYNC) && !TransportLifecycleStore.shouldKeepAlive(this)) {
            stopSelf()
            return START_NOT_STICKY
        }
        requestedMode = intent?.getStringExtra(EXTRA_MODE)
            ?.let { runCatching { TransportChoice.valueOf(it) }.getOrNull() }
            ?: TransportLifecycleStore.preferredMode(this)
        if (action == ACTION_START) {
            TransportLifecycleStore.rememberActiveTransport(this, requestedMode)
        }
        BatteryRestrictionNotifier.maybeNotify(applicationContext)
        acquireWakeLock()
        registerNetworkCallback()
        registerScreenReceiver()
        scheduleBackstop()
        when (action) {
            ACTION_BACKSTOP -> {
                Telemetry.flush(applicationContext)
                if (workerActive.get()) requestLifecycleResync(NetworkEvent.BACKSTOP_ALARM)
            }
            ACTION_RESYNC -> requestLifecycleResync(NetworkEvent.FOREGROUND_RESYNC)
        }
        startAuto()
        return START_STICKY
    }

    override fun onTaskRemoved(rootIntent: Intent?) {
        if (TransportLifecycleStore.shouldKeepAlive(this)) {
            scheduleBackstop()
        }
        super.onTaskRemoved(rootIntent)
    }

    override fun onDestroy() {
        activeService.compareAndSet(this, null)
        stopAuto(cancelBackstop = !TransportLifecycleStore.shouldKeepAlive(this))
        executor.shutdownNow()
        super.onDestroy()
    }

    private fun startAuto(): Boolean {
        if (!workerActive.compareAndSet(false, true)) return false
        acquireWakeLock()
        publishState(
            TransportUiState(
                stateTextRes = R.string.state_starting,
                clockTextRes = R.string.clock_status_checking,
                activeTransport = routeLabel(Route.AWG_RU),
                socksListen = ROUTER_SOCKS,
            ),
        )
        try {
            executor.execute {
            var awgRuStarted = false
            var awgStarted = false
            var activeRoute = Route.AWG_RU
            var awgRuFailures = 0
            var awgRuHandshakeFailures = 0
            var awgRuOutboundFailures = 0
            var awgFailures = 0
            var awgHandshakeFailures = 0
            var awgOutboundFailures = 0
            var rekeyAfterStop = false
            var outboundIp = ""
            var xrayStarted = false
            var xray2Started = false
            var lastAwgRuRx = 0L
            var lastAwgRuTx = 0L
            var lastAwgRx = 0L
            var lastAwgTx = 0L
            var lastRealityRx = 0L
            var lastRealityTx = 0L
            var lastReality2Rx = 0L
            var lastReality2Tx = 0L
            var lastTrafficAtMs: Long? = null
            var lastOutboundProbeAtMs = 0L
            var lastAwgRuProbeAtMs = 0L
            var lastAwgProbeAtMs = 0L
            var lastAwgRuRetryProbeAtMs = 0L
            var lastAwgRetryProbeAtMs = 0L
            var lastRealityProbeAtMs = 0L
            var lastReality2ProbeAtMs = 0L
            var lastAwgRuRetryOkAtMs = 0L
            var lastAwgRetryOkAtMs = 0L
            var awgRuRetryFailures = 0
            var awgRetryFailures = 0
            var lastAwgRuRxProgressAtMs = 0L
            var lastAwgRxProgressAtMs = 0L
            var lastRealityRxProgressAtMs = 0L
            var lastReality2RxProgressAtMs = 0L
            var lastAwgRuEndToEndProbeAtMs = 0L
            var lastAwgEndToEndProbeAtMs = 0L
            var lastAwgRuEndToEndFailureAtMs = 0L
            var lastAwgEndToEndFailureAtMs = 0L
            var lastRouteSwitchAtMs = 0L
            var cachedAwgRuProbe = AWGProbeResult(false)
            var cachedAwgProbe = AWGProbeResult(false)
            var cachedRealityProbe = RealityProbeResult(false)
            var cachedReality2Probe = RealityProbeResult(false)
            var reconnectBackoffMs = RECONNECT_MIN_BACKOFF_MS
            var consecutiveAllDeadCycles = 0
            var nextRealityRestartAtMs = 0L
            var nextReality2RestartAtMs = 0L
            var awgRuStartBackoffMs = AWG_START_MIN_BACKOFF_MS
            var awgStartBackoffMs = AWG_START_MIN_BACKOFF_MS
            var awgRuUdpDeadFailures = 0
            var awgUdpDeadFailures = 0
            var nextAwgRuStartAtMs = 0L
            var nextAwgStartAtMs = 0L
            var nextTelemetryHeartbeatAtMs = 0L
            var nextBatteryRestrictionNotifyCheckAtMs = 0L
            var stableSinceElapsedRealtimeMs: Long? = null
            var lastHealthyRouteAtMs: Long? = null
            var lastTunnelDisruptionAtMs = 0L
            var lastTunnelDisruptionReason = ""
            var lastSessionFlushAtMs = 0L
            var awgRuHandshakeObserved = false
            var awgHandshakeObserved = false
            var lastAwgRuHandshakeEstablished = false
            var lastAwgHandshakeEstablished = false
            var routeHealthObserved = false
            var lastRouteHealthy = false
            var routeStabilityLost = false
            val routeCooldownLevel = mutableMapOf<Route, Int>()
            val routeCooldownUntilMs = mutableMapOf<Route, Long>()
            val routeHealthySinceMs = mutableMapOf<Route, Long>()
            val routeUnhealthySinceMs = mutableMapOf<Route, Long>()
            val routeLastHealthyAtMs = mutableMapOf<Route, Long>()
            val tcpRouteHealthLostEvents = mutableMapOf<Route, ArrayDeque<Long>>()
            val tcpRouteFlapDemotedUntilMs = mutableMapOf<Route, Long>()
            fun markTunnelDisruption(atMs: Long, reason: String) {
                if (atMs <= lastTunnelDisruptionAtMs) return
                lastTunnelDisruptionAtMs = atMs
                lastTunnelDisruptionReason = reason
                Log.i(LOG_TAG, "tunnel disruption marked rsn=$reason")
            }
            fun isRouteCooldownActive(route: Route, atMs: Long): Boolean =
                when (route) {
                    Route.AWG_RU, Route.AWG -> isAwgCooldownActive(route, atMs)
                    else -> (routeCooldownUntilMs[route] ?: 0L) > atMs
                }
            fun routeCooldownDelaySeconds(route: Route, atMs: Long): Long =
                when (route) {
                    Route.AWG_RU, Route.AWG -> awgRetryDelaySeconds(route, atMs)
                    else -> (((routeCooldownUntilMs[route] ?: 0L) - atMs).coerceAtLeast(0) + 999) / 1000
                }
            fun demoteRoute(route: Route, atMs: Long, reason: String): Long {
                if (route == Route.AWG_RU || route == Route.AWG) {
                    return demoteAwg(route, atMs).backoffMs
                }
                val nextLevel = ((routeCooldownLevel[route] ?: 0) + 1).coerceAtMost(ROUTE_COOLDOWN_MAX_LEVEL)
                routeCooldownLevel[route] = nextLevel
                var backoffMs = ROUTE_COOLDOWN_BASE_MS
                repeat((nextLevel - 1).coerceAtLeast(0).coerceAtMost(ROUTE_COOLDOWN_MAX_SHIFT)) {
                    backoffMs = (backoffMs * 2).coerceAtMost(ROUTE_COOLDOWN_MAX_MS)
                }
                routeCooldownUntilMs[route] = atMs + backoffMs
                telemetryEvent("route_cooldown",
                    "rsn" to reason,
                    "route" to routeLabel(route),
                    "route_cd_s" to routeCooldownDelaySeconds(route, atMs),
                    "route_cd_level" to nextLevel,
                )
                return backoffMs
            }
            fun resetRouteCooldown(route: Route) {
                if (route == Route.AWG_RU || route == Route.AWG) return
                routeCooldownLevel[route] = 0
                routeCooldownUntilMs[route] = 0
            }
            fun isTcpRoute(route: Route): Boolean =
                route == Route.REALITY || route == Route.REALITY2
            fun pruneTcpHealthLosses(route: Route, atMs: Long) {
                val events = tcpRouteHealthLostEvents[route] ?: return
                while (events.isNotEmpty()) {
                    val first = events.peekFirst() ?: break
                    if (atMs - first <= TCP_ROUTE_FLAP_WINDOW_MS) break
                    events.removeFirst()
                }
            }
            fun recentTcpHealthLossCount(route: Route, atMs: Long): Int {
                if (!isTcpRoute(route)) return 0
                pruneTcpHealthLosses(route, atMs)
                return tcpRouteHealthLostEvents[route]?.size ?: 0
            }
            fun lastTcpHealthLostAt(route: Route, atMs: Long): Long {
                if (!isTcpRoute(route)) return 0L
                pruneTcpHealthLosses(route, atMs)
                return tcpRouteHealthLostEvents[route]?.peekLast() ?: 0L
            }
            fun isTcpRouteFlapDemoted(route: Route, atMs: Long): Boolean =
                isTcpRoute(route) && (tcpRouteFlapDemotedUntilMs[route] ?: 0L) > atMs
            fun recordTcpRouteHealthLost(route: Route, atMs: Long) {
                if (!isTcpRoute(route)) return
                val events = tcpRouteHealthLostEvents.getOrPut(route) { ArrayDeque() }
                pruneTcpHealthLosses(route, atMs)
                events.addLast(atMs)
                val demoteMs = tcpRouteFlapDemotionMs(events.size)
                if (demoteMs <= 0L) return
                val demotedUntilMs = atMs + demoteMs
                tcpRouteFlapDemotedUntilMs[route] = maxOf(tcpRouteFlapDemotedUntilMs[route] ?: 0L, demotedUntilMs)
                telemetryEvent("route_cooldown",
                    "rsn" to "tcp_flap",
                    "route" to routeLabel(route),
                    "route_cd_s" to ((tcpRouteFlapDemotedUntilMs[route] ?: demotedUntilMs) - atMs + 999) / 1000,
                    "route_cd_level" to events.size,
                )
            }
            fun tcpPriorityPromotable(route: Route, healthy: Boolean, atMs: Long): Boolean =
                if (!isTcpRoute(route) || !healthy || isTcpRouteFlapDemoted(route, atMs)) {
                    !isTcpRoute(route)
                } else {
                    shouldPromoteRecoveredPriorityRoute(
                        inactiveHealthySinceMs = routeHealthySinceMs[route] ?: 0L,
                        lastHealthLostAtMs = lastTcpHealthLostAt(route, atMs),
                        recentHealthLostCount = recentTcpHealthLossCount(route, atMs),
                        nowMs = atMs,
                    )
                }
            fun observeRouteHealth(
                route: Route,
                healthy: Boolean,
                atMs: Long,
                startOnRxProgress: Boolean = false,
                rxProgressed: Boolean = false,
            ) {
                if (!healthy) {
                    if (route != Route.AWG_RU && route != Route.AWG) {
                        routeHealthySinceMs[route] = 0
                        routeUnhealthySinceMs[route] = atMs
                        return
                    }
                    val unhealthySinceMs = routeUnhealthySinceMs[route].takeIf { it != null && it > 0L } ?: atMs
                    routeUnhealthySinceMs[route] = unhealthySinceMs
                    if ((routeLastHealthyAtMs[route] ?: 0L) == 0L || atMs - unhealthySinceMs >= HEALTH_LOSS_GRACE_MS) {
                        routeHealthySinceMs[route] = 0
                    }
                    return
                }
                routeUnhealthySinceMs[route] = 0
                routeLastHealthyAtMs[route] = atMs
                if (startOnRxProgress && !rxProgressed && (routeHealthySinceMs[route] ?: 0L) == 0L) {
                    return
                }
                if ((routeHealthySinceMs[route] ?: 0L) == 0L) {
                    routeHealthySinceMs[route] = atMs
                }
            }
            fun routeDwelled(route: Route, atMs: Long): Boolean {
                val sinceMs = routeHealthySinceMs[route] ?: 0L
                return sinceMs > 0L && atMs - sinceMs >= ROUTE_DWELL_MS
            }
            fun resetRecoveredInactiveRouteCooldown(route: Route, healthy: Boolean, atMs: Long) {
                if (route == activeRoute || !healthy || !routeDwelled(route, atMs) || !isRouteCooldownActive(route, atMs)) {
                    return
                }
                if (isTcpRoute(route) && !tcpPriorityPromotable(route, healthy, atMs)) {
                    return
                }
                resetRouteCooldown(route)
                telemetryEvent("route_cooldown_reset",
                    "rsn" to "inactive_recovered",
                    "route" to routeLabel(route),
                    "route_cd_s" to 0,
                    "route_cd_level" to 0,
                )
            }
            fun awgLocalRxFresh(route: Route, atMs: Long): Boolean =
                when (route) {
                    Route.AWG_RU -> isRecent(atMs, lastAwgRuRxProgressAtMs, AWG_CARRYING_EVIDENCE_MAX_AGE_MS)
                    Route.AWG -> isRecent(atMs, lastAwgRxProgressAtMs, AWG_CARRYING_EVIDENCE_MAX_AGE_MS)
                    else -> false
                }
            fun awgRxFreshForUsable(route: Route, atMs: Long): Boolean =
                when (route) {
                    Route.AWG_RU -> isRecent(atMs, lastAwgRuRxProgressAtMs, RX_FRESH_FOR_USABLE_MS)
                    Route.AWG -> isRecent(atMs, lastAwgRxProgressAtMs, RX_FRESH_FOR_USABLE_MS)
                    else -> false
                }
            fun awgLocallyHealthy(route: Route, probe: AWGProbeResult, atMs: Long): Boolean =
                probe.handshakeEstablished && awgLocalRxFresh(route, atMs)
            val clock = checkClock()
            try {
                if (!workerActive.get()) return@execute
                acquireWakeLock()
                Telemetry.flush(applicationContext)
                if (DeploymentConfig.IS_PUBLIC_PLATFORM) {
                    restorePublicPlatformRuntimeForService()
                }
                telemetryEvent("worker_start",
                    "mode" to requestedMode.name,
                    "skew_s" to clock.skewSeconds,
                )
                if (!clock.okForStart) {
                    telemetryEvent("clock_error",
                        "skew_s" to clock.skewSeconds,
                        "err_where" to "clock",
                        "err_kind" to "config",
                    )
                }
                var realityConfig = TransportRuntime.auth.reality
                var reality2Config = TransportRuntime.auth.reality2
                if (reality2Config?.isComplete() == true) {
                    val xrayStart = startXraySidecar(reality2Config, Route.REALITY2)
                    xray2Started = xrayStart.started
                    if (xrayStart.started) {
                        setAppliedReality2Uuid(reality2Config.uuid)
                    }
                    telemetryEvent("xray_start_result",
                        "route" to routeLabel(Route.REALITY2),
                        "rl2_started" to xrayStart.started,
                        "rl2_alive" to xrayStart.started,
                        "rl2_uid8" to realityUuid8(appliedReality2Uuid),
                        "err_where" to "xray2_start",
                        "err_kind" to xrayStart.errorKind,
                        "err_msg" to xrayStart.error,
                    )
                }
                if (realityConfig?.isComplete() == true) {
                    val xrayStart = startXraySidecar(realityConfig, Route.REALITY)
                    xrayStarted = xrayStart.started
                    telemetryEvent("xray_start_result",
                        "route" to routeLabel(Route.REALITY),
                        "rl_started" to xrayStart.started,
                        "rl_alive" to xrayStart.started,
                        "err_where" to "xray_start",
                        "err_kind" to xrayStart.errorKind,
                        "err_msg" to xrayStart.error,
                    )
                }

                if (
                    (requestedMode == TransportChoice.AUTO || requestedMode == TransportChoice.AWG_RU) &&
                    publicRouteConfigured(Route.AWG_RU)
                ) {
                    val awgStart = startAWGCore(Route.AWG_RU)
                    awgRuStarted = awgStart.started
                    telemetryEvent("awg_start_result",
                        "route" to routeLabel(Route.AWG_RU),
                        "awgru_started" to awgStart.started,
                        "awgru_start_err" to awgStart.error,
                        "err_where" to "awgru_start",
                        "err_kind" to awgStart.errorKind,
                    )
                }
                if (requestedMode == TransportChoice.AWG && publicRouteConfigured(Route.AWG)) {
                    val awgStart = startAWGCore(Route.AWG)
                    awgStarted = awgStart.started
                    telemetryEvent("awg_start_result",
                        "route" to routeLabel(Route.AWG),
                        "awg_started" to awgStart.started,
                        "awg_start_err" to awgStart.error,
                        "err_where" to "awg_start",
                        "err_kind" to awgStart.errorKind,
                    )
                }
                val startNowMs = SystemClock.elapsedRealtime()
                var nextPublicConfigPollAtMs = startNowMs + PUBLIC_CONFIG_POLL_INITIAL_DELAY_MS
                activeRoute = initialRoute(
                    mode = requestedMode,
                    awgRuStarted = awgRuStarted,
                    awgStarted = awgStarted,
                    realityStarted = xrayStarted,
                    reality2Started = xray2Started,
                    realityConfig = realityConfig,
                    reality2Config = reality2Config,
                )
                activeRoute = setRoute(
                    route = activeRoute,
                    mode = requestedMode,
                    awgRuStarted = awgRuStarted,
                    awgStarted = awgStarted,
                    realityStarted = xrayStarted,
                    reality2Started = xray2Started,
                    realityConfig = realityConfig,
                    reality2Config = reality2Config,
                )
                if (
                    requestedMode == TransportChoice.AUTO &&
                    activeRoute != Route.AWG_RU &&
                    awgRuStarted &&
                    isAwgCooldownActive(Route.AWG_RU, startNowMs)
                ) {
                    telemetryEvent("route_switch",
                        "rsn" to "awgru_cooldown",
                        "route" to routeLabel(activeRoute),
                        "awgru_demote" to awgDemotionLevel(Route.AWG_RU).get(),
                        "awgru_retry_s" to awgRetryDelaySeconds(Route.AWG_RU, startNowMs),
                    )
                }
                if (routeAvailable(activeRoute, awgRuStarted, awgStarted, xrayStarted, xray2Started, realityConfig, reality2Config)) {
                    router = startSocksRouter()
                } else {
                    telemetryEvent("route_guard",
                        "rsn" to ROUTE_REASON_NO_UPSTREAM,
                        "route" to routeLabel(activeRoute),
                    )
                }
                if (requestedMode == TransportChoice.AUTO && publicRouteConfigured(Route.AWG)) {
                    val awgStart = startAWGCore(Route.AWG)
                    awgStarted = awgStart.started
                    val awgStartDelayMs = if (awgStart.started) {
                        0L
                    } else if (awgUdpDeadFailures + 1 >= AWG_UDP_DEAD_FAILURES_BEFORE_PAUSE) {
                        AWG_UDP_DEAD_BACKOFF_MS
                    } else {
                        awgStartBackoffMs
                    }
                    val awgStartFailuresAfterAttempt = if (awgStart.started) 0 else awgUdpDeadFailures + 1
                    telemetryEvent("awg_start_result",
                        "rsn" to "background",
                        "route" to routeLabel(Route.AWG),
                        "awg_started" to awgStart.started,
                        "awg_start_err" to awgStart.error,
                        "awg_fail" to awgStartFailuresAfterAttempt,
                        "awg_udp_dead" to (awgStartFailuresAfterAttempt >= AWG_UDP_DEAD_FAILURES_BEFORE_PAUSE),
                        "backoff_ms" to awgStartDelayMs,
                        "err_where" to "awg_start",
                        "err_kind" to awgStart.errorKind,
                    )
                    if (awgStart.started) {
                        awgUdpDeadFailures = 0
                        awgStartBackoffMs = AWG_START_MIN_BACKOFF_MS
                        nextAwgStartAtMs = 0L
                    } else {
                        awgUdpDeadFailures++
                        nextAwgStartAtMs = startNowMs + awgStartDelayMs
                        awgStartBackoffMs = (awgStartBackoffMs * 2).coerceAtMost(AWG_START_MAX_BACKOFF_MS)
                    }
                }

                while (workerActive.get()) {
                    val nowMs = SystemClock.elapsedRealtime()
                    if (nowMs >= nextBatteryRestrictionNotifyCheckAtMs) {
                        BatteryRestrictionNotifier.maybeNotify(applicationContext)
                        nextBatteryRestrictionNotifyCheckAtMs = nowMs + BATTERY_RESTRICTION_NOTIFY_CHECK_INTERVAL_MS
                    }
                    val latestAuth = TransportRuntime.auth
                    if (latestAuth.reality?.isComplete() == true) {
                        realityConfig = latestAuth.reality
                    }
                    if (latestAuth.reality2?.isComplete() == true) {
                        reality2Config = latestAuth.reality2
                    }
                    if (xray2Process?.isAlive != true && appliedReality2Uuid.isNotBlank()) {
                        setAppliedReality2Uuid("")
                    }
                    val pendingNetworkEvent = networkEvent.getAndSet(null)
                    if (pendingNetworkEvent != null) {
                        if (pendingNetworkEvent.marksTunnelDisruption) {
                            markTunnelDisruption(nowMs, pendingNetworkEvent.logText)
                        } else {
                            router?.closeSessionsCreatedBefore(nowMs - RESYNC_SESSION_GRACE_MS)
                            lastTrafficAtMs = null
                            stableSinceElapsedRealtimeMs = null
                            lastHealthyRouteAtMs = null
                            Log.i(LOG_TAG, "${pendingNetworkEvent.logText}, sessions closed")
                        }
                        outboundIp = ""
                        lastOutboundProbeAtMs = 0L
                        lastAwgRuProbeAtMs = 0L
                        lastAwgProbeAtMs = 0L
                        lastRealityProbeAtMs = 0L
                        lastReality2ProbeAtMs = 0L
                        cachedRealityProbe = RealityProbeResult(false)
                        cachedReality2Probe = RealityProbeResult(false)
                        lastAwgRuEndToEndFailureAtMs = 0L
                        lastAwgEndToEndFailureAtMs = 0L
                        if (pendingNetworkEvent.marksTunnelDisruption) {
                            awgRuFailures = 0
                            awgRuHandshakeFailures = 0
                            awgRuOutboundFailures = 0
                            awgRuRetryFailures = 0
                            awgFailures = 0
                            awgHandshakeFailures = 0
                            awgOutboundFailures = 0
                            awgRetryFailures = 0
                            awgRuUdpDeadFailures = 0
                            awgUdpDeadFailures = 0
                            awgRuRekeyRequested.set(false)
                            awgRekeyRequested.set(false)
                            awgRuStartBackoffMs = AWG_START_MIN_BACKOFF_MS
                            awgStartBackoffMs = AWG_START_MIN_BACKOFF_MS
                            nextAwgRuStartAtMs = 0L
                            nextAwgStartAtMs = 0L
                            reconnectBackoffMs = RECONNECT_MIN_BACKOFF_MS
                        }
                        telemetryEvent("network_event",
                            "rsn" to pendingNetworkEvent.logText,
                            "route" to routeLabel(activeRoute),
                        )
                    }
                    val previousAwgRuHandshakeEstablished = lastAwgRuHandshakeEstablished
                    val previousAwgHandshakeEstablished = lastAwgHandshakeEstablished
                    val mode = requestedMode
                    if (
                        reality2Config?.isComplete() == true &&
                        shouldRestartReality2ForUuid(
                            appliedUuid = appliedReality2Uuid,
                            desiredUuid = reality2Config.uuid,
                            sidecarAlive = xray2Process?.isAlive == true,
                        )
                    ) {
                        val oldUid8 = realityUuid8(appliedReality2Uuid)
                        val newUid8 = realityUuid8(reality2Config.uuid)
                        Log.i(LOG_TAG, "REALITY2 uuid changed $oldUid8 -> $newUid8, restarting sidecar")
                        val xrayStart = startXraySidecar(
                            cfg = reality2Config,
                            route = Route.REALITY2,
                            forceRestart = true,
                        )
                        xray2Started = xrayStart.started
                        if (xrayStart.started) {
                            setAppliedReality2Uuid(reality2Config.uuid)
                            nextReality2RestartAtMs = 0L
                        } else {
                            setAppliedReality2Uuid("")
                            nextReality2RestartAtMs = nowMs + reconnectBackoffMs
                        }
                        telemetryEvent("xray_start_result",
                            "rsn" to "uuid_changed",
                            "route" to routeLabel(Route.REALITY2),
                            "rl2_started" to xrayStart.started,
                            "rl2_alive" to xrayStart.started,
                            "rl2_uid8" to realityUuid8(appliedReality2Uuid),
                            "err_where" to "xray2_uuid_restart",
                            "err_kind" to xrayStart.errorKind,
                            "err_msg" to xrayStart.error,
                        )
                    }
                    if (
                        !awgRuStarted &&
                        (mode == TransportChoice.AUTO || mode == TransportChoice.AWG_RU) &&
                        publicRouteConfigured(Route.AWG_RU) &&
                        nowMs >= nextAwgRuStartAtMs
                    ) {
                        val awgStart = startAWGCore(Route.AWG_RU)
                        awgRuStarted = awgStart.started
                        val awgStartDelayMs = if (awgStart.started) {
                            0L
                        } else if (awgRuUdpDeadFailures + 1 >= AWG_UDP_DEAD_FAILURES_BEFORE_PAUSE) {
                            AWG_UDP_DEAD_BACKOFF_MS
                        } else {
                            awgRuStartBackoffMs
                        }
                        val awgStartFailuresAfterAttempt = if (awgStart.started) 0 else awgRuUdpDeadFailures + 1
                        telemetryEvent("awg_start_result",
                            "rsn" to "retry",
                            "route" to routeLabel(Route.AWG_RU),
                            "awgru_started" to awgStart.started,
                            "awgru_start_err" to awgStart.error,
                            "awgru_fail" to awgStartFailuresAfterAttempt,
                            "awgru_udp_dead" to (awgStartFailuresAfterAttempt >= AWG_UDP_DEAD_FAILURES_BEFORE_PAUSE),
                            "backoff_ms" to awgStartDelayMs,
                            "err_where" to "awgru_start_retry",
                            "err_kind" to awgStart.errorKind,
                        )
                        if (awgStart.started) {
                            awgRuUdpDeadFailures = 0
                            awgRuStartBackoffMs = AWG_START_MIN_BACKOFF_MS
                            nextAwgRuStartAtMs = 0L
                        } else {
                            awgRuUdpDeadFailures++
                            nextAwgRuStartAtMs = nowMs + awgStartDelayMs
                            awgRuStartBackoffMs = (awgRuStartBackoffMs * 2).coerceAtMost(AWG_START_MAX_BACKOFF_MS)
                        }
                    }
                    if (
                        !awgStarted &&
                        (mode == TransportChoice.AUTO || mode == TransportChoice.AWG) &&
                        publicRouteConfigured(Route.AWG) &&
                        nowMs >= nextAwgStartAtMs
                    ) {
                        val awgStart = startAWGCore(Route.AWG)
                        awgStarted = awgStart.started
                        val awgStartDelayMs = if (awgStart.started) {
                            0L
                        } else if (awgUdpDeadFailures + 1 >= AWG_UDP_DEAD_FAILURES_BEFORE_PAUSE) {
                            AWG_UDP_DEAD_BACKOFF_MS
                        } else {
                            awgStartBackoffMs
                        }
                        val awgStartFailuresAfterAttempt = if (awgStart.started) 0 else awgUdpDeadFailures + 1
                        telemetryEvent("awg_start_result",
                            "rsn" to "retry",
                            "route" to routeLabel(Route.AWG),
                            "awg_started" to awgStart.started,
                            "awg_start_err" to awgStart.error,
                            "awg_fail" to awgStartFailuresAfterAttempt,
                            "awg_udp_dead" to (awgStartFailuresAfterAttempt >= AWG_UDP_DEAD_FAILURES_BEFORE_PAUSE),
                            "backoff_ms" to awgStartDelayMs,
                            "err_where" to "awg_start_retry",
                            "err_kind" to awgStart.errorKind,
                        )
                        if (awgStart.started) {
                            awgUdpDeadFailures = 0
                            awgStartBackoffMs = AWG_START_MIN_BACKOFF_MS
                            nextAwgStartAtMs = 0L
                        } else {
                            awgUdpDeadFailures++
                            nextAwgStartAtMs = nowMs + awgStartDelayMs
                            awgStartBackoffMs = (awgStartBackoffMs * 2).coerceAtMost(AWG_START_MAX_BACKOFF_MS)
                        }
                    }
                    if (
                        realityConfig?.isComplete() == true &&
                        xrayProcess?.isAlive != true &&
                        nowMs >= nextRealityRestartAtMs
                    ) {
                        val xrayStart = startXraySidecar(realityConfig, Route.REALITY)
                        xrayStarted = xrayStart.started
                        telemetryEvent("xray_start_result",
                            "rsn" to "restart",
                            "route" to routeLabel(Route.REALITY),
                            "rl_started" to xrayStart.started,
                            "rl_alive" to xrayStart.started,
                            "err_where" to "xray_restart",
                            "err_kind" to xrayStart.errorKind,
                            "err_msg" to xrayStart.error,
                        )
                        nextRealityRestartAtMs = nowMs + reconnectBackoffMs
                    }
                    if (
                        reality2Config?.isComplete() == true &&
                        xray2Process?.isAlive != true &&
                        nowMs >= nextReality2RestartAtMs
                    ) {
                        val xrayStart = startXraySidecar(reality2Config, Route.REALITY2)
                        xray2Started = xrayStart.started
                        if (xrayStart.started) {
                            setAppliedReality2Uuid(reality2Config.uuid)
                        } else {
                            setAppliedReality2Uuid("")
                        }
                        telemetryEvent("xray_start_result",
                            "rsn" to "restart",
                            "route" to routeLabel(Route.REALITY2),
                            "rl2_started" to xrayStart.started,
                            "rl2_alive" to xrayStart.started,
                            "rl2_uid8" to realityUuid8(appliedReality2Uuid),
                            "err_where" to "xray2_restart",
                            "err_kind" to xrayStart.errorKind,
                            "err_msg" to xrayStart.error,
                        )
                        nextReality2RestartAtMs = nowMs + reconnectBackoffMs
                    }
                    if (router == null) {
                        val guardedStartupRoute = selectAvailableRoute(
                            mode = mode,
                            preferred = activeRoute,
                            awgRuStarted = awgRuStarted,
                            awgStarted = awgStarted,
                            realityStarted = xrayStarted,
                            reality2Started = xray2Started,
                            realityConfig = realityConfig,
                            reality2Config = reality2Config,
                        )
                        if (routeAvailable(guardedStartupRoute, awgRuStarted, awgStarted, xrayStarted, xray2Started, realityConfig, reality2Config)) {
                            activeRoute = setRoute(
                                route = guardedStartupRoute,
                                mode = mode,
                                awgRuStarted = awgRuStarted,
                                awgStarted = awgStarted,
                                realityStarted = xrayStarted,
                                reality2Started = xray2Started,
                                realityConfig = realityConfig,
                                reality2Config = reality2Config,
                            )
                            router = startSocksRouter()
                            telemetryEvent("route_guard",
                                "rsn" to "router_started",
                                "route" to routeLabel(activeRoute),
                            )
                        }
                    }
                    val shouldProbeAwgRu = awgRuStarted && shouldProbeAWG(
                        nowMs = nowMs,
                        lastProbeAtMs = lastAwgRuProbeAtMs,
                        activeRoute = activeRoute,
                        route = Route.AWG_RU,
                        awgFailures = awgRuFailures,
                    )
                    var awgRuProbe = if (shouldProbeAwgRu) {
                        lastAwgRuProbeAtMs = nowMs
                        probeAWG(Route.AWG_RU)
                    } else {
                        cachedAwgRuProbe
                    }
                    val awgRuRxAdvanced = awgRuProbe.rxBytes > lastAwgRuRx
                    if (awgRuRxAdvanced) {
                        lastTrafficAtMs = nowMs
                        lastAwgRuRxProgressAtMs = nowMs
                    }
                    if (awgRuProbe.rxBytes != lastAwgRuRx || awgRuProbe.txBytes != lastAwgRuTx) {
                        lastAwgRuRx = awgRuProbe.rxBytes
                        lastAwgRuTx = awgRuProbe.txBytes
                    }
                    awgRuProbe = awgRuProbe.copy(
                        carrying = awgCarrying(
                            handshakeEstablished = awgRuProbe.handshakeEstablished,
                            nowMs = nowMs,
                            lastRxProgressAtMs = lastAwgRuRxProgressAtMs,
                            lastEndToEndProbeAtMs = lastAwgRuEndToEndProbeAtMs,
                            allowEndToEndProbe = activeRoute == Route.AWG_RU,
                        ),
                    )
                    if (shouldProbeAwgRu) {
                        if (
                            awgRuHandshakeObserved &&
                            !previousAwgRuHandshakeEstablished &&
                            awgRuProbe.handshakeEstablished &&
                            activeRoute == Route.AWG_RU
                        ) {
                            markTunnelDisruption(nowMs, "awgru_handshake_recovered")
                        }
                        awgRuHandshakeObserved = true
                        lastAwgRuHandshakeEstablished = awgRuProbe.handshakeEstablished
                        if (!awgRuProbe.handshakeEstablished) {
                            awgRuFailures++
                            awgRuHandshakeFailures++
                            awgRuUdpDeadFailures++
                            awgRuOutboundFailures = 0
                            if (awgRuFailures == AWG_FAILURES_BEFORE_FALLBACK ||
                                awgRuHandshakeFailures == AWG_REKEY_FAILURES_BEFORE_REFRESH
                            ) {
                                telemetryEvent("awg_probe_fail",
                                    "rsn" to "awgru_handshake",
                                    "route" to routeLabel(Route.AWG_RU),
                                    "awgru_hs" to false,
                                    "awgru_carry" to false,
                                    "awgru_rx" to awgRuProbe.rxBytes,
                                    "awgru_tx" to awgRuProbe.txBytes,
                                    "awgru_fail" to awgRuFailures,
                                    "awgru_udp_dead" to (awgRuUdpDeadFailures >= AWG_UDP_DEAD_FAILURES_BEFORE_PAUSE),
                                    "awgru_demote" to awgDemotionLevel(Route.AWG_RU).get(),
                                    "awgru_retry_s" to awgRetryDelaySeconds(Route.AWG_RU, nowMs),
                                    "backoff_ms" to reconnectBackoffMs,
                                )
                            }
                        } else if (awgRuProbe.carrying) {
                            awgRuFailures = 0
                            awgRuHandshakeFailures = 0
                            awgRuOutboundFailures = 0
                            awgRuUdpDeadFailures = 0
                            awgRuRekeyRequested.set(false)
                        }
                        cachedAwgRuProbe = awgRuProbe
                    }
                    val shouldProbeAwg = awgStarted && shouldProbeAWG(
                        nowMs = nowMs,
                        lastProbeAtMs = lastAwgProbeAtMs,
                        activeRoute = activeRoute,
                        route = Route.AWG,
                        awgFailures = awgFailures,
                    )
                    var awgProbe = if (shouldProbeAwg) {
                        lastAwgProbeAtMs = nowMs
                        probeAWG(Route.AWG)
                    } else {
                        cachedAwgProbe
                    }
                    val awgRxAdvanced = awgProbe.rxBytes > lastAwgRx
                    if (awgRxAdvanced) {
                        lastTrafficAtMs = nowMs
                        lastAwgRxProgressAtMs = nowMs
                    }
                    if (awgProbe.rxBytes != lastAwgRx || awgProbe.txBytes != lastAwgTx) {
                        lastAwgRx = awgProbe.rxBytes
                        lastAwgTx = awgProbe.txBytes
                    }
                    awgProbe = awgProbe.copy(
                        carrying = awgCarrying(
                            handshakeEstablished = awgProbe.handshakeEstablished,
                            nowMs = nowMs,
                            lastRxProgressAtMs = lastAwgRxProgressAtMs,
                            lastEndToEndProbeAtMs = lastAwgEndToEndProbeAtMs,
                            allowEndToEndProbe = activeRoute == Route.AWG,
                        ),
                    )
                    if (shouldProbeAwg) {
                        if (
                            awgHandshakeObserved &&
                            !previousAwgHandshakeEstablished &&
                            awgProbe.handshakeEstablished &&
                            activeRoute == Route.AWG
                        ) {
                            markTunnelDisruption(nowMs, "awg_handshake_recovered")
                        }
                        awgHandshakeObserved = true
                        lastAwgHandshakeEstablished = awgProbe.handshakeEstablished
                        if (!awgProbe.handshakeEstablished) {
                            awgFailures++
                            awgHandshakeFailures++
                            awgUdpDeadFailures++
                            awgOutboundFailures = 0
                            if (awgFailures == AWG_FAILURES_BEFORE_FALLBACK ||
                                awgHandshakeFailures == AWG_REKEY_FAILURES_BEFORE_REFRESH
                            ) {
                                telemetryEvent("awg_probe_fail",
                                    "rsn" to "awg_handshake",
                                    "awg_hs" to false,
                                    "awg_carry" to false,
                                    "awg_rx" to awgProbe.rxBytes,
                                    "awg_tx" to awgProbe.txBytes,
                                    "awg_fail" to awgFailures,
                                    "awg_udp_dead" to (awgUdpDeadFailures >= AWG_UDP_DEAD_FAILURES_BEFORE_PAUSE),
                                    "awg_demote" to awgDemotionLevel(Route.AWG).get(),
                                    "awg_retry_s" to awgRetryDelaySeconds(Route.AWG, nowMs),
                                    "backoff_ms" to reconnectBackoffMs,
                                    "route" to routeLabel(activeRoute),
                                )
                            }
                        } else if (awgProbe.carrying) {
                            awgFailures = 0
                            awgHandshakeFailures = 0
                            awgOutboundFailures = 0
                            awgUdpDeadFailures = 0
                            awgRekeyRequested.set(false)
                        }
                        cachedAwgProbe = awgProbe
                    }
                    val currentRealityRx = realityRxBytes.get()
                    val currentRealityTx = realityTxBytes.get()
                    if (currentRealityRx > lastRealityRx) {
                        lastTrafficAtMs = nowMs
                        lastRealityRxProgressAtMs = nowMs
                    }
                    if (currentRealityRx != lastRealityRx || currentRealityTx != lastRealityTx) {
                        lastRealityRx = currentRealityRx
                        lastRealityTx = currentRealityTx
                    }
                    val currentReality2Rx = reality2RxBytes.get()
                    val currentReality2Tx = reality2TxBytes.get()
                    if (currentReality2Rx > lastReality2Rx) {
                        lastTrafficAtMs = nowMs
                        lastReality2RxProgressAtMs = nowMs
                    }
                    if (currentReality2Rx != lastReality2Rx || currentReality2Tx != lastReality2Tx) {
                        lastReality2Rx = currentReality2Rx
                        lastReality2Tx = currentReality2Tx
                    }
                    if (xrayStarted && shouldProbeReality(
                            nowMs = nowMs,
                            lastProbeAtMs = lastRealityProbeAtMs,
                            activeRoute = activeRoute,
                            route = Route.REALITY,
                            localRxFresh = isRecent(nowMs, lastRealityRxProgressAtMs, REALITY_LOCAL_RX_FRESH_MS),
                        )
                    ) {
                        cachedRealityProbe = probeReality(Route.REALITY, realityConfig)
                        lastRealityProbeAtMs = nowMs
                    }
                    val realityProbe = if (xrayStarted) cachedRealityProbe else RealityProbeResult(false)
                    val realityHealthy = xrayStarted && realityProbe.healthy
                    if (xray2Started && shouldProbeReality(
                            nowMs = nowMs,
                            lastProbeAtMs = lastReality2ProbeAtMs,
                            activeRoute = activeRoute,
                            route = Route.REALITY2,
                            localRxFresh = isRecent(nowMs, lastReality2RxProgressAtMs, REALITY_LOCAL_RX_FRESH_MS),
                        )
                    ) {
                        cachedReality2Probe = probeReality(Route.REALITY2, reality2Config)
                        lastReality2ProbeAtMs = nowMs
                    }
                    val reality2Probe = if (xray2Started) cachedReality2Probe else RealityProbeResult(false)
                    val reality2Healthy = xray2Started && reality2Probe.healthy
                    if (activeRoute == Route.REALITY && realityHealthy) {
                        outboundIp = realityProbe.outboundIp
                        lastTrafficAtMs = nowMs
                    } else if (activeRoute == Route.REALITY2 && reality2Healthy) {
                        outboundIp = reality2Probe.outboundIp
                        lastTrafficAtMs = nowMs
                    }
                    if (xrayStarted && realityConfig?.isComplete() == true && !realityHealthy) {
                        telemetryEvent("reality_probe_fail",
                            "rsn" to "carry_gate",
                            "route" to routeLabel(Route.REALITY),
                            "rl_started" to xrayStarted,
                            "rl_alive" to (xrayProcess?.isAlive == true),
                            "rl_tcp_ok" to false,
                            "rl_carry" to false,
                            "rl_tcp_err" to realityProbe.tcpError,
                            "rl_rx" to currentRealityRx,
                            "rl_tx" to currentRealityTx,
                            "backoff_ms" to reconnectBackoffMs,
                        )
                    }
                    if (xray2Started && reality2Config?.isComplete() == true && !reality2Healthy) {
                        telemetryEvent("reality_probe_fail",
                            "rsn" to "carry_gate",
                            "route" to routeLabel(Route.REALITY2),
                            "rl2_started" to xray2Started,
                            "rl2_alive" to (xray2Process?.isAlive == true),
                            "rl2_carry" to false,
                            "rl2_err" to reality2Probe.tcpError,
                            "rl2_rx" to currentReality2Rx,
                            "rl2_tx" to currentReality2Tx,
                            "backoff_ms" to reconnectBackoffMs,
                        )
                    }
                    if (
                        awgRuStarted &&
                        (mode == TransportChoice.AUTO || mode == TransportChoice.AWG_RU) &&
                        awgRuHandshakeFailures >= AWG_REKEY_FAILURES_BEFORE_REFRESH &&
                        awgRuRekeyRequested.compareAndSet(false, true)
                    ) {
                        val demotion = demoteAwg(Route.AWG_RU, nowMs)
                        nextAwgRuStartAtMs = maxOf(nextAwgRuStartAtMs, nowMs + AWG_UDP_DEAD_BACKOFF_MS)
                        Log.w(LOG_TAG, "AWG-RU handshake unhealthy for $awgRuHandshakeFailures probes, keeping existing keys")
                        telemetryEvent("awg_probe_fail",
                            "rsn" to "awgru_probe_threshold",
                            "route" to routeLabel(Route.AWG_RU),
                            "awgru_rekey" to false,
                            "awgru_fail" to awgRuHandshakeFailures,
                            "awgru_hs" to awgRuProbe.handshakeEstablished,
                            "awgru_carry" to awgRuProbe.carrying,
                            "awgru_rx" to awgRuProbe.rxBytes,
                            "awgru_tx" to awgRuProbe.txBytes,
                            "awgru_demote" to demotion.level,
                            "awgru_retry_s" to awgRetryDelaySeconds(Route.AWG_RU, nowMs),
                            "backoff_ms" to reconnectBackoffMs,
                            "awgru_udp_dead" to (awgRuUdpDeadFailures >= AWG_UDP_DEAD_FAILURES_BEFORE_PAUSE),
                            "awgru_udp_dead_backoff_ms" to AWG_UDP_DEAD_BACKOFF_MS,
                        )
                    }
                    if (
                        awgStarted &&
                        (mode == TransportChoice.AUTO || mode == TransportChoice.AWG) &&
                        awgHandshakeFailures >= AWG_REKEY_FAILURES_BEFORE_REFRESH &&
                        awgRekeyRequested.compareAndSet(false, true)
                    ) {
                        val demotion = demoteAwg(Route.AWG, nowMs)
                        nextAwgStartAtMs = maxOf(nextAwgStartAtMs, nowMs + AWG_UDP_DEAD_BACKOFF_MS)
                        Log.w(LOG_TAG, "AWG handshake unhealthy for $awgHandshakeFailures probes, keeping existing keys")
                        telemetryEvent("awg_probe_fail",
                            "rsn" to "awg_probe_threshold",
                            "awg_rekey" to false,
                            "awg_fail" to awgHandshakeFailures,
                            "awg_hs" to awgProbe.handshakeEstablished,
                            "awg_carry" to awgProbe.carrying,
                            "awg_rx" to awgProbe.rxBytes,
                            "awg_tx" to awgProbe.txBytes,
                            "awg_demote" to demotion.level,
                            "awg_retry_s" to awgRetryDelaySeconds(Route.AWG, nowMs),
                            "backoff_ms" to reconnectBackoffMs,
                            "awg_udp_dead" to (awgUdpDeadFailures >= AWG_UDP_DEAD_FAILURES_BEFORE_PAUSE),
                            "awg_udp_dead_backoff_ms" to AWG_UDP_DEAD_BACKOFF_MS,
                        )
                    }

                    val activeAwgRxStalled =
                        (activeRoute == Route.AWG_RU &&
                            awgRuProbe.handshakeEstablished &&
                            !awgLocalRxFresh(Route.AWG_RU, nowMs)) ||
                            (activeRoute == Route.AWG &&
                                awgProbe.handshakeEstablished &&
                                !awgLocalRxFresh(Route.AWG, nowMs))
                    if (
                        router != null &&
                        (
                            lastOutboundProbeAtMs == 0L ||
                                nowMs - lastOutboundProbeAtMs >= OUTBOUND_REFRESH_INTERVAL_MS ||
                                (activeRoute == Route.AWG_RU && awgRuProbe.handshakeEstablished && !awgRuProbe.carrying) ||
                                (activeRoute == Route.AWG && awgProbe.handshakeEstablished && !awgProbe.carrying)
                            )
                    ) {
                        lastOutboundProbeAtMs = nowMs
                        val outboundTimeoutMs = if (activeAwgRxStalled) {
                            ACTIVE_AWG_STALL_OUTBOUND_TIMEOUT_MS
                        } else {
                            OUTBOUND_TIMEOUT_MS
                        }
                        runCatching { fetchOutboundIp(ROUTER_SOCKS, outboundTimeoutMs) }
                            .onSuccess { ip ->
                                val egressMatchesRoute = outboundMatchesRoute(activeRoute, ip)
                                if (egressMatchesRoute) {
                                    outboundIp = ip
                                    lastTrafficAtMs = nowMs
                                    reconnectBackoffMs = RECONNECT_MIN_BACKOFF_MS
                                    if (activeRoute == Route.AWG_RU) {
                                        lastAwgRuEndToEndProbeAtMs = nowMs
                                        lastAwgRuEndToEndFailureAtMs = 0L
                                        awgRuOutboundFailures = 0
                                        awgRuFailures = 0
                                        awgRuHandshakeFailures = 0
                                        awgRuRetryFailures = 0
                                        awgRuUdpDeadFailures = 0
                                        awgRuRekeyRequested.set(false)
                                        awgRuProbe = awgRuProbe.copy(
                                            carrying = awgCarrying(
                                                handshakeEstablished = awgRuProbe.handshakeEstablished,
                                                nowMs = nowMs,
                                                lastRxProgressAtMs = lastAwgRuRxProgressAtMs,
                                                lastEndToEndProbeAtMs = lastAwgRuEndToEndProbeAtMs,
                                                allowEndToEndProbe = true,
                                            ),
                                        )
                                        cachedAwgRuProbe = awgRuProbe
                                    } else if (activeRoute == Route.AWG) {
                                        lastAwgEndToEndProbeAtMs = nowMs
                                        lastAwgEndToEndFailureAtMs = 0L
                                        awgOutboundFailures = 0
                                        awgFailures = 0
                                        awgHandshakeFailures = 0
                                        awgRetryFailures = 0
                                        awgUdpDeadFailures = 0
                                        awgRekeyRequested.set(false)
                                        awgProbe = awgProbe.copy(
                                            carrying = awgCarrying(
                                                handshakeEstablished = awgProbe.handshakeEstablished,
                                                nowMs = nowMs,
                                                lastRxProgressAtMs = lastAwgRxProgressAtMs,
                                                lastEndToEndProbeAtMs = lastAwgEndToEndProbeAtMs,
                                                allowEndToEndProbe = true,
                                            ),
                                        )
                                        cachedAwgProbe = awgProbe
                                    }
                                }
                                telemetryEvent("outbound_probe",
                                    "route" to routeLabel(activeRoute),
                                    "healthy" to routeHealthy(
                                        route = activeRoute,
                                        awgRuProbe = awgRuProbe,
                                        awgProbe = awgProbe,
                                        realityHealthy = realityHealthy,
                                        reality2Healthy = reality2Healthy,
                                        outboundIp = if (egressMatchesRoute) ip else "",
                                    ),
                                    "awgru_hs" to awgRuProbe.handshakeEstablished,
                                    "awgru_carry" to awgRuProbe.carrying,
                                    "awgru_demote" to awgDemotionLevel(Route.AWG_RU).get(),
                                    "awgru_retry_s" to awgRetryDelaySeconds(Route.AWG_RU, nowMs),
                                    "awg_hs" to awgProbe.handshakeEstablished,
                                    "awg_carry" to awgProbe.carrying,
                                    "awg_demote" to awgDemotionLevel(Route.AWG).get(),
                                    "awg_retry_s" to awgRetryDelaySeconds(Route.AWG, nowMs),
                                    "rl_egress" to realityEgressClass(activeRoute, ip),
                                    "rl_carry" to realityHealthy,
                                    "rl2_carry" to reality2Healthy,
                                )
                            }
                            .onFailure { error ->
                                if (activeRoute == Route.AWG_RU) {
                                    awgRuOutboundFailures++
                                    lastAwgRuEndToEndFailureAtMs = nowMs
                                    if (awgRuProbe.handshakeEstablished) {
                                        awgRuFailures++
                                        awgRuProbe = awgRuProbe.copy(
                                            carrying = awgCarrying(
                                                handshakeEstablished = awgRuProbe.handshakeEstablished,
                                                nowMs = nowMs,
                                                lastRxProgressAtMs = lastAwgRuRxProgressAtMs,
                                                lastEndToEndProbeAtMs = lastAwgRuEndToEndProbeAtMs,
                                                allowEndToEndProbe = true,
                                            ),
                                        )
                                        cachedAwgRuProbe = awgRuProbe
                                    }
                                } else if (activeRoute == Route.AWG) {
                                    awgOutboundFailures++
                                    lastAwgEndToEndFailureAtMs = nowMs
                                    if (awgProbe.handshakeEstablished) {
                                        awgFailures++
                                        awgProbe = awgProbe.copy(
                                            carrying = awgCarrying(
                                                handshakeEstablished = awgProbe.handshakeEstablished,
                                                nowMs = nowMs,
                                                lastRxProgressAtMs = lastAwgRxProgressAtMs,
                                                lastEndToEndProbeAtMs = lastAwgEndToEndProbeAtMs,
                                                allowEndToEndProbe = true,
                                            ),
                                        )
                                        cachedAwgProbe = awgProbe
                                    }
                                }
                                if ((lastTrafficAtMs?.let { nowMs - it } ?: Long.MAX_VALUE) > STABLE_TRAFFIC_MAX_AGE_MS) {
                                    outboundIp = ""
                                }
                                telemetryEvent("outbound_probe",
                                    "route" to routeLabel(activeRoute),
                                    "healthy" to false,
                                    "awgru_hs" to awgRuProbe.handshakeEstablished,
                                    "awgru_carry" to awgRuProbe.carrying,
                                    "awgru_fail" to awgRuFailures,
                                    "awgru_demote" to awgDemotionLevel(Route.AWG_RU).get(),
                                    "awgru_retry_s" to awgRetryDelaySeconds(Route.AWG_RU, nowMs),
                                    "awg_hs" to awgProbe.handshakeEstablished,
                                    "awg_carry" to awgProbe.carrying,
                                    "awg_fail" to awgFailures,
                                    "awg_demote" to awgDemotionLevel(Route.AWG).get(),
                                    "awg_retry_s" to awgRetryDelaySeconds(Route.AWG, nowMs),
                                    "rl_egress" to "",
                                    "rl_carry" to realityHealthy,
                                    "rl2_carry" to reality2Healthy,
                                    "err_where" to "outbound_probe",
                                    "err_kind" to Telemetry.errorKind(error),
                                    "err_msg" to Telemetry.safeErrorMessage(error),
                                )
                            }
                    }
                    val activeRouteCurrentlyHealthy = routeHealthy(
                        route = activeRoute,
                        awgRuProbe = awgRuProbe,
                        awgProbe = awgProbe,
                        realityHealthy = realityHealthy,
                        reality2Healthy = reality2Healthy,
                        outboundIp = outboundIp,
                    )
                    val activeRealityUsable = when (activeRoute) {
                        Route.REALITY -> routeHealthy(
                            route = activeRoute,
                            awgRuProbe = awgRuProbe,
                            awgProbe = awgProbe,
                            realityHealthy = realityHealthy,
                            reality2Healthy = reality2Healthy,
                            outboundIp = outboundIp,
                        )
                        Route.REALITY2 -> routeHealthy(
                            route = activeRoute,
                            awgRuProbe = awgRuProbe,
                            awgProbe = awgProbe,
                            realityHealthy = realityHealthy,
                            reality2Healthy = reality2Healthy,
                            outboundIp = outboundIp,
                        )
                        Route.AWG_RU, Route.AWG -> reality2Healthy || realityHealthy
                    }
                    if (
                        mode == TransportChoice.AUTO &&
                        activeRoute != Route.AWG_RU &&
                        awgRuStarted &&
                        shouldProbeAwgRetry(
                            nowMs = nowMs,
                            lastProbeAtMs = lastAwgRuRetryProbeAtMs,
                            route = Route.AWG_RU,
                            activeRoute = activeRoute,
                            activeHealthy = activeRouteCurrentlyHealthy,
                            activeStableSinceMs = stableSinceElapsedRealtimeMs,
                            realityUsable = activeRealityUsable,
                            retryFailures = awgRuRetryFailures,
                            udpDeadFailures = awgRuUdpDeadFailures,
                        )
                    ) {
                        lastAwgRuRetryProbeAtMs = nowMs
                        runCatching { fetchOutboundIp("${AWG_RU_UPSTREAM.host}:${AWG_RU_UPSTREAM.port}", OUTBOUND_TIMEOUT_MS) }
                            .onSuccess {
                                lastAwgRuRetryOkAtMs = nowMs
                                awgRuRetryFailures = 0
                                awgRuProbe = awgRuProbe.copy(
                                    carrying = awgCarrying(
                                        handshakeEstablished = awgRuProbe.handshakeEstablished,
                                        nowMs = nowMs,
                                        lastRxProgressAtMs = lastAwgRuRxProgressAtMs,
                                        lastEndToEndProbeAtMs = lastAwgRuEndToEndProbeAtMs,
                                        allowEndToEndProbe = false,
                                    ),
                                )
                                cachedAwgRuProbe = awgRuProbe
                                telemetryEvent("outbound_probe",
                                    "rsn" to "awgru_retry",
                                    "route" to routeLabel(Route.AWG_RU),
                                    "healthy" to activeRouteCurrentlyHealthy,
                                    "awgru_hs" to awgRuProbe.handshakeEstablished,
                                    "awgru_carry" to awgRuProbe.carrying,
                                    "awgru_demote" to awgDemotionLevel(Route.AWG_RU).get(),
                                    "awgru_retry_s" to awgRetryDelaySeconds(Route.AWG_RU, nowMs),
                                    "awg_carry" to awgProbe.carrying,
                                    "rl_carry" to realityHealthy,
                                    "rl2_carry" to reality2Healthy,
                                )
                            }
                            .onFailure { error ->
                                awgRuRetryFailures++
                                awgRuOutboundFailures++
                                val shouldDemoteRetry =
                                    activeRealityUsable &&
                                        awgRuRetryFailures >= AWG_RETRY_FAILURES_BEFORE_DEMOTE &&
                                        !awgLocallyHealthy(Route.AWG_RU, awgRuProbe, nowMs) &&
                                        !isRecent(nowMs, lastAwgRuRetryOkAtMs, OUTBOUND_REFRESH_INTERVAL_MS)
                                if (shouldDemoteRetry) {
                                    awgRuFailures++
                                    val demotion = demoteAwg(Route.AWG_RU, nowMs)
                                    telemetryEvent("awg_probe_fail",
                                        "rsn" to "awgru_retry",
                                        "route" to routeLabel(activeRoute),
                                        "awgru_hs" to awgRuProbe.handshakeEstablished,
                                        "awgru_carry" to awgRuProbe.carrying,
                                        "awgru_rx" to awgRuProbe.rxBytes,
                                        "awgru_tx" to awgRuProbe.txBytes,
                                        "awgru_fail" to awgRuFailures,
                                        "awgru_demote" to demotion.level,
                                        "awgru_retry_s" to awgRetryDelaySeconds(Route.AWG_RU, nowMs),
                                        "backoff_ms" to demotion.backoffMs,
                                        "err_where" to "awgru_retry",
                                        "err_kind" to Telemetry.errorKind(error),
                                        "err_msg" to Telemetry.safeErrorMessage(error),
                                    )
                                }
                            }
                    }
                    if (
                        mode == TransportChoice.AUTO &&
                        activeRoute != Route.AWG &&
                        awgStarted &&
                        shouldProbeAwgRetry(
                            nowMs = nowMs,
                            lastProbeAtMs = lastAwgRetryProbeAtMs,
                            route = Route.AWG,
                            activeRoute = activeRoute,
                            activeHealthy = activeRouteCurrentlyHealthy,
                            activeStableSinceMs = stableSinceElapsedRealtimeMs,
                            realityUsable = activeRealityUsable,
                            retryFailures = awgRetryFailures,
                            udpDeadFailures = awgUdpDeadFailures,
                        )
                    ) {
                        lastAwgRetryProbeAtMs = nowMs
                        runCatching { fetchOutboundIp("${AWG_UPSTREAM.host}:${AWG_UPSTREAM.port}", OUTBOUND_TIMEOUT_MS) }
                            .onSuccess {
                                lastAwgRetryOkAtMs = nowMs
                                awgRetryFailures = 0
                                awgProbe = awgProbe.copy(
                                    carrying = awgCarrying(
                                        handshakeEstablished = awgProbe.handshakeEstablished,
                                        nowMs = nowMs,
                                        lastRxProgressAtMs = lastAwgRxProgressAtMs,
                                        lastEndToEndProbeAtMs = lastAwgEndToEndProbeAtMs,
                                        allowEndToEndProbe = false,
                                    ),
                                )
                                cachedAwgProbe = awgProbe
                                telemetryEvent("outbound_probe",
                                    "rsn" to "awg_retry",
                                    "route" to routeLabel(Route.AWG),
                                    "healthy" to activeRouteCurrentlyHealthy,
                                    "awgru_carry" to awgRuProbe.carrying,
                                    "awg_hs" to awgProbe.handshakeEstablished,
                                    "awg_carry" to awgProbe.carrying,
                                    "awg_demote" to awgDemotionLevel(Route.AWG).get(),
                                    "awg_retry_s" to awgRetryDelaySeconds(Route.AWG, nowMs),
                                    "rl_carry" to realityHealthy,
                                    "rl2_carry" to reality2Healthy,
                                )
                            }
                            .onFailure { error ->
                                awgRetryFailures++
                                awgOutboundFailures++
                                val shouldDemoteRetry =
                                    activeRealityUsable &&
                                        awgRetryFailures >= AWG_RETRY_FAILURES_BEFORE_DEMOTE &&
                                        !awgLocallyHealthy(Route.AWG, awgProbe, nowMs) &&
                                        !isRecent(nowMs, lastAwgRetryOkAtMs, OUTBOUND_REFRESH_INTERVAL_MS)
                                if (shouldDemoteRetry) {
                                    awgFailures++
                                    val demotion = demoteAwg(Route.AWG, nowMs)
                                    telemetryEvent("awg_probe_fail",
                                        "rsn" to "awg_retry",
                                        "route" to routeLabel(activeRoute),
                                        "awg_hs" to awgProbe.handshakeEstablished,
                                        "awg_carry" to awgProbe.carrying,
                                        "awg_rx" to awgProbe.rxBytes,
                                        "awg_tx" to awgProbe.txBytes,
                                        "awg_fail" to awgFailures,
                                        "awg_demote" to demotion.level,
                                        "awg_retry_s" to awgRetryDelaySeconds(Route.AWG, nowMs),
                                        "backoff_ms" to demotion.backoffMs,
                                        "err_where" to "awg_retry",
                                        "err_kind" to Telemetry.errorKind(error),
                                        "err_msg" to Telemetry.safeErrorMessage(error),
                                    )
                                }
                            }
                    }
                    awgRuProbe = awgRuProbe.copy(
                        carrying = awgCarrying(
                            handshakeEstablished = awgRuProbe.handshakeEstablished,
                            nowMs = nowMs,
                            lastRxProgressAtMs = lastAwgRuRxProgressAtMs,
                            lastEndToEndProbeAtMs = lastAwgRuEndToEndProbeAtMs,
                            allowEndToEndProbe = activeRoute == Route.AWG_RU,
                        ),
                    )
                    cachedAwgRuProbe = awgRuProbe
                    awgProbe = awgProbe.copy(
                        carrying = awgCarrying(
                            handshakeEstablished = awgProbe.handshakeEstablished,
                            nowMs = nowMs,
                            lastRxProgressAtMs = lastAwgRxProgressAtMs,
                            lastEndToEndProbeAtMs = lastAwgEndToEndProbeAtMs,
                            allowEndToEndProbe = activeRoute == Route.AWG,
                        ),
                    )
                    cachedAwgProbe = awgProbe
                    val awgFastFail = activeRoute == Route.AWG &&
                        shouldFastFailActiveAwg(
                            handshakeEstablished = awgProbe.handshakeEstablished,
                            carrying = awgProbe.carrying,
                            rxStalled = !awgLocalRxFresh(Route.AWG, nowMs),
                            activeEndToEndProbeFailed = isRecent(
                                nowMs,
                                lastAwgEndToEndFailureAtMs,
                                ACTIVE_AWG_FAST_FAIL_FAILURE_MAX_AGE_MS,
                            ),
                        )
                    val awgRuFastFail = activeRoute == Route.AWG_RU &&
                        shouldFastFailActiveAwg(
                            handshakeEstablished = awgRuProbe.handshakeEstablished,
                            carrying = awgRuProbe.carrying,
                            rxStalled = !awgLocalRxFresh(Route.AWG_RU, nowMs),
                            activeEndToEndProbeFailed = isRecent(
                                nowMs,
                                lastAwgRuEndToEndFailureAtMs,
                                ACTIVE_AWG_FAST_FAIL_FAILURE_MAX_AGE_MS,
                            ),
                        )
                    val awgNotCarrying = awgStarted &&
                        awgProbe.handshakeEstablished &&
                        !awgProbe.carrying &&
                        (awgFastFail || awgOutboundFailures >= AWG_OUTBOUND_FAILURES_BEFORE_NOT_CARRYING)
                    val awgRuNotCarrying = awgRuStarted &&
                        awgRuProbe.handshakeEstablished &&
                        !awgRuProbe.carrying &&
                        (awgRuFastFail || awgRuOutboundFailures >= AWG_OUTBOUND_FAILURES_BEFORE_NOT_CARRYING)
                    observeAwgCarrying(Route.AWG_RU, nowMs, awgRuProbe.carrying)
                    observeAwgCarrying(Route.AWG, nowMs, awgProbe.carrying)
                    observeRouteHealth(Route.REALITY2, reality2Healthy, nowMs)
                    observeRouteHealth(Route.REALITY, realityHealthy, nowMs)
                    observeRouteHealth(
                        route = Route.AWG_RU,
                        healthy = awgRuProbe.handshakeEstablished,
                        atMs = nowMs,
                        startOnRxProgress = true,
                        rxProgressed = awgRuRxAdvanced,
                    )
                    observeRouteHealth(
                        route = Route.AWG,
                        healthy = awgProbe.handshakeEstablished,
                        atMs = nowMs,
                        startOnRxProgress = true,
                        rxProgressed = awgRxAdvanced,
                    )
                    resetRecoveredInactiveRouteCooldown(Route.AWG_RU, awgRuProbe.carrying, nowMs)
                    resetRecoveredInactiveRouteCooldown(Route.AWG, awgProbe.carrying, nowMs)
                    resetRecoveredInactiveRouteCooldown(Route.REALITY2, reality2Healthy, nowMs)
                    resetRecoveredInactiveRouteCooldown(Route.REALITY, realityHealthy, nowMs)
                    val activeRouteHealthyNow = routeHealthy(
                        route = activeRoute,
                        awgRuProbe = awgRuProbe,
                        awgProbe = awgProbe,
                        realityHealthy = realityHealthy,
                        reality2Healthy = reality2Healthy,
                        outboundIp = outboundIp,
                    )
                    var activeRouteDemoted = false
                    if (routeHealthObserved && lastRouteHealthy && !activeRouteHealthyNow) {
                        recordTcpRouteHealthLost(activeRoute, nowMs)
                        demoteRoute(activeRoute, nowMs, ROUTE_REASON_HEALTH_LOST)
                        activeRouteDemoted = true
                    }
                    val reality2Usable = reality2Healthy &&
                        (activeRoute == Route.REALITY2 || routeDwelled(Route.REALITY2, nowMs)) &&
                        !isRouteCooldownActive(Route.REALITY2, nowMs)
                    val realityUsable = realityHealthy &&
                        (activeRoute == Route.REALITY || routeDwelled(Route.REALITY, nowMs)) &&
                        !isRouteCooldownActive(Route.REALITY, nowMs)
                    val awgRuUsable = awgRuStarted &&
                        (
                            if (activeRoute == Route.AWG_RU) {
                                awgRuProbe.carrying
                            } else {
                                awgRuProbe.handshakeEstablished &&
                                    routeDwelled(Route.AWG_RU, nowMs) &&
                                    awgRxFreshForUsable(Route.AWG_RU, nowMs)
                            }
                            ) &&
                        !isRouteCooldownActive(Route.AWG_RU, nowMs)
                    val awgUsable = awgStarted &&
                        (
                            if (activeRoute == Route.AWG) {
                                awgProbe.carrying
                            } else {
                                awgProbe.handshakeEstablished &&
                                    routeDwelled(Route.AWG, nowMs) &&
                                    awgRxFreshForUsable(Route.AWG, nowMs)
                            }
                            ) &&
                        !isRouteCooldownActive(Route.AWG, nowMs)
                    val routeDecision = chooseRoute(
                        mode = mode,
                        active = activeRoute,
                        awgRuStarted = awgRuStarted,
                        awgRuFailures = awgRuFailures,
                        awgRuUsable = awgRuUsable,
                        awgRuNotCarrying = awgRuNotCarrying,
                        awgStarted = awgStarted,
                        awgFailures = awgFailures,
                        awgUsable = awgUsable,
                        awgNotCarrying = awgNotCarrying,
                        realityUsable = realityUsable,
                        reality2Usable = reality2Usable,
                        reality2PriorityPromotable = tcpPriorityPromotable(Route.REALITY2, reality2Healthy, nowMs),
                        activeHealthy = activeRouteHealthyNow,
                    )
                    val guardedRoute = selectAvailableRoute(
                        mode = mode,
                        preferred = routeDecision.route,
                        awgRuStarted = awgRuStarted,
                        awgStarted = awgStarted,
                        realityStarted = xrayStarted,
                        reality2Started = xray2Started,
                        realityConfig = realityConfig,
                        reality2Config = reality2Config,
                    )
                    val guardedReason = if (guardedRoute != routeDecision.route) {
                        ROUTE_REASON_GUARD_FALLBACK
                    } else {
                        routeDecision.reason
                    }
                    if (
                        guardedRoute != activeRoute &&
                        canSwitchRoute(nowMs, lastRouteSwitchAtMs, guardedReason)
                    ) {
                        val previousRoute = activeRoute
                        val switchReason = guardedReason.ifBlank {
                            "${routeLabel(previousRoute)}_to_${routeLabel(guardedRoute)}"
                        }
                        var demotion: AwgDemotion? = null
                        if (
                            mode == TransportChoice.AUTO &&
                            (previousRoute == Route.AWG_RU || previousRoute == Route.AWG) &&
                            guardedRoute != previousRoute &&
                            guardedReason in setOf(ROUTE_REASON_AWG_NOT_CARRYING, ROUTE_REASON_AWG_UNHEALTHY)
                        ) {
                            demotion = demoteAwg(previousRoute, nowMs)
                        }
                        if (
                            mode == TransportChoice.AUTO &&
                            previousRoute != Route.AWG_RU &&
                            previousRoute != Route.AWG &&
                            !activeRouteDemoted &&
                            guardedReason == ROUTE_REASON_ACTIVE_UNHEALTHY
                        ) {
                            demoteRoute(previousRoute, nowMs, guardedReason)
                        }
                        activeRoute = guardedRoute
                        lastRouteSwitchAtMs = nowMs
                        activeRoute = setRoute(
                            route = activeRoute,
                            mode = mode,
                            awgRuStarted = awgRuStarted,
                            awgStarted = awgStarted,
                            realityStarted = xrayStarted,
                            reality2Started = xray2Started,
                            realityConfig = realityConfig,
                            reality2Config = reality2Config,
                        )
                        Log.i(LOG_TAG, "route switch is non-destructive rsn=$switchReason")
                        outboundIp = when (activeRoute) {
                            Route.REALITY -> realityProbe.outboundIp.takeIf { realityHealthy }.orEmpty()
                            Route.REALITY2 -> reality2Probe.outboundIp.takeIf { reality2Healthy }.orEmpty()
                            Route.AWG_RU -> ""
                            Route.AWG -> ""
                        }
                        lastOutboundProbeAtMs = 0L
                        telemetryEvent("route_switch",
                            "rsn" to switchReason,
                            "route" to routeLabel(activeRoute),
                            "awgru_fail" to awgRuFailures,
                            "awgru_hs" to awgRuProbe.handshakeEstablished,
                            "awgru_carry" to awgRuProbe.carrying,
                            "awgru_demote" to if (previousRoute == Route.AWG_RU) {
                                demotion?.level ?: awgDemotionLevel(Route.AWG_RU).get()
                            } else {
                                awgDemotionLevel(Route.AWG_RU).get()
                            },
                            "awgru_retry_s" to awgRetryDelaySeconds(Route.AWG_RU, nowMs),
                            "awg_fail" to awgFailures,
                            "awg_hs" to awgProbe.handshakeEstablished,
                            "awg_carry" to awgProbe.carrying,
                            "awg_demote" to if (previousRoute == Route.AWG) {
                                demotion?.level ?: awgDemotionLevel(Route.AWG).get()
                            } else {
                                awgDemotionLevel(Route.AWG).get()
                            },
                            "awg_retry_s" to awgRetryDelaySeconds(Route.AWG, nowMs),
                            "backoff_ms" to demotion?.backoffMs,
                            "rl_tcp_ok" to realityHealthy,
                            "rl_carry" to realityHealthy,
                            "rl2_carry" to reality2Healthy,
                            "route_cd_s" to routeCooldownDelaySeconds(activeRoute, nowMs),
                        )
                    }
                    val routeHealthy = routeHealthy(
                        route = activeRoute,
                        awgRuProbe = awgRuProbe,
                        awgProbe = awgProbe,
                        realityHealthy = realityHealthy,
                        reality2Healthy = reality2Healthy,
                        outboundIp = outboundIp,
                    )
                    val hasUsableRoute = awgRuUsable || awgUsable || realityUsable || reality2Usable
                    if (!routeHealthy && !hasUsableRoute) {
                        consecutiveAllDeadCycles++
                    } else {
                        consecutiveAllDeadCycles = 0
                    }
                    if (routeHealthObserved && !lastRouteHealthy && routeHealthy && routeStabilityLost) {
                        markTunnelDisruption(nowMs, "route_recovered")
                        routeStabilityLost = false
                    }
                    routeHealthObserved = true
                    lastRouteHealthy = routeHealthy
                    if (routeHealthy && lastTunnelDisruptionAtMs > lastSessionFlushAtMs) {
                        val closedSessions = router?.closeSessionsCreatedBefore(lastTunnelDisruptionAtMs) ?: 0
                        lastSessionFlushAtMs = nowMs
                        Log.i(
                            LOG_TAG,
                            "flushed stale sessions after tunnel change rsn=$lastTunnelDisruptionReason closed=$closedSessions",
                        )
                        telemetryEvent("stale_flush",
                            "rsn" to lastTunnelDisruptionReason,
                            "route" to routeLabel(activeRoute),
                            "healthy" to true,
                            "stable" to (stableSinceElapsedRealtimeMs != null),
                            "sess_closed" to closedSessions,
                            "awgru_hs" to awgRuProbe.handshakeEstablished,
                            "awgru_carry" to awgRuProbe.carrying,
                            "awgru_rx" to awgRuProbe.rxBytes,
                            "awgru_tx" to awgRuProbe.txBytes,
                            "awgru_demote" to awgDemotionLevel(Route.AWG_RU).get(),
                            "awgru_retry_s" to awgRetryDelaySeconds(Route.AWG_RU, nowMs),
                            "awg_hs" to awgProbe.handshakeEstablished,
                            "awg_carry" to awgProbe.carrying,
                            "awg_rx" to awgProbe.rxBytes,
                            "awg_tx" to awgProbe.txBytes,
                            "awg_demote" to awgDemotionLevel(Route.AWG).get(),
                            "awg_retry_s" to awgRetryDelaySeconds(Route.AWG, nowMs),
                            "rl_tcp_ok" to realityHealthy,
                            "rl_carry" to realityHealthy,
                            "rl2_carry" to reality2Healthy,
                            "rl2_rx" to currentReality2Rx,
                            "rl2_tx" to currentReality2Tx,
                        )
                    }
                    if (routeHealthy) {
                        resetRouteCooldown(activeRoute)
                        lastHealthyRouteAtMs = nowMs
                        val wasStable = stableSinceElapsedRealtimeMs != null
                        stableSinceElapsedRealtimeMs = stableSinceElapsedRealtimeMs ?: nowMs
                        if (!wasStable) {
                            telemetryEvent("tunnel_stable",
                                "route" to routeLabel(activeRoute),
                                "healthy" to true,
                                "stable" to true,
                                "awgru_hs" to awgRuProbe.handshakeEstablished,
                                "awgru_carry" to awgRuProbe.carrying,
                                "awgru_demote" to awgDemotionLevel(Route.AWG_RU).get(),
                                "awgru_retry_s" to awgRetryDelaySeconds(Route.AWG_RU, nowMs),
                                "awgru_rx" to awgRuProbe.rxBytes,
                                "awgru_tx" to awgRuProbe.txBytes,
                                "awg_hs" to awgProbe.handshakeEstablished,
                                "awg_carry" to awgProbe.carrying,
                                "awg_demote" to awgDemotionLevel(Route.AWG).get(),
                                "awg_retry_s" to awgRetryDelaySeconds(Route.AWG, nowMs),
                                "awg_rx" to awgProbe.rxBytes,
                                "awg_tx" to awgProbe.txBytes,
                                "rl_tcp_ok" to realityHealthy,
                                "rl_carry" to realityHealthy,
                                "rl2_carry" to reality2Healthy,
                                "rl2_rx" to currentReality2Rx,
                                "rl2_tx" to currentReality2Tx,
                            )
                        }
                    } else if (
                        stableSinceElapsedRealtimeMs != null &&
                        lastHealthyRouteAtMs?.let { nowMs - it <= ROUTE_LOSS_RESET_GRACE_MS } == true
                    ) {
                        Log.i(LOG_TAG, "route unhealthy inside stability grace window")
                    } else {
                        if (stableSinceElapsedRealtimeMs != null) {
                            routeStabilityLost = true
                        }
                        stableSinceElapsedRealtimeMs = null
                    }
                    val lastExchangeAgeSeconds = lastTrafficAtMs?.let { ((nowMs - it) / 1000).coerceAtLeast(0) }
                    routeHealthSnapshot.set(
                        RouteHealthSnapshot(
                            observedAtMs = nowMs,
                            routeHealthy = routeHealthy,
                            lastTrafficAtMs = lastTrafficAtMs,
                            stableSinceElapsedRealtimeMs = stableSinceElapsedRealtimeMs,
                        ),
                    )
                    publishState(
                        stateFor(
                            route = activeRoute,
                            awgRuProbe = awgRuProbe,
                            awgProbe = awgProbe,
                            realityHealthy = realityHealthy,
                            reality2Healthy = reality2Healthy,
                            outboundIp = outboundIp,
                            lastExchangeAgeSeconds = lastExchangeAgeSeconds,
                            stableSinceElapsedRealtimeMs = stableSinceElapsedRealtimeMs.takeIf { routeHealthy },
                            clock = clock,
                        ),
                    )
                    val stable = routeHealthy &&
                        lastExchangeAgeSeconds != null &&
                        lastExchangeAgeSeconds <= STABLE_TRAFFIC_MAX_AGE_SECONDS
                    if (stable) {
                        maybeCheckUpdates(activeRoute, nowMs)
                    }
                    if (nowMs >= nextTelemetryHeartbeatAtMs) {
                        telemetryEvent("heartbeat",
                            "route" to routeLabel(activeRoute),
                            "healthy" to routeHealthy,
                            "stable" to stable,
                            "last_exch_s" to lastExchangeAgeSeconds,
                            "backoff_ms" to reconnectBackoffMs,
                            "awgru_started" to awgRuStarted,
                            "awgru_hs" to awgRuProbe.handshakeEstablished,
                            "awgru_carry" to awgRuProbe.carrying,
                            "awgru_rx" to awgRuProbe.rxBytes,
                            "awgru_tx" to awgRuProbe.txBytes,
                            "awgru_fail" to awgRuFailures,
                            "awgru_demote" to awgDemotionLevel(Route.AWG_RU).get(),
                            "awgru_retry_s" to awgRetryDelaySeconds(Route.AWG_RU, nowMs),
                            "awg_hs" to awgProbe.handshakeEstablished,
                            "awg_carry" to awgProbe.carrying,
                            "awg_rx" to awgProbe.rxBytes,
                            "awg_tx" to awgProbe.txBytes,
                            "awg_fail" to awgFailures,
                            "awg_demote" to awgDemotionLevel(Route.AWG).get(),
                            "awg_retry_s" to awgRetryDelaySeconds(Route.AWG, nowMs),
                            "rl_started" to xrayStarted,
                            "rl_alive" to (xrayProcess?.isAlive == true),
                            "rl_tcp_ok" to realityHealthy,
                            "rl_carry" to realityHealthy,
                            "rl_rx" to currentRealityRx,
                            "rl_tx" to currentRealityTx,
                            "rl2_started" to xray2Started,
                            "rl2_alive" to (xray2Process?.isAlive == true),
                            "rl2_carry" to reality2Healthy,
                            "rl2_rx" to currentReality2Rx,
                            "rl2_tx" to currentReality2Tx,
                            "route_cd_s" to routeCooldownDelaySeconds(activeRoute, nowMs),
                        )
                        nextTelemetryHeartbeatAtMs = nowMs + telemetryHeartbeatDelay(stable)
                    }
                    if (
                        DeploymentConfig.IS_PUBLIC_PLATFORM &&
                        stable &&
                        nowMs >= nextPublicConfigPollAtMs
                    ) {
                        val pollResult = pollPublicPlatformConfig()
                        if (pollResult.applied) {
                            telemetryEvent("public_config_update",
                                "seq" to pollResult.seq,
                                "route" to routeLabel(activeRoute),
                            )
                            realityConfig = TransportRuntime.auth.reality
                            reality2Config = TransportRuntime.auth.reality2
                        } else if (pollResult.error.isNotBlank()) {
                            Log.w(LOG_TAG, "public config poll failed: ${pollResult.error}")
                        }
                        nextPublicConfigPollAtMs = nowMs + PUBLIC_CONFIG_POLL_INTERVAL_MS
                    }
                    val sleepMs = if (stable) PROBE_INTERVAL_MS else reconnectBackoffMs
                    reconnectBackoffMs = if (stable) {
                        RECONNECT_MIN_BACKOFF_MS
                    } else {
                        (reconnectBackoffMs * 2).coerceAtMost(RECONNECT_MAX_BACKOFF_MS)
                    }
                    val releaseWakeLockForSleep = shouldReleaseWakeLockForAllDeadSleep(
                        routeHealthy = routeHealthy,
                        hasUsableRoute = hasUsableRoute,
                        consecutiveAllDeadCycles = consecutiveAllDeadCycles,
                        sleepMs = sleepMs,
                    )
                    if (releaseWakeLockForSleep) {
                        scheduleBackstop()
                        telemetryEvent("wakelock_sleep",
                            "rsn" to "all_dead",
                            "route" to routeLabel(activeRoute),
                            "healthy" to false,
                            "backoff_ms" to sleepMs,
                        )
                        releaseWakeLock()
                        try {
                            sleepOrResync(sleepMs)
                        } finally {
                            if (workerActive.get()) {
                                acquireWakeLock()
                            }
                        }
                    } else {
                        sleepOrResync(sleepMs)
                    }
                }
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
            } catch (error: Throwable) {
                telemetryEvent("worker_exception",
                    "err_where" to "auto_worker",
                    "err_kind" to Telemetry.errorKind(error),
                    "err_msg" to Telemetry.safeErrorMessage(error),
                )
                publishState(
                    TransportUiState(
                        stateTextRes = R.string.state_error,
                        clockTextRes = clock.statusTextRes,
                        clockSkewSeconds = clock.skewSeconds,
                        socksListen = ROUTER_SOCKS,
                    ),
                )
            } finally {
                workerActive.set(false)
                routeHealthSnapshot.set(null)
                router?.stop()
                router = null
                xrayProcess?.destroy()
                xrayProcess = null
                xray2Process?.destroy()
                xray2Process = null
                setAppliedReality2Uuid("")
                if (awgRuStarted) {
                    Transport.stopAWGRU()
                }
                if (awgStarted) {
                    Transport.stop()
                }
                if (rekeyAfterStop) {
                    recoverStoredTransportKeys(applicationContext)
                }
                releaseWakeLock()
                if (TransportLifecycleStore.shouldKeepAlive(applicationContext)) {
                    scheduleBackstop()
                    if (networkEvent.get() != null) {
                        reviveWorkerAfterNetworkAvailable("pending lifecycle event")
                    }
                }
            }
            }
        } catch (_: RejectedExecutionException) {
            workerActive.set(false)
            releaseWakeLock()
            return false
        }
        return true
    }

    private fun stopAuto(cancelBackstop: Boolean) {
        workerActive.set(false)
        routeHealthSnapshot.set(null)
        synchronized(resyncSignal) {
            resyncSignal.notifyAll()
        }
        unregisterNetworkCallback()
        unregisterScreenReceiver()
        router?.stop()
        router = null
        xrayProcess?.destroy()
        xrayProcess = null
        xray2Process?.destroy()
        xray2Process = null
        setAppliedReality2Uuid("")
        Transport.stopAWGRU()
        Transport.stop()
        if (cancelBackstop) {
            cancelBackstop()
        } else if (TransportLifecycleStore.shouldKeepAlive(this)) {
            scheduleBackstop()
        }
        releaseWakeLock()
        publishState(TransportUiState(stateTextRes = R.string.state_idle))
    }

    private fun registerNetworkCallback() {
        if (networkCallback != null) return
        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                val previous = defaultNetwork.getAndSet(network)
                if (!workerActive.get() && TransportLifecycleStore.shouldKeepAlive(applicationContext)) {
                    reviveWorkerAfterNetworkAvailable()
                } else if (previous == null) {
                    requestLifecycleResync(NetworkEvent.DEFAULT_AVAILABLE)
                } else if (previous != network) {
                    requestLifecycleResync(NetworkEvent.DEFAULT_SWITCHED)
                }
            }

            override fun onLost(network: Network) {
                if (defaultNetwork.get() == network) {
                    defaultNetwork.set(null)
                    requestLifecycleResync(NetworkEvent.DEFAULT_LOST)
                }
            }

            override fun onCapabilitiesChanged(network: Network, networkCapabilities: NetworkCapabilities) {
                // Signal/validation churn is not a transport break; keep sessions alive.
            }
        }
        runCatching {
            val connectivity = getSystemService(ConnectivityManager::class.java)
            defaultNetwork.set(connectivity.activeNetwork)
            connectivity.registerDefaultNetworkCallback(callback)
            networkCallback = callback
        }.onFailure {
            Log.w(LOG_TAG, "network callback unavailable: ${it.message}")
        }
    }

    private fun unregisterNetworkCallback() {
        val callback = networkCallback ?: return
        runCatching {
            getSystemService(ConnectivityManager::class.java).unregisterNetworkCallback(callback)
        }
        defaultNetwork.set(null)
        networkEvent.set(null)
        networkCallback = null
    }

    private fun registerScreenReceiver() {
        if (screenReceiver != null) return
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(context: Context?, intent: Intent?) {
                if (intent?.action == Intent.ACTION_SCREEN_ON) {
                    requestLifecycleResync(NetworkEvent.SCREEN_ON)
                }
            }
        }
        runCatching {
            val filter = IntentFilter(Intent.ACTION_SCREEN_ON)
            if (Build.VERSION.SDK_INT >= 33) {
                registerReceiver(receiver, filter, Context.RECEIVER_NOT_EXPORTED)
            } else {
                registerReceiver(receiver, filter)
            }
            screenReceiver = receiver
        }.onFailure {
            Log.w(LOG_TAG, "screen receiver unavailable: ${it.message}")
        }
    }

    private fun unregisterScreenReceiver() {
        val receiver = screenReceiver ?: return
        runCatching { unregisterReceiver(receiver) }
        screenReceiver = null
    }

    private fun requestLifecycleResync(event: NetworkEvent) {
        val nowMs = SystemClock.elapsedRealtime()
        if (event == NetworkEvent.BACKSTOP_ALARM) {
            Telemetry.flush(applicationContext)
        }
        telemetryEvent("network_event", "rsn" to event.logText)
        if (
            (event == NetworkEvent.FOREGROUND_RESYNC ||
                event == NetworkEvent.SCREEN_ON ||
                event == NetworkEvent.BACKSTOP_ALARM) &&
            shouldKeepForegroundResyncNonDestructive(nowMs)
        ) {
            Log.i(LOG_TAG, "${event.logText} skipped, tunnel healthy")
            synchronized(resyncSignal) {
                resyncSignal.notifyAll()
            }
            scheduleBackstop()
            return
        }
        networkEvent.set(event)
        if (!event.marksTunnelDisruption) {
            router?.closeSessionsCreatedBefore(nowMs - RESYNC_SESSION_GRACE_MS)
            mainHandler.post {
                val current = TransportRuntime.state
                if (current.socksListen == ROUTER_SOCKS) {
                    TransportRuntime.state = current.copy(
                        stateTextRes = R.string.state_reconnecting,
                        handshakeEstablished = false,
                        tunnelStable = false,
                        outboundIp = "",
                        lastExchangeAgeSeconds = null,
                        stableSinceElapsedRealtimeMs = null,
                    )
                }
            }
        }
        synchronized(resyncSignal) {
            resyncSignal.notifyAll()
        }
        scheduleBackstop()
    }

    private fun telemetryEvent(kind: String, vararg fields: Pair<String, Any?>) {
        Telemetry.event(applicationContext, kind, *fields, "active_route" to activeRouteLabel())
    }

    private fun activeRouteLabel(): String =
        routeLabel(
            when (upstreamRef.get()) {
                AWG_RU_UPSTREAM -> Route.AWG_RU
                AWG_UPSTREAM -> Route.AWG
                REALITY_UPSTREAM -> Route.REALITY
                REALITY2_UPSTREAM -> Route.REALITY2
                else -> Route.AWG_RU
            },
        )

    private fun reviveWorkerAfterNetworkAvailable(reason: String = "network available") {
        if (activeService.get() !== this) return
        val nowMs = SystemClock.elapsedRealtime()
        while (true) {
            val lastMs = lastNetworkReviveAtMs.get()
            if (lastMs != 0L && nowMs - lastMs < AUTO_REVIVE_DEBOUNCE_MS) {
                Log.i(LOG_TAG, "network worker revive skipped by debounce")
                scheduleBackstop()
                return
            }
            if (lastNetworkReviveAtMs.compareAndSet(lastMs, nowMs)) break
        }
        if (startAuto()) {
            Log.w(LOG_TAG, "$reason revived transport worker")
        }
    }

    private fun shouldKeepForegroundResyncNonDestructive(nowMs: Long): Boolean {
        if (!workerActive.get() || router == null || networkEvent.get() != null) return false
        val snapshot = routeHealthSnapshot.get() ?: return false
        val snapshotAgeMs = nowMs - snapshot.observedAtMs
        val trafficAgeMs = snapshot.lastTrafficAtMs?.let { nowMs - it } ?: Long.MAX_VALUE
        return snapshot.routeHealthy &&
            snapshot.stableSinceElapsedRealtimeMs != null &&
            snapshotAgeMs in 0..STABLE_TRAFFIC_MAX_AGE_MS &&
            trafficAgeMs in 0..STABLE_TRAFFIC_MAX_AGE_MS
    }

    @SuppressLint("WakelockTimeout")
    private fun acquireWakeLock() {
        synchronized(wakeLockMonitor) {
            val current = wakeLock
            if (current?.isHeld == true) return
            wakeLock = getSystemService(PowerManager::class.java)
                .newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, WAKE_LOCK_TAG)
                .apply {
                    setReferenceCounted(false)
                    acquire()
                }
            Log.i(LOG_TAG, "partial wake lock acquired")
        }
    }

    private fun releaseWakeLock() {
        synchronized(wakeLockMonitor) {
            val current = wakeLock ?: return
            runCatching {
                if (current.isHeld) {
                    current.release()
                    Log.i(LOG_TAG, "partial wake lock released")
                }
            }
            wakeLock = null
        }
    }

    private fun scheduleBackstop() {
        scheduleBackstopAlarm(this)
    }

    private fun cancelBackstop() {
        cancelBackstopAlarm(this)
    }

    private fun sleepOrResync(durationMs: Long) {
        synchronized(resyncSignal) {
            resyncSignal.wait(durationMs)
        }
    }

    private fun startAWGCore(route: Route): AWGStartResult {
        return runCatching {
            val raw = when (route) {
                Route.AWG_RU -> Transport.startProvisionedAWGRU()
                Route.AWG -> Transport.startProvisioned()
                else -> error("route is not AWG: $route")
            }
            val result = JSONObject(raw)
            if (!result.optBoolean(JSON_OK, false)) {
                val error = result.optString(JSON_ERROR)
                Log.w(LOG_TAG, "${routeLabel(route)} core start failed: $error")
                AWGStartResult(started = false, error = error, errorKind = "config")
            } else {
                AWGStartResult(started = true)
            }
        }.getOrElse { error ->
            Log.w(LOG_TAG, "${routeLabel(route)} core start exception: ${error.message}")
            AWGStartResult(
                started = false,
                error = Telemetry.safeErrorMessage(error),
                errorKind = Telemetry.errorKind(error),
            )
        }
    }

    private fun restorePublicPlatformRuntimeForService() {
        if (!DeploymentConfig.IS_PUBLIC_PLATFORM) return
        if (TransportRuntime.publicPlatformRouteSlots.routePriorities.isNotEmpty()) return
        val store = SecureIdentityStore(applicationContext)
        val stored = store.readPublicPlatformState()
        if (
            stored.clientBundleJson.isBlank() ||
            stored.configPubkeyPin.isBlank() ||
            stored.realityUUID.isBlank() ||
            stored.awgPrivateKey.isBlank()
        ) {
            Log.w(LOG_TAG, "public platform runtime restore skipped: cached state is incomplete")
            return
        }
        runCatching {
            val config = PublicPlatformConfigParser.verifyAndParseClientConfig(
                envelopeRaw = stored.clientBundleJson,
                expectedPublicKey = stored.configPubkeyPin,
                maxSeenSeq = stored.maxSeenConfigSeq,
                nowMs = 0L,
            )
            applyPublicPlatformRuntime(stored, config)
            Log.i(LOG_TAG, "public platform runtime restored seq=${config.seq}")
        }.onFailure { error ->
            Log.w(LOG_TAG, "public platform runtime restore failed", error)
        }
    }

    private fun applyPublicPlatformRuntime(
        stored: StoredPublicPlatformState,
        config: PublicClientConfig,
    ) {
        val credentials = PublicPlatformCredentials(
            deviceID = stored.deviceID,
            realityUUID = stored.realityUUID,
            internalIP = stored.internalIP,
            psk2 = stored.psk2,
            serverAWGPublic = stored.serverAWGPublic,
            awgPrivateKey = stored.awgPrivateKey,
            awgPublicKey = stored.awgPublicKey,
        )
        val slots = PublicPlatformConfigParser.routeSlots(config, stored.deviceID, credentials)
        if (!slots.hasUsableRoute()) error("public client config has no usable route")

        val applyRequest = JSONObject()
            .put("awg_private_key", stored.awgPrivateKey)
            .put("internal_ip", stored.internalIP)
            .put("psk2", stored.psk2)
            .put("server_awg_public", stored.serverAWGPublic)
            .put("socks_listen", AWG_UPSTREAM.host + ":" + AWG_UPSTREAM.port)
            .put("awg_ru_socks_listen", AWG_RU_UPSTREAM.host + ":" + AWG_RU_UPSTREAM.port)
            .put("mtu", 1420)
        slots.awgRu?.let { applyRequest.put("awg_ru", PublicPlatformConfigParser.awgRouteJson(it)) }
        slots.awg?.let { applyRequest.put("awg", PublicPlatformConfigParser.awgRouteJson(it)) }
        val applyResponse = JSONObject(Transport.applyPublicPlatformConfig(applyRequest.toString()))
        if (!applyResponse.optBoolean(JSON_OK, false)) {
            error(applyResponse.optString(JSON_ERROR))
        }

        TransportRuntime.publicPlatformConfig = config
        TransportRuntime.publicPlatformRouteSlots = slots
        TransportRuntime.publicReality2EgressIp = slots.reality2ExpectedEgressIp
        TransportRuntime.publicRealityEgressIp = slots.realityExpectedEgressIp
        TransportRuntime.auth = TransportRuntime.auth.copy(
            authorized = true,
            internalIP = stored.internalIP,
            endpoint = publicAwgEndpoint(slots.awgRu ?: slots.awg),
            provisionedSOCKS = ROUTER_SOCKS,
            awgRu = publicAwgUiConfig(slots.awgRu, stored),
            reality = slots.reality,
            reality2 = slots.reality2,
        )
    }

    private data class PublicConfigPollResult(
        val applied: Boolean = false,
        val seq: Long = 0,
        val error: String = "",
    )

    private fun pollPublicPlatformConfig(): PublicConfigPollResult {
        val store = SecureIdentityStore(applicationContext)
        val stored = store.readPublicPlatformState()
        if (stored.configPubkeyPin.isBlank() || stored.deviceID.isBlank()) {
            return PublicConfigPollResult(error = "public state is incomplete")
        }
        val urls = publicConfigBaseUrls()
        if (urls.isEmpty()) {
            return PublicConfigPollResult(error = "no public config urls")
        }
        var lastError = ""
        for (baseUrl in urls) {
            try {
                val configJson = fetchInternalHTTPViaRouter("$baseUrl/config.json").trim()
                val minisig = fetchInternalHTTPViaRouter("$baseUrl/config.json.minisig").trim()
                val envelope = JSONObject()
                    .put("config_json", configJson)
                    .put("config_json_minisig", minisig)
                    .put("public_key", stored.configPubkeyPin)
                val config = PublicPlatformConfigParser.verifyAndParseClientConfig(
                    envelopeRaw = envelope.toString(),
                    expectedPublicKey = stored.configPubkeyPin,
                    maxSeenSeq = stored.maxSeenConfigSeq,
                )
                if (config.seq <= stored.maxSeenConfigSeq) {
                    return PublicConfigPollResult(applied = false, seq = config.seq)
                }
                val next = stored.copy(
                    maxSeenConfigSeq = config.seq,
                    updatePubkeyPin = config.updatePubkey.ifBlank { stored.updatePubkeyPin },
                    clientConfigJson = configJson,
                    clientBundleJson = envelope.toString(),
                )
                applyPublicPlatformRuntime(next, config)
                store.writePublicPlatformState(next)
                Log.i(LOG_TAG, "public config hot-applied seq=${config.seq} from $baseUrl")
                return PublicConfigPollResult(applied = true, seq = config.seq)
            } catch (error: Throwable) {
                lastError = "${baseUrl}: ${Telemetry.safeErrorMessage(error)}"
            }
        }
        return PublicConfigPollResult(error = lastError)
    }

    private fun publicConfigBaseUrls(): List<String> {
        val urls = linkedSetOf<String>()
        TransportRuntime.publicPlatformRouteSlots.orderedRoutes.forEach { resolved ->
            val url = resolved.route.params.optString("config_url").trim()
            if (url.isNotBlank()) urls += url.trimEnd('/')
        }
        if (urls.isEmpty()) urls += PUBLIC_CONFIG_DEFAULT_BASE_URL
        return urls.toList()
    }

    private fun fetchInternalHTTPViaRouter(urlText: String): String {
        val uri = URI(urlText)
        if ((uri.scheme ?: "").lowercase() != "http") {
            error("only internal http config urls are supported")
        }
        val host = uri.host ?: error("config url host is empty")
        val port = if (uri.port > 0) uri.port else 80
        val rawPath = uri.rawPath?.ifBlank { "/" } ?: "/"
        val query = uri.rawQuery?.let { "?$it" }.orEmpty()
        openRouterSocks5Socket(host, port, PUBLIC_CONFIG_POLL_TIMEOUT_MS.toInt()).use { socket ->
            socket.soTimeout = PUBLIC_CONFIG_POLL_TIMEOUT_MS.toInt()
            val request = buildString {
                append("GET ")
                append(rawPath)
                append(query)
                append(" HTTP/1.1\r\nHost: ")
                append(host)
                if (uri.port > 0) append(":").append(port)
                append("\r\nConnection: close\r\nAccept: application/json,text/plain,*/*\r\n\r\n")
            }
            socket.getOutputStream().write(request.toByteArray(Charsets.US_ASCII))
            socket.getOutputStream().flush()
            val input = socket.getInputStream()
            val header = readInternalHttpHeader(input)
            val status = header.lineSequence().firstOrNull().orEmpty()
            if (!status.contains(" 200 ")) error("config http status: $status")
            return input.readBytes().toString(Charsets.UTF_8)
        }
    }

    private fun openRouterSocks5Socket(targetHost: String, targetPort: Int, timeoutMs: Int): Socket {
        val socket = Socket()
        try {
            socket.soTimeout = timeoutMs
            socket.connect(InetSocketAddress(ROUTER_HOST, ROUTER_PORT), timeoutMs)
            val input = socket.getInputStream()
            val output = socket.getOutputStream()
            output.write(byteArrayOf(SOCKS_VERSION.toByte(), 0x01, SOCKS_NO_AUTH.toByte()))
            output.flush()
            if (readSocksByte(input) != SOCKS_VERSION || readSocksByte(input) != SOCKS_NO_AUTH) {
                error("bad router socks greeting")
            }
            val hostBytes = targetHost.toByteArray(Charsets.UTF_8)
            if (hostBytes.size > BYTE_MASK) error("router target host is too long")
            output.write(byteArrayOf(SOCKS_VERSION.toByte(), SOCKS_CONNECT.toByte(), 0x00, SOCKS_ATYP_DOMAIN.toByte(), hostBytes.size.toByte()))
            output.write(hostBytes)
            output.write(byteArrayOf(((targetPort ushr 8) and BYTE_MASK).toByte(), (targetPort and BYTE_MASK).toByte()))
            output.flush()
            if (readSocksByte(input) != SOCKS_VERSION) error("bad router socks response")
            val reply = readSocksByte(input)
            readSocksByte(input)
            val atyp = readSocksByte(input)
            if (reply != 0) error("router socks connect failed rep=$reply")
            val bindLength = when (atyp) {
                SOCKS_ATYP_IPV4 -> 4
                SOCKS_ATYP_DOMAIN -> readSocksByte(input)
                SOCKS_ATYP_IPV6 -> 16
                else -> error("bad router socks bind atyp=$atyp")
            }
            readSocksExact(input, bindLength + 2)
            return socket
        } catch (error: Throwable) {
            runCatching { socket.close() }
            throw error
        }
    }

    private fun readInternalHttpHeader(input: InputStream): String {
        val bytes = ArrayList<Byte>(1024)
        var state = 0
        while (bytes.size < PUBLIC_HTTP_HEADER_LIMIT_BYTES) {
            val value = input.read()
            if (value < 0) error("bad http response")
            bytes += value.toByte()
            state = when (state) {
                0 -> if (value == '\r'.code) 1 else 0
                1 -> if (value == '\n'.code) 2 else 0
                2 -> if (value == '\r'.code) 3 else 0
                3 -> if (value == '\n'.code) return bytes.toByteArray().toString(Charsets.ISO_8859_1) else 0
                else -> 0
            }
        }
        error("http header is too large")
    }

    private fun readSocksByte(input: InputStream): Int {
        val value = input.read()
        if (value < 0) throw EOFException()
        return value and BYTE_MASK
    }

    private fun readSocksExact(input: InputStream, size: Int) {
        var remaining = size
        val buffer = ByteArray(256)
        while (remaining > 0) {
            val read = input.read(buffer, 0, minOf(buffer.size, remaining))
            if (read < 0) throw EOFException()
            remaining -= read
        }
    }

    private fun ByteArray.indexOfHeaderEnd(): Int {
        for (index in 0 until size - 3) {
            if (this[index] == '\r'.code.toByte() &&
                this[index + 1] == '\n'.code.toByte() &&
                this[index + 2] == '\r'.code.toByte() &&
                this[index + 3] == '\n'.code.toByte()
            ) {
                return index
            }
        }
        return -1
    }

    private fun publicAwgEndpoint(route: PublicRouteConfig?): String {
        if (route == null) return ""
        return route.params.optString("endpoint").ifBlank { "${route.address}:${route.port}" }
    }

    private fun publicAwgUiConfig(route: PublicRouteConfig?, stored: StoredPublicPlatformState): AwgUiConfig? {
        if (route == null) return null
        return AwgUiConfig(
            internalIP = stored.internalIP,
            endpoint = publicAwgEndpoint(route),
            serverPublicKey = route.params.optString("public_key").ifBlank { stored.serverAWGPublic },
        )
    }

    private fun startXraySidecar(
        cfg: RealityUiConfig,
        route: Route,
        forceRestart: Boolean = false,
    ): XrayStartResult {
        return runCatching {
            val current = xrayProcess(route)
            if (current?.isAlive == true) {
                if (!forceRestart) return XrayStartResult(started = true)
                stopXraySidecar(route)
            }
            val xray = File(applicationInfo.nativeLibraryDir, XRAY_LIB_NAME)
            if (!xray.canExecute()) {
                return XrayStartResult(started = false, error = "xray_not_executable", errorKind = "process")
            }
            val configFile = writeXrayConfig(cfg, route)
            val process = ProcessBuilder(
                xray.absolutePath,
                "run",
                "-config",
                configFile.absolutePath,
            )
                .redirectErrorStream(true)
                .start()
            setXrayProcess(route, process)
            drainProcessOutput(process)
            Thread.sleep(XRAY_WARMUP_MS)
            if (process.isAlive) {
                XrayStartResult(started = true)
            } else {
                XrayStartResult(started = false, error = "xray_process_exited", errorKind = "process")
            }
        }.getOrElse { error ->
            XrayStartResult(
                started = false,
                error = Telemetry.safeErrorMessage(error),
                errorKind = Telemetry.errorKind(error),
            )
        }
    }

    private fun stopXraySidecar(route: Route) {
        val current = xrayProcess(route) ?: return
        if (current.isAlive) {
            current.destroy()
            try {
                if (!current.waitFor(XRAY_STOP_GRACE_MS, TimeUnit.MILLISECONDS)) {
                    current.destroyForcibly()
                }
            } catch (error: InterruptedException) {
                Thread.currentThread().interrupt()
                current.destroyForcibly()
                throw error
            }
        }
        setXrayProcess(route, null)
    }

    private fun setAppliedReality2Uuid(uuid: String) {
        val normalized = uuid.trim()
        appliedReality2Uuid = normalized
        TransportRuntime.appliedReality2Uuid = normalized
    }

    private fun xrayProcess(route: Route): Process? =
        when (route) {
            Route.REALITY -> xrayProcess
            Route.REALITY2 -> xray2Process
            Route.AWG_RU -> null
            Route.AWG -> null
        }

    private fun setXrayProcess(route: Route, process: Process?) {
        when (route) {
            Route.REALITY -> xrayProcess = process
            Route.REALITY2 -> xray2Process = process
            Route.AWG_RU -> Unit
            Route.AWG -> Unit
        }
    }

    private fun writeXrayConfig(cfg: RealityUiConfig, route: Route): File {
        val dir = File(filesDir, routeXrayDir(route))
        if (!dir.exists() && !dir.mkdirs()) {
            throw IllegalStateException("cannot create reality config dir")
        }
        val configFile = File(dir, "xray-client-${route.name.lowercase()}.json")
        val inbound = JSONObject()
            .put("tag", "socks-in")
            .put("listen", REALITY_HOST)
            .put("port", routePort(route))
            .put("protocol", "socks")
            .put(
                "settings",
                JSONObject()
                    .put("auth", "noauth")
                    .put("udp", false),
            )
        val user = JSONObject()
            .put("id", cfg.uuid)
            .put("encryption", "none")
        if (cfg.flow.isNotBlank()) {
            user.put("flow", cfg.flow)
        }
        val vnext = JSONObject()
            .put("address", cfg.address)
            .put("port", cfg.port)
            .put("users", JSONArray().put(user))
        val outbound = JSONObject()
            .put("tag", "reality-out")
            .put("protocol", "vless")
            .put("settings", JSONObject().put("vnext", JSONArray().put(vnext)))
            .put(
                "streamSettings",
                JSONObject()
                    .put("network", cfg.network)
                    .put("security", cfg.security)
                    .put("sockopt", realitySockopt())
                    .put(
                        "realitySettings",
                        JSONObject()
                            .put("serverName", cfg.serverName)
                            .put("fingerprint", cfg.fingerprint)
                            .put("publicKey", cfg.publicKey)
                            .put("shortId", cfg.shortId)
                            .put("spiderX", cfg.spiderX),
                    ),
            )
        val config = JSONObject()
            .put("log", JSONObject().put("loglevel", "warning"))
            .put("inbounds", JSONArray().put(inbound))
            .put("outbounds", JSONArray().put(outbound))
            .put(
                "routing",
                JSONObject().put(
                    "rules",
                    JSONArray().put(
                        JSONObject()
                            .put("type", "field")
                            .put("inboundTag", JSONArray().put("socks-in"))
                            .put("outboundTag", "reality-out"),
                    ),
                ),
            )
        configFile.writeText(config.toString(), Charsets.UTF_8)
        return configFile
    }

    private fun realitySockopt(): JSONObject =
        JSONObject().put("tcpMaxSeg", REALITY_TCP_MAX_SEG)

    private fun initialRoute(
        mode: TransportChoice,
        awgRuStarted: Boolean,
        awgStarted: Boolean,
        realityStarted: Boolean,
        reality2Started: Boolean,
        realityConfig: RealityUiConfig?,
        reality2Config: RealityUiConfig?,
    ): Route =
        selectAvailableRoute(
            mode = mode,
            preferred = when (mode) {
                TransportChoice.AWG_RU -> Route.AWG_RU
                TransportChoice.REALITY -> Route.REALITY
                TransportChoice.REALITY2 -> Route.REALITY2
                TransportChoice.AWG -> Route.AWG
                TransportChoice.AUTO -> autoPreferredRoute()
            },
            awgRuStarted = awgRuStarted,
            awgStarted = awgStarted,
            realityStarted = realityStarted,
            reality2Started = reality2Started,
            realityConfig = realityConfig,
            reality2Config = reality2Config,
        )

    private fun selectAvailableRoute(
        mode: TransportChoice,
        preferred: Route,
        awgRuStarted: Boolean,
        awgStarted: Boolean,
        realityStarted: Boolean,
        reality2Started: Boolean,
        realityConfig: RealityUiConfig?,
        reality2Config: RealityUiConfig?,
    ): Route {
        return selectRouteWithFallbackPolicy(mode = mode, preferred = preferred) {
            val candidates = candidateRoutes(preferred)
            candidates.firstOrNull { route ->
                routeAvailable(
                    route = route,
                    awgRuStarted = awgRuStarted,
                    awgStarted = awgStarted,
                    realityStarted = realityStarted,
                    reality2Started = reality2Started,
                    realityConfig = realityConfig,
                    reality2Config = reality2Config,
                )
            } ?: preferred
        }
    }

    private fun autoPreferredRoute(): Route =
        if (DeploymentConfig.IS_PUBLIC_PLATFORM) {
            publicOrderedRoutes().firstOrNull() ?: Route.AWG_RU
        } else {
            Route.AWG_RU
        }

    private fun candidateRoutes(preferred: Route): List<Route> {
        if (DeploymentConfig.IS_PUBLIC_PLATFORM) {
            val publicOrder = publicOrderedRoutes()
            if (publicOrder.isNotEmpty()) {
                return (listOf(preferred) + publicOrder).distinct()
            }
        }
        return when (preferred) {
            Route.AWG_RU -> listOf(Route.AWG_RU, Route.REALITY2, Route.AWG, Route.REALITY)
            Route.REALITY2 -> listOf(Route.REALITY2, Route.AWG, Route.REALITY, Route.AWG_RU)
            Route.AWG -> listOf(Route.AWG, Route.REALITY2, Route.REALITY, Route.AWG_RU)
            Route.REALITY -> listOf(Route.REALITY, Route.REALITY2, Route.AWG, Route.AWG_RU)
        }
    }

    private fun publicOrderedRoutes(): List<Route> {
        val priorities = TransportRuntime.publicPlatformRouteSlots.routePriorities
        if (priorities.isEmpty()) return emptyList()
        return Route.values()
            .filter { priorities.containsKey(it.name) }
            .sortedWith(compareBy<Route> { priorities[it.name] ?: Int.MAX_VALUE }.thenBy { privateRoutePriority(it) })
    }

    private fun publicRouteConfigured(route: Route): Boolean {
        if (!DeploymentConfig.IS_PUBLIC_PLATFORM) return true
        return TransportRuntime.publicPlatformRouteSlots.routePriorities.containsKey(route.name)
    }

    private fun routeAvailable(
        route: Route,
        awgRuStarted: Boolean,
        awgStarted: Boolean,
        realityStarted: Boolean,
        reality2Started: Boolean,
        realityConfig: RealityUiConfig?,
        reality2Config: RealityUiConfig?,
    ): Boolean =
        when (route) {
            Route.AWG_RU -> awgRuStarted
            Route.AWG -> awgStarted
            Route.REALITY -> realityStarted &&
                realityConfig?.isComplete() == true &&
                xrayProcess(Route.REALITY)?.isAlive == true
            Route.REALITY2 -> reality2Started &&
                reality2Config?.isComplete() == true &&
                xrayProcess(Route.REALITY2)?.isAlive == true
        }

    private fun chooseRoute(
        mode: TransportChoice,
        active: Route,
        awgRuStarted: Boolean,
        awgRuFailures: Int,
        awgRuUsable: Boolean,
        awgRuNotCarrying: Boolean,
        awgStarted: Boolean,
        awgFailures: Int,
        awgUsable: Boolean,
        awgNotCarrying: Boolean,
        realityUsable: Boolean,
        reality2Usable: Boolean,
        reality2PriorityPromotable: Boolean,
        activeHealthy: Boolean,
    ): RouteDecision =
        when (mode) {
            TransportChoice.AWG_RU -> RouteDecision(Route.AWG_RU)
            TransportChoice.AWG -> RouteDecision(Route.AWG)
            TransportChoice.REALITY -> RouteDecision(Route.REALITY)
            TransportChoice.REALITY2 -> RouteDecision(Route.REALITY2)
            TransportChoice.AUTO -> when {
                active == Route.AWG_RU &&
                    activeHealthy -> RouteDecision(active)
                active == Route.REALITY2 &&
                    activeHealthy &&
                    !awgRuUsable -> RouteDecision(active)
                active == Route.AWG &&
                    activeHealthy &&
                    !awgRuUsable &&
                    !reality2Usable &&
                    !realityUsable -> RouteDecision(active)
                active == Route.REALITY &&
                    activeHealthy &&
                    !awgRuUsable &&
                    !reality2Usable &&
                    !awgUsable -> RouteDecision(active)
                awgRuUsable &&
                    routePriority(Route.AWG_RU) < routePriority(active) &&
                    active != Route.AWG_RU -> RouteDecision(Route.AWG_RU, ROUTE_REASON_PRIORITY_RECOVERED)
                active == Route.AWG_RU &&
                    awgRuNotCarrying &&
                    (reality2Usable || awgUsable || realityUsable) -> RouteDecision(
                        firstUsableRoute(reality2Usable, awgUsable, realityUsable),
                        ROUTE_REASON_AWG_NOT_CARRYING,
                    )
                active == Route.AWG_RU &&
                    (!awgRuStarted || awgRuFailures >= AWG_FAILURES_BEFORE_FALLBACK) &&
                    (reality2Usable || awgUsable || realityUsable) -> RouteDecision(
                        firstUsableRoute(reality2Usable, awgUsable, realityUsable),
                        ROUTE_REASON_AWG_UNHEALTHY,
                    )
                reality2Usable &&
                    (!activeHealthy || reality2PriorityPromotable) &&
                    active != Route.REALITY2 -> RouteDecision(Route.REALITY2, ROUTE_REASON_PRIORITY_RECOVERED)
                awgUsable &&
                    active != Route.AWG &&
                    !activeHealthy -> RouteDecision(Route.AWG, ROUTE_REASON_ACTIVE_UNHEALTHY)
                active == Route.AWG &&
                    awgNotCarrying &&
                    (reality2Usable || realityUsable) -> RouteDecision(
                        if (reality2Usable) Route.REALITY2 else Route.REALITY,
                        ROUTE_REASON_AWG_NOT_CARRYING,
                    )
                active == Route.AWG &&
                    (!awgStarted || awgFailures >= AWG_FAILURES_BEFORE_FALLBACK) &&
                    (reality2Usable || realityUsable) -> RouteDecision(
                        if (reality2Usable) Route.REALITY2 else Route.REALITY,
                        ROUTE_REASON_AWG_UNHEALTHY,
                    )
                realityUsable &&
                    active != Route.REALITY &&
                    !activeHealthy -> RouteDecision(Route.REALITY, ROUTE_REASON_ACTIVE_UNHEALTHY)
                !activeHealthy && awgRuUsable -> RouteDecision(Route.AWG_RU, ROUTE_REASON_ACTIVE_UNHEALTHY)
                !activeHealthy && reality2Usable -> RouteDecision(Route.REALITY2, ROUTE_REASON_ACTIVE_UNHEALTHY)
                !activeHealthy && awgUsable -> RouteDecision(Route.AWG, ROUTE_REASON_ACTIVE_UNHEALTHY)
                !activeHealthy && realityUsable -> RouteDecision(Route.REALITY, ROUTE_REASON_ACTIVE_UNHEALTHY)
                else -> RouteDecision(active)
            }
        }

    private fun setRoute(
        route: Route,
        mode: TransportChoice,
        awgRuStarted: Boolean,
        awgStarted: Boolean,
        realityStarted: Boolean,
        reality2Started: Boolean,
        realityConfig: RealityUiConfig?,
        reality2Config: RealityUiConfig?,
    ): Route {
        val selected = selectAvailableRoute(
            mode = mode,
            preferred = route,
            awgRuStarted = awgRuStarted,
            awgStarted = awgStarted,
            realityStarted = realityStarted,
            reality2Started = reality2Started,
            realityConfig = realityConfig,
            reality2Config = reality2Config,
        )
        if (selected != route) {
            Log.w(LOG_TAG, "route guard fallback from $route to $selected")
            telemetryEvent("route_guard",
                "rsn" to ROUTE_REASON_GUARD_FALLBACK,
                "route" to routeLabel(selected),
                "from_route" to routeLabel(route),
            )
        }
        upstreamRef.set(
            when (selected) {
                Route.AWG_RU -> AWG_RU_UPSTREAM
                Route.AWG -> AWG_UPSTREAM
                Route.REALITY -> REALITY_UPSTREAM
                Route.REALITY2 -> REALITY2_UPSTREAM
            },
        )
        Log.i(LOG_TAG, "route switched to $selected")
        return selected
    }

    private fun firstUsableRoute(reality2Usable: Boolean, awgUsable: Boolean, realityUsable: Boolean): Route =
        when {
            reality2Usable -> Route.REALITY2
            awgUsable -> Route.AWG
            realityUsable -> Route.REALITY
            else -> Route.REALITY
        }

    private fun startSocksRouter(): SocksRouter =
        SocksRouter(
            host = ROUTER_HOST,
            port = ROUTER_PORT,
            upstreamProvider = { upstreamRef.get() },
            realityRxCounter = realityRxBytes,
            realityTxCounter = realityTxBytes,
            reality2RxCounter = reality2RxBytes,
            reality2TxCounter = reality2TxBytes,
        ).also { it.start() }

    private fun shouldProbeAWG(
        nowMs: Long,
        lastProbeAtMs: Long,
        activeRoute: Route,
        route: Route,
        awgFailures: Int,
    ): Boolean {
        if (lastProbeAtMs == 0L) return true
        val interval = if (
            activeRoute != route &&
            awgFailures >= AWG_FAILURES_BEFORE_FALLBACK &&
            awgRekeyRequested(route).get()
        ) {
            AWG_UNHEALTHY_PROBE_INTERVAL_MS
        } else {
            PROBE_INTERVAL_MS
        }
        return nowMs - lastProbeAtMs >= interval
    }

    private fun shouldProbeAwgRetry(
        nowMs: Long,
        lastProbeAtMs: Long,
        route: Route,
        activeRoute: Route,
        activeHealthy: Boolean,
        activeStableSinceMs: Long?,
        realityUsable: Boolean,
        retryFailures: Int,
        udpDeadFailures: Int,
    ): Boolean {
        if (realityUsable && isAwgCooldownActive(route, nowMs)) return false
        if (
            activeHealthy &&
            activeStableSinceMs?.let { nowMs - it >= ACTIVE_STABLE_RETRY_SUPPRESS_MS } == true &&
            routePriority(route) > routePriority(activeRoute)
        ) {
            return false
        }
        if (lastProbeAtMs == 0L) return true
        return nowMs - lastProbeAtMs >= awgRetryProbeIntervalMs(retryFailures, udpDeadFailures)
    }

    private fun awgRetryProbeIntervalMs(retryFailures: Int, udpDeadFailures: Int): Long {
        if (udpDeadFailures >= AWG_UDP_DEAD_FAILURES_BEFORE_PAUSE) return AWG_UDP_DEAD_BACKOFF_MS
        if (retryFailures <= 0) return OUTBOUND_REFRESH_INTERVAL_MS
        var interval = OUTBOUND_REFRESH_INTERVAL_MS
        repeat(retryFailures.coerceAtMost(AWG_RETRY_MAX_BACKOFF_SHIFT)) {
            interval = (interval * 2).coerceAtMost(AWG_RETRY_MAX_INTERVAL_MS)
        }
        return interval
    }

    private fun shouldProbeReality(
        nowMs: Long,
        lastProbeAtMs: Long,
        activeRoute: Route,
        route: Route,
        localRxFresh: Boolean,
    ): Boolean {
        if (lastProbeAtMs == 0L) return true
        val interval = if (activeRoute == route) {
            PROBE_INTERVAL_MS
        } else {
            REALITY_INACTIVE_PROBE_INTERVAL_MS
        }
        if (activeRoute != route && !localRxFresh) return false
        return nowMs - lastProbeAtMs >= interval
    }

    private fun routePriority(route: Route): Int {
        if (DeploymentConfig.IS_PUBLIC_PLATFORM) {
            TransportRuntime.publicPlatformRouteSlots.routePriorities[route.name]?.let { return it }
        }
        return privateRoutePriority(route)
    }

    private fun privateRoutePriority(route: Route): Int =
        when (route) {
            Route.AWG_RU -> 0
            Route.REALITY2 -> 1
            Route.AWG -> 2
            Route.REALITY -> 3
        }

    private fun probeAWG(route: Route): AWGProbeResult {
        val statRaw = when (route) {
            Route.AWG_RU -> Transport.statAWGRU()
            Route.AWG -> Transport.stat()
            else -> return AWGProbeResult(false)
        }
        return runCatching {
            val root = JSONObject(statRaw)
            if (!root.optBoolean(JSON_OK, false)) return AWGProbeResult(false)
            val status = root.optJSONObject(JSON_STATUS) ?: return AWGProbeResult(false)
            val handshake = status.optBoolean(JSON_HANDSHAKE, false)
            AWGProbeResult(
                handshakeEstablished = handshake,
                rxBytes = status.optLong(JSON_RX, 0),
                txBytes = status.optLong(JSON_TX, 0),
            )
        }.getOrDefault(AWGProbeResult(false))
    }

    private fun awgCarrying(
        handshakeEstablished: Boolean,
        nowMs: Long,
        lastRxProgressAtMs: Long,
        lastEndToEndProbeAtMs: Long,
        allowEndToEndProbe: Boolean,
    ): Boolean =
        awgCarryingEvidence(
            handshakeEstablished = handshakeEstablished,
            nowMs = nowMs,
            lastRxProgressAtMs = lastRxProgressAtMs,
            lastEndToEndProbeAtMs = lastEndToEndProbeAtMs,
            allowEndToEndProbe = allowEndToEndProbe,
            requireEndToEndProbe = DeploymentConfig.IS_PUBLIC_PLATFORM,
        )

    /**
     * Called only from the auto worker single-thread executor. The demotion atomics
     * are state holders, not a concurrent multi-writer protocol.
     */
    private fun observeAwgCarrying(route: Route, nowMs: Long, carrying: Boolean) {
        val carryingSince = awgCarryingSince(route)
        val demotionLevel = awgDemotionLevel(route)
        val retryAfter = awgRetryAfter(route)
        if (!carrying) {
            carryingSince.set(0)
            return
        }
        var sinceMs = carryingSince.get()
        if (sinceMs == 0L) {
            carryingSince.compareAndSet(0, nowMs)
            sinceMs = carryingSince.get()
        }
        if (
            demotionLevel.get() > 0 &&
            nowMs - sinceMs >= AWG_DEMOTION_RESET_CARRYING_MS
        ) {
            demotionLevel.set(0)
            retryAfter.set(0)
            telemetryEvent("awg_demotion_reset",
                "rsn" to "awg_carrying",
                "route" to routeLabel(route),
                "awg_carry" to true,
                "awg_demote" to 0,
                "awg_retry_s" to 0,
            )
        }
    }

    private fun demoteAwg(route: Route, nowMs: Long): AwgDemotion {
        val demotionLevel = awgDemotionLevel(route)
        val carryingSince = awgCarryingSince(route)
        val retryAfter = awgRetryAfter(route)
        val nextLevel = (demotionLevel.get() + 1).coerceAtMost(AWG_DEMOTION_MAX_LEVEL)
        demotionLevel.set(nextLevel)
        carryingSince.set(0)
        val backoffMs = awgDemotionBackoffMs(nextLevel)
        val retryAfterMs = nowMs + backoffMs
        retryAfter.set(retryAfterMs)
        return AwgDemotion(level = nextLevel, backoffMs = backoffMs, retryAfterMs = retryAfterMs)
    }

    private fun awgDemotionBackoffMs(level: Long): Long {
        var backoffMs = AWG_DEMOTION_BASE_BACKOFF_MS
        repeat((level - 1).coerceAtLeast(0).coerceAtMost(AWG_DEMOTION_MAX_SHIFT).toInt()) {
            backoffMs = (backoffMs * 2).coerceAtMost(AWG_DEMOTION_MAX_BACKOFF_MS)
        }
        return backoffMs
    }

    private fun isAwgCooldownActive(route: Route, nowMs: Long): Boolean =
        awgRetryAfter(route).get() > nowMs

    private fun awgRetryDelaySeconds(route: Route, nowMs: Long): Long =
        ((awgRetryAfter(route).get() - nowMs).coerceAtLeast(0) + 999) / 1000

    private fun awgDemotionLevel(route: Route): AtomicLong =
        when (route) {
            Route.AWG_RU -> awgRuDemotionLevel
            Route.AWG -> awgDemotionLevel
            else -> awgDemotionLevel
        }

    private fun awgRetryAfter(route: Route): AtomicLong =
        when (route) {
            Route.AWG_RU -> awgRuRetryAfterElapsedMs
            Route.AWG -> awgRetryAfterElapsedMs
            else -> awgRetryAfterElapsedMs
        }

    private fun awgCarryingSince(route: Route): AtomicLong =
        when (route) {
            Route.AWG_RU -> awgRuCarryingSinceElapsedMs
            Route.AWG -> awgCarryingSinceElapsedMs
            else -> awgCarryingSinceElapsedMs
        }

    private fun awgRekeyRequested(route: Route): AtomicBoolean =
        when (route) {
            Route.AWG_RU -> awgRuRekeyRequested
            Route.AWG -> awgRekeyRequested
            else -> awgRekeyRequested
        }

    private fun canSwitchRoute(nowMs: Long, lastRouteSwitchAtMs: Long, reason: String): Boolean =
        lastRouteSwitchAtMs == 0L ||
            nowMs - lastRouteSwitchAtMs >= ROUTE_SWITCH_MIN_INTERVAL_MS ||
            reason == ROUTE_REASON_ACTIVE_UNHEALTHY

    private fun isRecent(nowMs: Long, timestampMs: Long, maxAgeMs: Long): Boolean =
        isRecentTimestamp(nowMs, timestampMs, maxAgeMs)

    private fun probeReality(route: Route, cfg: RealityUiConfig?): RealityProbeResult {
        if (cfg?.isComplete() != true) return RealityProbeResult(false, "config_incomplete")
        if (xrayProcess(route)?.isAlive != true) return RealityProbeResult(false, "process_dead")
        localTcpError(REALITY_HOST, routePort(route), LOCAL_TCP_PROBE_TIMEOUT_MS)?.let { error ->
            return RealityProbeResult(false, "local_tcp:$error")
        }
        var lastResult = RealityProbeResult(false, "probe_not_run")
        for (attempt in 0 until REALITY_PROBE_ATTEMPTS) {
            lastResult = runCatching {
                val socks = "${REALITY_HOST}:${routePort(route)}"
                val ip = fetchOutboundIp(socks, HEALTH_TIMEOUT_MS)
                RealityProbeResult(
                    healthy = ip == expectedRealityIp(route),
                    tcpError = if (ip == expectedRealityIp(route)) "" else "unexpected_egress:$ip",
                    outboundIp = ip,
                )
            }.getOrElse { error ->
                RealityProbeResult(false, Telemetry.safeErrorMessage(error))
            }
            if (lastResult.healthy || !shouldRetryRealityProbe(attempt)) return lastResult
        }
        return lastResult
    }

    private fun localTcpError(host: String, port: Int, timeoutMs: Int): String? =
        runCatching {
            Socket().use { socket ->
                socket.connect(InetSocketAddress(host, port), timeoutMs)
            }
            null
        }.getOrElse { error ->
            Telemetry.safeErrorMessage(error).ifBlank { "connect_failed" }
        }

    private fun realityEgressClass(route: Route, ip: String): String =
        when {
            route == Route.REALITY && ip.isNotBlank() ->
                if (ip == expectedRealityIp(route)) "tw_expected" else "tw_other"
            route == Route.REALITY2 && ip.isNotBlank() ->
                if (ip == expectedRealityIp(route)) "reality2_expected" else "reality2_other"
            else -> ""
        }

    private fun routePort(route: Route): Int =
        when (route) {
            Route.REALITY -> REALITY_PORT
            Route.REALITY2 -> REALITY2_PORT
            Route.AWG_RU -> AWG_RU_UPSTREAM.port
            Route.AWG -> AWG_UPSTREAM.port
        }

    private fun routeXrayDir(route: Route): String =
        when (route) {
            Route.REALITY -> "reality"
            Route.REALITY2 -> "reality2"
            Route.AWG_RU -> "awgru"
            Route.AWG -> "awg"
        }

    private fun expectedRealityIp(route: Route): String =
        when (route) {
            Route.REALITY -> if (DeploymentConfig.IS_PUBLIC_PLATFORM) {
                TransportRuntime.publicRealityEgressIp
            } else {
                EXPECTED_REALITY_IP
            }
            Route.REALITY2 -> if (DeploymentConfig.IS_PUBLIC_PLATFORM) {
                TransportRuntime.publicReality2EgressIp
            } else {
                EXPECTED_REALITY2_IP
            }
            Route.AWG_RU -> ""
            Route.AWG -> ""
        }

    private fun expectedEgressIp(route: Route): String =
        when (route) {
            Route.AWG_RU -> if (DeploymentConfig.IS_PUBLIC_PLATFORM) {
                TransportRuntime.publicPlatformRouteSlots.awgRuExpectedEgressIp
            } else {
                ""
            }
            Route.AWG -> if (DeploymentConfig.IS_PUBLIC_PLATFORM) {
                TransportRuntime.publicPlatformRouteSlots.awgExpectedEgressIp
            } else {
                ""
            }
            Route.REALITY, Route.REALITY2 -> expectedRealityIp(route)
        }

    private fun outboundMatchesRoute(route: Route, ip: String): Boolean {
        if (ip.isBlank()) return false
        val expected = expectedEgressIp(route)
        return if (DeploymentConfig.IS_PUBLIC_PLATFORM) {
            expected.isNotBlank() && ip == expected
        } else {
            expected.isBlank() || ip == expected
        }
    }

    private fun telemetryHeartbeatDelay(stable: Boolean): Long {
        val base = if (stable) TELEMETRY_HEARTBEAT_STABLE_MS else TELEMETRY_HEARTBEAT_UNHEALTHY_MS
        return base + Random.nextLong(TELEMETRY_HEARTBEAT_JITTER_MS)
    }

    private fun stateFor(
        route: Route,
        awgRuProbe: AWGProbeResult,
        awgProbe: AWGProbeResult,
        realityHealthy: Boolean,
        reality2Healthy: Boolean,
        outboundIp: String,
        lastExchangeAgeSeconds: Long?,
        stableSinceElapsedRealtimeMs: Long?,
        clock: ClockCheckResult,
    ): TransportUiState {
        val routeHealthy = routeHealthy(route, awgRuProbe, awgProbe, realityHealthy, reality2Healthy, outboundIp)
        val tunnelStable = routeHealthy
        return TransportUiState(
            stateTextRes = when {
                tunnelStable -> R.string.state_connected_stable
                routeHealthy || outboundIp.isNotBlank() -> R.string.state_reconnecting
                else -> R.string.state_starting
            },
            clockTextRes = clock.statusTextRes,
            clockSkewSeconds = clock.skewSeconds,
            handshakeEstablished = routeHealthy,
            tunnelStable = tunnelStable,
            activeTransport = routeLabel(route),
            socksListen = ROUTER_SOCKS,
            rxBytes = when (route) {
                Route.AWG_RU -> awgRuProbe.rxBytes
                Route.AWG -> awgProbe.rxBytes
                Route.REALITY -> realityRxBytes.get()
                Route.REALITY2 -> reality2RxBytes.get()
            },
            txBytes = when (route) {
                Route.AWG_RU -> awgRuProbe.txBytes
                Route.AWG -> awgProbe.txBytes
                Route.REALITY -> realityTxBytes.get()
                Route.REALITY2 -> reality2TxBytes.get()
            },
            outboundIp = outboundIp,
            lastExchangeAgeSeconds = lastExchangeAgeSeconds,
            stableSinceElapsedRealtimeMs = stableSinceElapsedRealtimeMs,
        )
    }

    private fun routeHealthy(
        route: Route,
        awgRuProbe: AWGProbeResult,
        awgProbe: AWGProbeResult,
        realityHealthy: Boolean,
        reality2Healthy: Boolean,
        outboundIp: String,
    ): Boolean {
        fun realityRouteHealthy(realityRoute: Route, healthy: Boolean): Boolean {
            val expected = expectedRealityIp(realityRoute)
            return if (DeploymentConfig.IS_PUBLIC_PLATFORM) {
                healthy && expected.isNotBlank() && outboundIp == expected
            } else {
                healthy && (expected.isBlank() || outboundIp == expected)
            }
        }
        return when (route) {
            Route.AWG_RU -> awgRuProbe.carrying
            Route.AWG -> awgProbe.carrying
            Route.REALITY -> realityRouteHealthy(Route.REALITY, realityHealthy)
            Route.REALITY2 -> realityRouteHealthy(Route.REALITY2, reality2Healthy)
        }
    }

    private fun maybeCheckUpdates(route: Route, nowMs: Long) {
        DistributionChannel.maybeCheckAutomatically(
            context = applicationContext,
            auth = TransportRuntime.auth,
            socksListen = ROUTER_SOCKS,
            activeTransport = routeLabel(route),
            nowMs = nowMs,
            mainHandler = mainHandler,
        )
    }

    private fun fetchOutboundIp(socksListen: String, timeoutMs: Int): String {
        val address = socksListen.substringBefore(":")
        val port = socksListen.substringAfter(":", ROUTER_PORT.toString()).toInt()
        val proxy = Proxy(Proxy.Type.SOCKS, InetSocketAddress(address, port))
        val connection = URL(OUTBOUND_URL).openConnection(proxy) as HttpsURLConnection
        connection.connectTimeout = timeoutMs
        connection.readTimeout = timeoutMs
        connection.setRequestProperty("Connection", "keep-alive")
        return connection.inputStream.bufferedReader().use { it.readText().trim() }
    }

    private fun checkClock(): ClockCheckResult =
        try {
            ClockDiagnostics.check(TransportRuntime.debugClockSkewSeconds)
        } catch (_: Throwable) {
            ClockDiagnostics.unavailable()
        }

    private fun publishState(state: TransportUiState) {
        mainHandler.post {
            TransportRuntime.state = state
        }
    }

    private fun drainProcessOutput(process: Process) {
        Thread {
            runCatching {
                process.inputStream.bufferedReader().useLines { lines ->
                    lines.forEach { _ -> }
                }
            }
        }.apply {
            isDaemon = true
            start()
        }
    }

    private fun createNotificationChannel() {
        val channel = NotificationChannel(
            CHANNEL_ID,
            getString(R.string.notification_channel),
            NotificationManager.IMPORTANCE_LOW,
        )
        getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
    }

    private fun buildNotification(): Notification =
        Notification.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle(getString(R.string.notification_title))
            .setContentText(getString(R.string.notification_text))
            .setContentIntent(mainActivityLaunchPendingIntent(this))
            .setOngoing(true)
            .build()

    private fun startTransportForeground() {
        val notification = buildNotification()
        if (Build.VERSION.SDK_INT >= 29) {
            startForeground(
                NOTIFICATION_ID,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE,
            )
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    private enum class Route {
        AWG_RU,
        AWG,
        REALITY,
        REALITY2,
    }

    private enum class NetworkEvent(val logText: String, val marksTunnelDisruption: Boolean = false) {
        DEFAULT_LOST("default network lost", marksTunnelDisruption = true),
        DEFAULT_AVAILABLE("default network available"),
        DEFAULT_SWITCHED("default network switched", marksTunnelDisruption = true),
        SCREEN_ON("screen on"),
        FOREGROUND_RESYNC("foreground resync"),
        BACKSTOP_ALARM("backstop alarm"),
    }

    private data class Upstream(val host: String, val port: Int)

    private data class RouteCounters(val rx: AtomicLong, val tx: AtomicLong)

    private data class AWGProbeResult(
        val handshakeEstablished: Boolean,
        val carrying: Boolean = false,
        val rxBytes: Long = 0,
        val txBytes: Long = 0,
    )

    private data class RouteDecision(val route: Route, val reason: String = "")

    private data class AwgDemotion(
        val level: Long,
        val backoffMs: Long,
        val retryAfterMs: Long,
    )

    private data class AWGStartResult(
        val started: Boolean,
        val error: String = "",
        val errorKind: String = "unknown",
    )

    private data class XrayStartResult(
        val started: Boolean,
        val error: String = "",
        val errorKind: String = "unknown",
    )

    private data class RealityProbeResult(
        val healthy: Boolean,
        val tcpError: String = "",
        val outboundIp: String = "",
    )

    private data class RouteHealthSnapshot(
        val observedAtMs: Long,
        val routeHealthy: Boolean,
        val lastTrafficAtMs: Long?,
        val stableSinceElapsedRealtimeMs: Long?,
    )

    private class SocksRouter(
        private val host: String,
        private val port: Int,
        private val upstreamProvider: () -> Upstream,
        private val realityRxCounter: AtomicLong,
        private val realityTxCounter: AtomicLong,
        private val reality2RxCounter: AtomicLong,
        private val reality2TxCounter: AtomicLong,
    ) {
        private val active = AtomicBoolean(false)
        private val ioPool = Executors.newFixedThreadPool(SOCKS_IO_THREADS)
        private val activeSessionCount = AtomicLong(0)
        private val sessions = Collections.synchronizedMap(mutableMapOf<Socket, TrackedSocket>())
        private val nextSessionID = AtomicLong(1)

        @Volatile
        private var serverSocket: ServerSocket? = null

        fun start() {
            if (!active.compareAndSet(false, true)) return
            val server = ServerSocket().apply {
                reuseAddress = true
                bind(InetSocketAddress(InetAddress.getByName(host), port))
            }
            serverSocket = server
            ioPool.execute {
                while (active.get()) {
                    try {
                        val client = server.accept()
                        if (activeSessionCount.incrementAndGet() > SOCKS_MAX_SESSIONS) {
                            activeSessionCount.decrementAndGet()
                            runCatching { client.close() }
                            continue
                        }
                        try {
                            ioPool.execute {
                                try {
                                    handleClient(client)
                                } finally {
                                    activeSessionCount.decrementAndGet()
                                }
                            }
                        } catch (rejected: RejectedExecutionException) {
                            activeSessionCount.decrementAndGet()
                            runCatching { client.close() }
                        }
                    } catch (_: Throwable) {
                        if (active.get()) {
                            runCatching { Thread.sleep(100) }
                        }
                    }
                }
            }
        }

        fun closeSessions() {
            val snapshot = synchronized(sessions) { sessions.keys.toList() }
            snapshot.forEach { runCatching { it.close() } }
        }

        fun closeSessionsCreatedBefore(cutoffElapsedRealtimeMs: Long): Int {
            val snapshot = synchronized(sessions) {
                sessions
                    .filterValues { it.createdAtMs < cutoffElapsedRealtimeMs }
                    .map { it.key }
            }
            var closed = 0
            snapshot.forEach { socket ->
                if (runCatching { socket.close() }.isSuccess) {
                    closed++
                }
            }
            return closed
        }

        fun stop() {
            active.set(false)
            runCatching { serverSocket?.close() }
            closeSessions()
            ioPool.shutdownNow()
            runCatching { ioPool.awaitTermination(SOCKS_STOP_DRAIN_TIMEOUT_MS, TimeUnit.MILLISECONDS) }
        }

        private fun handleClient(client: Socket) {
            val sessionID = nextSessionID.getAndIncrement()
            val sessionCreatedAtMs = SystemClock.elapsedRealtime()
            var upstream: Socket? = null
            sessions[client] = TrackedSocket(sessionCreatedAtMs)
            try {
                client.use { clientSocket ->
                    tuneSocket(clientSocket)
                    val clientIn = clientSocket.getInputStream()
                    val clientOut = clientSocket.getOutputStream()
                    val request = readClientConnectRequest(clientIn, clientOut)
                    val selected = upstreamProvider()
                    val counters = countersFor(selected)
                    Log.d(LOG_TAG, "session=$sessionID connect dest=${request.destination} upstream=${selected.host}:${selected.port}")
                    val upstreamSocketForSession = connectUpstream(request.raw, selected)
                    upstream = upstreamSocketForSession
                    sessions[upstreamSocketForSession] = TrackedSocket(sessionCreatedAtMs)
                    upstreamSocketForSession.use { upstreamSocket ->
                        sendSuccess(clientOut)
                        val totals = proxy(sessionID, clientSocket, upstreamSocket, counters)
                        Log.d(
                            LOG_TAG,
                            "session=$sessionID closed dest=${request.destination} up=${totals.upBytes} down=${totals.downBytes}",
                        )
                    }
                }
            } catch (rejected: SocksRequestRejectedException) {
                Log.i(LOG_TAG, "session=$sessionID rejected: ${rejected.message}")
            } catch (error: Throwable) {
                Log.w(LOG_TAG, "session=$sessionID failed: ${error.message}")
                if (error is UpstreamConnectException) {
                    runCatching { sendFailure(client.getOutputStream()) }
                }
            } finally {
                upstream?.let {
                    sessions.remove(it)
                    runCatching { it.close() }
                }
                sessions.remove(client)
            }
        }

        private fun readClientConnectRequest(input: InputStream, output: OutputStream): SocksConnectRequest {
            if (input.readByteOrThrow() != SOCKS_VERSION) throw EOFException()
            val methods = input.readByteOrThrow()
            input.readExact(methods)
            output.write(byteArrayOf(SOCKS_VERSION.toByte(), SOCKS_NO_AUTH.toByte()))
            output.flush()

            val header = input.readExact(4)
            if (header[0].toInt() and BYTE_MASK != SOCKS_VERSION) throw EOFException()
            val command = header[1].toInt() and BYTE_MASK
            if (command != SOCKS_CONNECT) throw EOFException("unsupported socks command $command")
            val atyp = header[3].toInt() and BYTE_MASK
            val addressLength = when (atyp) {
                SOCKS_ATYP_IPV4 -> 4
                SOCKS_ATYP_DOMAIN -> input.readByteOrThrow()
                SOCKS_ATYP_IPV6 -> 16
                else -> throw EOFException()
            }
            val address = input.readExact(addressLength)
            val portBytes = input.readExact(2)
            val policy = socksConnectAddressPolicy(atyp)
            if (!policy.openUpstream) {
                val destination = describeDestination(atyp, address, portBytes)
                output.write(policy.rejectReply ?: throw EOFException("missing socks reject reply"))
                output.flush()
                throw SocksRequestRejectedException("unsupported address type $atyp dest=$destination")
            }
            val raw = byteArrayOf(
                SOCKS_VERSION.toByte(),
                SOCKS_CONNECT.toByte(),
                0,
                header[3],
            ) + if ((header[3].toInt() and BYTE_MASK) == SOCKS_ATYP_DOMAIN) {
                byteArrayOf(addressLength.toByte()) + address
            } else {
                address
            } + portBytes
            return SocksConnectRequest(
                raw = raw,
                destination = describeDestination(header[3].toInt() and BYTE_MASK, address, portBytes),
            )
        }

        private fun connectUpstream(request: ByteArray, upstream: Upstream): Socket {
            val socket = Socket()
            try {
                tuneSocket(socket)
                socket.connect(InetSocketAddress(upstream.host, upstream.port), UPSTREAM_CONNECT_TIMEOUT_MS)
                val input = socket.getInputStream()
                val output = socket.getOutputStream()
                output.write(byteArrayOf(SOCKS_VERSION.toByte(), 1, SOCKS_NO_AUTH.toByte()))
                output.flush()
                val greeting = input.readExact(2)
                if ((greeting[0].toInt() and BYTE_MASK) != SOCKS_VERSION ||
                    (greeting[1].toInt() and BYTE_MASK) != SOCKS_NO_AUTH
                ) {
                    throw EOFException("bad upstream socks greeting")
                }
                output.write(request)
                output.flush()
                val responseHeader = input.readExact(4)
                if ((responseHeader[0].toInt() and BYTE_MASK) != SOCKS_VERSION ||
                    (responseHeader[1].toInt() and BYTE_MASK) != 0
                ) {
                    throw EOFException("bad upstream socks connect response")
                }
                val bindAddressLength = when (responseHeader[3].toInt() and BYTE_MASK) {
                    SOCKS_ATYP_IPV4 -> 4
                    SOCKS_ATYP_DOMAIN -> input.readByteOrThrow()
                    SOCKS_ATYP_IPV6 -> 16
                    else -> throw EOFException()
                }
                input.readExact(bindAddressLength + 2)
                return socket
            } catch (error: Throwable) {
                runCatching { socket.close() }
                throw UpstreamConnectException(error)
            }
        }

        private fun proxy(sessionID: Long, client: Socket, upstream: Socket, counters: RouteCounters?): PipeTotals {
            val closed = AtomicBoolean(false)
            val done = CountDownLatch(2)
            val upBytes = AtomicLong(0)
            val downBytes = AtomicLong(0)
            fun closeBoth() {
                if (closed.compareAndSet(false, true)) {
                    runCatching { client.close() }
                    runCatching { upstream.close() }
                }
            }
            val upstreamThread = Thread {
                try {
                    pipe(
                        sessionID = sessionID,
                        input = client.getInputStream(),
                        output = upstream.getOutputStream(),
                        counter = upBytes,
                        aggregateCounter = counters?.tx,
                        direction = "up",
                    )
                } finally {
                    closeBoth()
                    done.countDown()
                }
            }
            val downstreamThread = Thread {
                try {
                    pipe(
                        sessionID = sessionID,
                        input = upstream.getInputStream(),
                        output = client.getOutputStream(),
                        counter = downBytes,
                        aggregateCounter = counters?.rx,
                        direction = "down",
                    )
                } finally {
                    closeBoth()
                    done.countDown()
                }
            }
            upstreamThread.isDaemon = true
            downstreamThread.isDaemon = true
            upstreamThread.start()
            downstreamThread.start()
            try {
                done.await()
            } catch (error: InterruptedException) {
                closeBoth()
                Thread.currentThread().interrupt()
            }
            return PipeTotals(upBytes = upBytes.get(), downBytes = downBytes.get())
        }

        private fun pipe(
            sessionID: Long,
            input: InputStream,
            output: OutputStream,
            counter: AtomicLong,
            aggregateCounter: AtomicLong?,
            direction: String,
        ) {
            try {
                val buffer = ByteArray(PROXY_BUFFER_BYTES)
                while (active.get()) {
                    val read = input.read(buffer)
                    if (read < 0) break
                    output.write(buffer, 0, read)
                    counter.addAndGet(read.toLong())
                    aggregateCounter?.addAndGet(read.toLong())
                }
                output.flush()
            } catch (error: Throwable) {
                if (active.get()) {
                    Log.d(LOG_TAG, "session=$sessionID pipe=$direction closed: ${error.message}")
                }
            }
        }

        private fun tuneSocket(socket: Socket) {
            runCatching { socket.tcpNoDelay = true }
            runCatching { socket.receiveBufferSize = PROXY_BUFFER_BYTES }
            runCatching { socket.sendBufferSize = PROXY_BUFFER_BYTES }
        }

        private fun describeDestination(atyp: Int, address: ByteArray, portBytes: ByteArray): String {
            val host = when (atyp) {
                SOCKS_ATYP_IPV4, SOCKS_ATYP_IPV6 -> InetAddress.getByAddress(address).hostAddress
                SOCKS_ATYP_DOMAIN -> address.toString(Charsets.UTF_8)
                else -> "unknown"
            }
            val port = ((portBytes[0].toInt() and BYTE_MASK) shl 8) or (portBytes[1].toInt() and BYTE_MASK)
            return "$host:$port"
        }

        private fun countersFor(upstream: Upstream): RouteCounters? =
            when (upstream.port) {
                REALITY_PORT -> RouteCounters(rx = realityRxCounter, tx = realityTxCounter)
                REALITY2_PORT -> RouteCounters(rx = reality2RxCounter, tx = reality2TxCounter)
                else -> null
            }

        private fun sendSuccess(output: OutputStream) {
            output.write(byteArrayOf(5, 0, 0, 1, 0, 0, 0, 0, 0, 0))
            output.flush()
        }

        private fun sendFailure(output: OutputStream) {
            output.write(byteArrayOf(5, 1, 0, 1, 0, 0, 0, 0, 0, 0))
            output.flush()
        }

        private fun InputStream.readByteOrThrow(): Int {
            val value = read()
            if (value < 0) throw EOFException()
            return value
        }

        private fun InputStream.readExact(size: Int): ByteArray {
            val out = ByteArray(size)
            var offset = 0
            while (offset < size) {
                val read = read(out, offset, size - offset)
                if (read < 0) throw EOFException()
                offset += read
            }
            return out
        }

        private data class SocksConnectRequest(val raw: ByteArray, val destination: String)

        private data class PipeTotals(val upBytes: Long, val downBytes: Long)

        private class UpstreamConnectException(cause: Throwable) : Exception(cause.message, cause)

        private class SocksRequestRejectedException(message: String) : Exception(message)

        private data class TrackedSocket(val createdAtMs: Long)

        private companion object {
            private const val PROXY_BUFFER_BYTES = 64 * 1024
            private const val SOCKS_IO_THREADS = 8
            private const val SOCKS_MAX_SESSIONS = 32L
            private const val SOCKS_STOP_DRAIN_TIMEOUT_MS = 2_000L
        }
    }

    companion object {
        const val ACTION_START = "pro.netcloud.trafficwrapper.action.AUTO_START"
        const val ACTION_STOP = "pro.netcloud.trafficwrapper.action.AUTO_STOP"
        const val ACTION_RESYNC = "pro.netcloud.trafficwrapper.action.AUTO_RESYNC"
        const val ACTION_BACKSTOP = "pro.netcloud.trafficwrapper.action.AUTO_BACKSTOP"
        const val EXTRA_MODE = "pro.netcloud.trafficwrapper.extra.TRANSPORT_MODE"
        const val EXTRA_KEEP_ALIVE_AFTER_STOP = "pro.netcloud.trafficwrapper.extra.KEEP_ALIVE_AFTER_STOP"

        @Volatile
        private var requestedMode: TransportChoice = TransportChoice.AUTO

        private const val CHANNEL_ID = "transport"
        private const val NOTIFICATION_ID = 1303
        private const val XRAY_LIB_NAME = "libxray.so"

        private const val ROUTER_HOST = "127.0.0.1"
        private const val ROUTER_PORT = 18080
        private const val ROUTER_SOCKS = "$ROUTER_HOST:$ROUTER_PORT"
        private const val REALITY_HOST = "127.0.0.1"
        private const val REALITY_PORT = 18081
        private const val REALITY2_PORT = 18083
        private const val REALITY_TCP_MAX_SEG = 1200

        private val AWG_UPSTREAM = Upstream("127.0.0.1", 18082)
        private val AWG_RU_UPSTREAM = Upstream("127.0.0.1", 18084)
        private val REALITY_UPSTREAM = Upstream("127.0.0.1", 18081)
        private val REALITY2_UPSTREAM = Upstream("127.0.0.1", 18083)

        private val EXPECTED_REALITY_IP: String get() = DEFAULT_REALITY_EGRESS_IP
        private val EXPECTED_REALITY2_IP: String get() = DEFAULT_REALITY2_EGRESS_IP
        private val OUTBOUND_URL: String get() = DeploymentConfig.OUTBOUND_URL.ifBlank { "https://api.ipify.org" }

        private const val PROBE_INTERVAL_MS = 2_500L
        private const val REALITY_INACTIVE_PROBE_INTERVAL_MS = 75_000L
        private const val REALITY_LOCAL_RX_FRESH_MS = 30_000L
        private const val LOCAL_TCP_PROBE_TIMEOUT_MS = 300
        private const val PUBLIC_CONFIG_POLL_INITIAL_DELAY_MS = 5_000L
        private const val PUBLIC_CONFIG_POLL_INTERVAL_MS = 20_000L
        private const val PUBLIC_CONFIG_POLL_TIMEOUT_MS = 7_000L
        private const val PUBLIC_HTTP_HEADER_LIMIT_BYTES = 64 * 1024
        private const val PUBLIC_CONFIG_DEFAULT_BASE_URL = "http://awg-gw:8080/tw"
        // Android deep Doze throttles exact allow-while-idle alarms to roughly
        // one delivery per 9 minutes, so this is a kill-recovery watchdog.
        private const val BACKSTOP_INTERVAL_MS = 10 * 60 * 1000L
        private const val AWG_UNHEALTHY_PROBE_INTERVAL_MS = 75_000L
        private const val OUTBOUND_REFRESH_INTERVAL_MS = 15_000L
        private const val XRAY_WARMUP_MS = 800L
        private const val XRAY_STOP_GRACE_MS = 1_500L
        private const val HEALTH_TIMEOUT_MS = HEALTH_PROBE_TIMEOUT_MS
        private const val OUTBOUND_TIMEOUT_MS = 5_000
        private const val ACTIVE_AWG_STALL_OUTBOUND_TIMEOUT_MS = 2_000
        private const val ACTIVE_AWG_FAST_FAIL_FAILURE_MAX_AGE_MS = 7_000L
        private const val UPSTREAM_CONNECT_TIMEOUT_MS = 5_000
        private const val AWG_FAILURES_BEFORE_FALLBACK = 2
        private const val AWG_OUTBOUND_FAILURES_BEFORE_NOT_CARRYING = 2
        private const val AWG_RETRY_FAILURES_BEFORE_DEMOTE = 2
        private const val AWG_REKEY_FAILURES_BEFORE_REFRESH = 6
        private const val HEALTH_LOSS_GRACE_MS = AWG_CARRYING_EVIDENCE_MAX_AGE_MS * 2
        private const val RX_FRESH_FOR_USABLE_MS = OUTBOUND_REFRESH_INTERVAL_MS * 2
        private const val AWG_START_MIN_BACKOFF_MS = 10_000L
        private const val AWG_START_MAX_BACKOFF_MS = 10 * 60 * 1000L
        private const val AWG_UDP_DEAD_FAILURES_BEFORE_PAUSE = 3
        private const val AWG_UDP_DEAD_BACKOFF_MS = 10 * 60 * 1000L
        private const val AWG_RETRY_MAX_INTERVAL_MS = 5 * 60 * 1000L
        private const val AWG_RETRY_MAX_BACKOFF_SHIFT = 5
        private const val AWG_DEMOTION_BASE_BACKOFF_MS = 60_000L
        private const val AWG_DEMOTION_MAX_BACKOFF_MS = 30 * 60 * 1000L
        private const val AWG_DEMOTION_MAX_LEVEL = 12L
        private const val AWG_DEMOTION_MAX_SHIFT = 5L
        private const val AWG_DEMOTION_RESET_CARRYING_MS = 30_000L
        private const val ROUTE_COOLDOWN_BASE_MS = 20_000L
        private const val ROUTE_COOLDOWN_MAX_MS = 5 * 60 * 1000L
        private const val ROUTE_COOLDOWN_MAX_LEVEL = 8
        private const val ROUTE_COOLDOWN_MAX_SHIFT = 4
        private const val RECONNECT_MIN_BACKOFF_MS = 2_500L
        private const val RECONNECT_MAX_BACKOFF_MS = 15_000L
        private const val ROUTE_DWELL_MS = 30_000L
        private const val ACTIVE_STABLE_RETRY_SUPPRESS_MS = 30_000L
        private const val ROUTE_LOSS_RESET_GRACE_MS = 15_000L
        private const val ROUTE_SWITCH_MIN_INTERVAL_MS = 10_000L
        private const val RESYNC_SESSION_GRACE_MS = 5_000L
        private const val AUTO_REVIVE_DEBOUNCE_MS = 45_000L
        private const val STABLE_TRAFFIC_MAX_AGE_SECONDS = 30L
        private const val STABLE_TRAFFIC_MAX_AGE_MS = STABLE_TRAFFIC_MAX_AGE_SECONDS * 1000L
        private const val TELEMETRY_HEARTBEAT_UNHEALTHY_MS = 60_000L
        private const val TELEMETRY_HEARTBEAT_STABLE_MS = 15 * 60 * 1000L
        private const val TELEMETRY_HEARTBEAT_JITTER_MS = 15_000L
        private const val BATTERY_RESTRICTION_NOTIFY_CHECK_INTERVAL_MS = 60L * 60L * 1000L
        private const val LOG_TAG = "TWSocksRouter"
        private const val WAKE_LOCK_TAG = "TrafficWrapper:transport"
        private const val BACKSTOP_REQUEST_CODE = 1304
        private const val ROUTE_REASON_AWG_NOT_CARRYING = "awg_not_carrying"
        private const val ROUTE_REASON_AWG_UNHEALTHY = "awg_unhealthy"
        private const val ROUTE_REASON_ACTIVE_UNHEALTHY = "active_unhealthy"
        private const val ROUTE_REASON_HEALTH_LOST = "health_lost"
        private const val ROUTE_REASON_PRIORITY_RECOVERED = "priority_recovered"
        private const val ROUTE_REASON_GUARD_FALLBACK = "route_guard_fallback"
        private const val ROUTE_REASON_NO_UPSTREAM = "no_upstream_ready"

        private val activeService = AtomicReference<AutoTransportService?>(null)
        private val lastNetworkReviveAtMs = AtomicLong(0)

        fun requestBackstopResync(context: Context): Boolean {
            if (!TransportLifecycleStore.shouldKeepAlive(context)) return false
            Telemetry.flush(context.applicationContext)
            val service = activeService.get() ?: return false
            if (!service.workerActive.get()) return false
            service.requestLifecycleResync(NetworkEvent.BACKSTOP_ALARM)
            return true
        }

        fun scheduleBackstopAlarm(context: Context) {
            val appContext = context.applicationContext
            if (!TransportLifecycleStore.shouldKeepAlive(appContext)) return
            val triggerAt = SystemClock.elapsedRealtime() + BACKSTOP_INTERVAL_MS
            val alarmManager = appContext.getSystemService(AlarmManager::class.java)
            runCatching {
                alarmManager.setExactAndAllowWhileIdle(
                    AlarmManager.ELAPSED_REALTIME_WAKEUP,
                    triggerAt,
                    backstopPendingIntent(appContext),
                )
                Log.i(LOG_TAG, "backstop exact alarm scheduled")
            }.onFailure { error ->
                Log.w(LOG_TAG, "backstop exact alarm failed: ${error.message}")
                alarmManager.setAndAllowWhileIdle(
                    AlarmManager.ELAPSED_REALTIME_WAKEUP,
                    triggerAt,
                    backstopPendingIntent(appContext),
                )
            }
        }

        fun cancelBackstopAlarm(context: Context) {
            val appContext = context.applicationContext
            appContext.getSystemService(AlarmManager::class.java)
                .cancel(backstopPendingIntent(appContext))
        }

        private fun backstopPendingIntent(context: Context): PendingIntent =
            PendingIntent.getBroadcast(
                context,
                BACKSTOP_REQUEST_CODE,
                Intent(context, TransportBackstopReceiver::class.java)
                    .setAction(ACTION_BACKSTOP)
                    .setPackage(context.packageName),
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
            )

        private const val JSON_OK = "ok"
        private const val JSON_ERROR = "error"
        private const val JSON_STATUS = "status"
        private const val JSON_HANDSHAKE = "handshake_established"
        private const val JSON_RX = "rx_bytes"
        private const val JSON_TX = "tx_bytes"

        private const val SOCKS_VERSION = 5
        private const val SOCKS_NO_AUTH = 0
        private const val SOCKS_CONNECT = 1
        private const val SOCKS_ATYP_IPV4 = 1
        private const val SOCKS_ATYP_DOMAIN = 3
        private const val SOCKS_ATYP_IPV6 = 4
        private const val BYTE_MASK = 0xff
        private val awgRuRekeyRequested = AtomicBoolean(false)
        private val awgRekeyRequested = AtomicBoolean(false)

        private fun routeLabel(route: Route): String =
            when (route) {
                Route.AWG_RU -> "awg-ru"
                Route.AWG -> "AWG"
                Route.REALITY -> "REALITY"
                Route.REALITY2 -> "REALITY2"
            }
    }
}
