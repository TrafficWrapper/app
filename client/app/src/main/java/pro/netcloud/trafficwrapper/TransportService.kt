package pro.netcloud.trafficwrapper

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Intent
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import org.json.JSONObject
import pro.netcloud.trafficwrapper.go.transport.Transport
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.URL
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import javax.net.ssl.HttpsURLConnection

class TransportService : Service() {
    private val mainHandler = Handler(Looper.getMainLooper())
    private val executor: ExecutorService = Executors.newSingleThreadExecutor()

    @Volatile
    private var workerActive = false

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopTransport()
            stopSelf()
            return START_NOT_STICKY
        }
        createNotificationChannel()
        startForeground(NOTIFICATION_ID, buildNotification())
        BatteryRestrictionNotifier.maybeNotify(applicationContext)
        startTransport(intent?.getDebugClockSkewSeconds())
        return START_STICKY
    }

    override fun onDestroy() {
        stopTransport()
        executor.shutdownNow()
        super.onDestroy()
    }

    private fun startTransport(fakeClockSkewSeconds: Long?) {
        if (workerActive) return
        workerActive = true
        publishState(
            TransportUiState(
                stateTextRes = R.string.state_starting,
                clockTextRes = R.string.clock_status_checking,
            ),
        )
        executor.execute {
            try {
                val clock = checkClock(fakeClockSkewSeconds)
                if (!clock.okForStart) {
                    workerActive = false
                    publishState(
                        TransportUiState(
                            stateTextRes = R.string.state_clock_error,
                            clockTextRes = clock.statusTextRes,
                            clockSkewSeconds = clock.skewSeconds,
                        ),
                    )
                    return@execute
                }
                val startResult = Transport.startProvisioned()
                publishTransportState(startResult, R.string.state_starting, "", clock)
                if (!JSONObject(startResult).optBoolean(JSON_OK, false)) {
                    workerActive = false
                    return@execute
                }
                val socksListen = parseSOCKSListen(startResult).ifBlank { DEFAULT_SOCKS }

                var outboundIp = ""
                while (workerActive) {
                    if (outboundIp.isEmpty()) {
                        outboundIp = fetchOutboundIp(socksListen)
                    }
                    publishTransportState(Transport.stat(), R.string.state_starting, outboundIp, clock)
                    Thread.sleep(STAT_INTERVAL_MS)
                }
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
            } catch (_: Throwable) {
                publishState(
                    TransportUiState(
                        stateTextRes = R.string.state_error,
                        clockTextRes = R.string.clock_status_unavailable,
                    ),
                )
            }
        }
    }

    private fun stopTransport() {
        workerActive = false
        Transport.stop()
        publishState(TransportUiState(stateTextRes = R.string.state_idle))
    }

    private fun publishTransportState(
        raw: String,
        fallbackState: Int,
        outboundIp: String,
        clock: ClockCheckResult,
    ) {
        val state = parseTransportState(raw, fallbackState, outboundIp, clock)
        publishState(state)
    }

    private fun publishState(state: TransportUiState) {
        mainHandler.post {
            TransportRuntime.state = state
        }
    }

    private fun parseSOCKSListen(raw: String): String {
        val root = JSONObject(raw)
        val status = root.optJSONObject(JSON_STATUS) ?: return ""
        return status.optString(JSON_SOCKS)
    }

    private fun parseTransportState(
        raw: String,
        fallbackState: Int,
        outboundIp: String,
        clock: ClockCheckResult,
    ): TransportUiState {
        val root = JSONObject(raw)
        if (!root.optBoolean(JSON_OK, false)) {
            return TransportUiState(
                stateTextRes = R.string.state_error,
                clockTextRes = clock.statusTextRes,
                clockSkewSeconds = clock.skewSeconds,
            )
        }
        val status = root.optJSONObject(JSON_STATUS)
            ?: return TransportUiState(
                stateTextRes = fallbackState,
                outboundIp = outboundIp,
                clockTextRes = clock.statusTextRes,
                clockSkewSeconds = clock.skewSeconds,
            )
        val handshake = status.optBoolean(JSON_HANDSHAKE, false)
        return TransportUiState(
            stateTextRes = if (handshake) R.string.state_connected else fallbackState,
            clockTextRes = clock.statusTextRes,
            clockSkewSeconds = clock.skewSeconds,
            handshakeEstablished = handshake,
            activeTransport = status.optString(JSON_TRANSPORT),
            socksListen = status.optString(JSON_SOCKS),
            rxBytes = status.optLong(JSON_RX, 0),
            txBytes = status.optLong(JSON_TX, 0),
            outboundIp = outboundIp,
        )
    }

    private fun fetchOutboundIp(socksListen: String): String {
        val address = socksListen.substringBefore(":")
        val port = socksListen.substringAfter(":", DEFAULT_SOCKS_PORT.toString()).toInt()
        val proxy = Proxy(Proxy.Type.SOCKS, InetSocketAddress(address, port))
        val connection = URL(OUTBOUND_URL).openConnection(proxy) as HttpsURLConnection
        return try {
            connection.connectTimeout = OUTBOUND_TIMEOUT_MS
            connection.readTimeout = OUTBOUND_TIMEOUT_MS
            connection.inputStream.bufferedReader().use { it.readText().trim() }
        } finally {
            connection.disconnect()
        }
    }

    private fun checkClock(fakeClockSkewSeconds: Long?): ClockCheckResult =
        try {
            ClockDiagnostics.check(fakeClockSkewSeconds)
        } catch (_: Throwable) {
            ClockDiagnostics.unavailable()
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

    companion object {
        const val ACTION_START = "pro.netcloud.trafficwrapper.action.START"
        const val ACTION_STOP = "pro.netcloud.trafficwrapper.action.STOP"
        const val EXTRA_FAKE_CLOCK_SKEW_SECONDS =
            "pro.netcloud.trafficwrapper.extra.FAKE_CLOCK_SKEW_SECONDS"

        private const val CHANNEL_ID = "transport"
        private const val NOTIFICATION_ID = 1301
        private const val DEFAULT_SOCKS = "127.0.0.1:18080"
        private const val DEFAULT_SOCKS_PORT = 18080
        private val OUTBOUND_URL: String get() = DeploymentConfig.OUTBOUND_URL
        private const val OUTBOUND_TIMEOUT_MS = 15_000
        private const val STAT_INTERVAL_MS = 1_000L

        private const val JSON_OK = "ok"
        private const val JSON_STATUS = "status"
        private const val JSON_HANDSHAKE = "handshake_established"
        private const val JSON_TRANSPORT = "active_transport"
        private const val JSON_SOCKS = "socks_listen"
        private const val JSON_RX = "rx_bytes"
        private const val JSON_TX = "tx_bytes"
    }
}

private fun Intent.getDebugClockSkewSeconds(): Long? =
    if (BuildConfig.DEBUG && hasExtra(TransportService.EXTRA_FAKE_CLOCK_SKEW_SECONDS)) {
        getLongExtra(TransportService.EXTRA_FAKE_CLOCK_SKEW_SECONDS, 0L)
    } else {
        null
    }
