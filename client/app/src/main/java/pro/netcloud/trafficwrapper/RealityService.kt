package pro.netcloud.trafficwrapper

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Intent
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.URL
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import javax.net.ssl.HttpsURLConnection

class RealityService : Service() {
    private val mainHandler = Handler(Looper.getMainLooper())
    private val executor: ExecutorService = Executors.newSingleThreadExecutor()

    @Volatile
    private var workerActive = false

    @Volatile
    private var xrayProcess: Process? = null

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopReality()
            stopSelf()
            return START_NOT_STICKY
        }
        createNotificationChannel()
        startForeground(NOTIFICATION_ID, buildNotification())
        BatteryRestrictionNotifier.maybeNotify(applicationContext)
        startReality()
        return START_STICKY
    }

    override fun onDestroy() {
        stopReality()
        executor.shutdownNow()
        super.onDestroy()
    }

    private fun startReality() {
        if (workerActive) return
        val cfg = TransportRuntime.auth.reality
        if (cfg?.isComplete() != true) {
            publishState(
                TransportUiState(
                    stateTextRes = R.string.state_error,
                    activeTransport = TRANSPORT_NAME,
                    socksListen = DEFAULT_REALITY_SOCKS,
                ),
            )
            return
        }
        workerActive = true
        publishState(
            TransportUiState(
                stateTextRes = R.string.state_starting,
                activeTransport = TRANSPORT_NAME,
                socksListen = DEFAULT_REALITY_SOCKS,
            ),
        )
        executor.execute {
            try {
                val xray = File(applicationInfo.nativeLibraryDir, XRAY_LIB_NAME)
                if (!xray.canExecute()) {
                    throw IllegalStateException("xray sidecar is not executable")
                }
                val configFile = writeXrayConfig(cfg)
                val process = ProcessBuilder(
                    xray.absolutePath,
                    "run",
                    "-config",
                    configFile.absolutePath,
                )
                    .redirectErrorStream(true)
                    .start()
                xrayProcess = process
                drainProcessOutput(process)

                var outboundIp = ""
                while (workerActive && process.isAlive) {
                    if (outboundIp.isEmpty()) {
                        outboundIp = runCatching { fetchOutboundIp(DEFAULT_REALITY_SOCKS) }.getOrDefault("")
                    }
                    publishState(
                        TransportUiState(
                            stateTextRes = if (outboundIp.isNotBlank()) {
                                R.string.state_connected
                            } else {
                                R.string.state_starting
                            },
                            handshakeEstablished = outboundIp.isNotBlank(),
                            activeTransport = TRANSPORT_NAME,
                            socksListen = DEFAULT_REALITY_SOCKS,
                            outboundIp = outboundIp,
                        ),
                    )
                    Thread.sleep(STAT_INTERVAL_MS)
                }
                if (workerActive) {
                    publishState(
                        TransportUiState(
                            stateTextRes = R.string.state_error,
                            activeTransport = TRANSPORT_NAME,
                            socksListen = DEFAULT_REALITY_SOCKS,
                            outboundIp = outboundIp,
                        ),
                    )
                }
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
            } catch (_: Throwable) {
                publishState(
                    TransportUiState(
                        stateTextRes = R.string.state_error,
                        activeTransport = TRANSPORT_NAME,
                        socksListen = DEFAULT_REALITY_SOCKS,
                    ),
                )
            } finally {
                workerActive = false
            }
        }
    }

    private fun stopReality() {
        workerActive = false
        xrayProcess?.destroy()
        xrayProcess = null
        publishState(TransportUiState(stateTextRes = R.string.state_idle))
    }

    private fun writeXrayConfig(cfg: RealityUiConfig): File {
        val dir = File(filesDir, "reality")
        if (!dir.exists() && !dir.mkdirs()) {
            throw IllegalStateException("cannot create reality config dir")
        }
        val configFile = File(dir, "xray-client.json")
        val inbound = JSONObject()
            .put("tag", "socks-in")
            .put("listen", DEFAULT_REALITY_HOST)
            .put("port", DEFAULT_REALITY_PORT)
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

    private fun fetchOutboundIp(socksListen: String): String {
        val address = socksListen.substringBefore(":")
        val port = socksListen.substringAfter(":", DEFAULT_REALITY_PORT.toString()).toInt()
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

    private fun publishState(state: TransportUiState) {
        mainHandler.post {
            TransportRuntime.state = state
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

    companion object {
        const val ACTION_START = "pro.netcloud.trafficwrapper.action.REALITY_START"
        const val ACTION_STOP = "pro.netcloud.trafficwrapper.action.REALITY_STOP"

        private const val CHANNEL_ID = "transport"
        private const val NOTIFICATION_ID = 1302
        private const val XRAY_LIB_NAME = "libxray.so"
        private const val TRANSPORT_NAME = "xray-reality"
        private const val DEFAULT_REALITY_HOST = "127.0.0.1"
        private const val DEFAULT_REALITY_PORT = 18081
        private const val REALITY_TCP_MAX_SEG = 1200
        private const val DEFAULT_REALITY_SOCKS = "$DEFAULT_REALITY_HOST:$DEFAULT_REALITY_PORT"
        private const val OUTBOUND_URL = "https://api.ipify.org"
        private const val OUTBOUND_TIMEOUT_MS = 15_000
        private const val STAT_INTERVAL_MS = 1_000L
    }
}
