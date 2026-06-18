package pro.netcloud.trafficwrapper

import android.Manifest
import android.app.Activity
import android.content.ClipData
import android.content.ClipboardManager
import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import android.provider.Settings
import android.util.Base64
import android.util.Log
import android.widget.ImageView
import android.widget.Toast
import androidx.annotation.StringRes
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Image
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.LocalLifecycleOwner
import org.json.JSONObject
import pro.netcloud.trafficwrapper.go.transport.Transport
import kotlinx.coroutines.delay
import java.security.SecureRandom
import java.util.Locale
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

class MainActivity : ComponentActivity() {
    private val mainHandler = Handler(Looper.getMainLooper())
    private val appListExecutor = Executors.newSingleThreadExecutor()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (BuildConfig.DEBUG && intent.hasExtra(TransportService.EXTRA_FAKE_CLOCK_SKEW_SECONDS)) {
            TransportRuntime.debugClockSkewSeconds =
                intent.getLongExtra(TransportService.EXTRA_FAKE_CLOCK_SKEW_SECONDS, 0L)
        }
        requestNotificationPermission()
        if (DeploymentConfig.IS_PUBLIC_PLATFORM) {
            val restored = restorePublicPlatformState(applicationContext)
            PUBLIC_BOOTSTRAP_IMPORTED = restored || publicBootstrapRaw(applicationContext).isNotBlank()
            if (!restored) {
                TransportRuntime.auth = AuthUiState(
                    statusTextRes = if (PUBLIC_BOOTSTRAP_IMPORTED) {
                        R.string.public_bootstrap_imported
                    } else {
                        R.string.public_bootstrap_required
                    },
                )
                if (PUBLIC_BOOTSTRAP_IMPORTED) {
                    startPublicDeviceEnrollment(applicationContext)
                }
            }
            handlePublicBootstrapIntent(intent)
        } else {
            requestStartupAutoconnect(applicationContext)
        }
        refreshAttentionState(applicationContext)
        setContent {
            TrafficWrapperApp()
        }
        handleBatteryHintIntent(intent)
        DistributionChannel.schedule(applicationContext)
        if (DeploymentConfig.IS_PUBLIC_PLATFORM) {
            UpdateCheckWorker.schedule(applicationContext)
        }
        loadInstalledApps()
        if (!DeploymentConfig.IS_PUBLIC_PLATFORM) {
            startDeviceEnrollment(applicationContext)
        }
    }

    override fun onResume() {
        super.onResume()
        refreshAttentionState(applicationContext)
        requestForegroundResync(applicationContext)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        handleBatteryHintIntent(intent)
        handlePublicBootstrapIntent(intent)
    }

    @Suppress("DEPRECATION", "OVERRIDE_DEPRECATION")
    override fun onRequestPermissionsResult(
        requestCode: Int,
        permissions: Array<String>,
        grantResults: IntArray,
    ) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        refreshAttentionState(applicationContext)
    }

    override fun onDestroy() {
        ENROLLMENT_ACTIVE.set(false)
        appListExecutor.shutdownNow()
        super.onDestroy()
    }

    private fun requestNotificationPermission() {
        if (Build.VERSION.SDK_INT >= 33 &&
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 1001)
        }
    }

    private fun loadInstalledApps() {
        appListExecutor.execute {
            val installed = loadSelectableApps(applicationContext)
            val selectedPackage = installed.firstOrNull { it.packageName == TELEGRAM_PACKAGE }?.packageName
                ?: installed.firstOrNull()?.packageName
                ?: TELEGRAM_PACKAGE
            mainHandler.post {
                TransportRuntime.apps = AppSelectionState(
                    loading = false,
                    apps = installed,
                    selectedPackage = selectedPackage,
                )
            }
        }
    }

    private fun handleBatteryHintIntent(intent: Intent?) {
        if (intent?.action == ACTION_OPEN_BATTERY_HINT) {
            openBatteryRestrictionFlow(this)
        }
    }

    private fun handlePublicBootstrapIntent(intent: Intent?) {
        if (!DeploymentConfig.IS_PUBLIC_PLATFORM || intent == null) return
        val raw = intent.getStringExtra(EXTRA_PUBLIC_BOOTSTRAP_PAYLOAD)
            ?: intent.getStringExtra(Intent.EXTRA_TEXT)
            ?: return
        if (raw.isBlank()) return
        try {
            val parsed = PublicPlatformConfigParser.parseBootstrap(raw)
            PENDING_EXTERNAL_BOOTSTRAP = PendingExternalBootstrap(
                raw = raw.trim(),
                orchestratorUrl = parsed.orchestratorUrl,
                configPubkeyPin = parsed.configPubkeyPin,
            )
            PUBLIC_BOOTSTRAP_ERROR = null
        } catch (_: Throwable) {
            PUBLIC_BOOTSTRAP_ERROR = getString(R.string.public_bootstrap_invalid)
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun TrafficWrapperApp() {
    val context = LocalContext.current
    val transport = TransportRuntime.state
    val auth = TransportRuntime.auth
    val apps = TransportRuntime.apps
    val updates = TransportRuntime.updates
    val batteryRestriction = TransportRuntime.batteryRestriction
    val selectedTransport = TransportRuntime.selectedTransport
    val selectedApp = apps.apps.firstOrNull { it.packageName == apps.selectedPackage }
    val stableDurationText = rememberStableDurationText(transport.stableSinceElapsedRealtimeMs)
    val attentionRefreshTick = ATTENTION_REFRESH_TICK

    MaterialTheme {
        Surface(
            modifier = Modifier.fillMaxSize(),
            color = MaterialTheme.colorScheme.background,
        ) {
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .statusBarsPadding()
                    .verticalScroll(rememberScrollState())
                    .padding(20.dp),
                horizontalAlignment = Alignment.Start,
                verticalArrangement = Arrangement.Top,
            ) {
                if (DeploymentConfig.IS_PUBLIC_PLATFORM && !PUBLIC_BOOTSTRAP_IMPORTED) {
                    PublicBootstrapScreen(context = context)
                } else if (SHOW_SETTINGS_SCREEN) {
                    SettingsScreen(
                        context = context,
                        transport = transport,
                        auth = auth,
                        updates = updates,
                        batteryRestriction = batteryRestriction,
                        attentionRefreshTick = attentionRefreshTick,
                        onBack = { SHOW_SETTINGS_SCREEN = false },
                    )
                } else if (DeploymentConfig.IS_PUBLIC_PLATFORM && !auth.authorized) {
                    PublicBootstrapPendingScreen()
                } else {
                    MainScreen(
                        context = context,
                        transport = transport,
                        auth = auth,
                        apps = apps,
                        updates = updates,
                        batteryRestriction = batteryRestriction,
                        selectedTransport = selectedTransport,
                        selectedApp = selectedApp,
                        stableDurationText = stableDurationText,
                        attentionRefreshTick = attentionRefreshTick,
                    )
                }
            }
        }
        DistributionChannel.AvailableSheet(
            context = context,
            updates = updates,
            auth = auth,
            socksListen = activeSocks(transport, auth),
        )
        OemBatteryGuideDialog(context = context)
        PENDING_EXTERNAL_BOOTSTRAP?.let { pending ->
            ExternalBootstrapConfirmDialog(
                pending = pending,
                onDismiss = { PENDING_EXTERNAL_BOOTSTRAP = null },
                onConfirm = {
                    savePublicBootstrap(context, pending.raw)
                    PUBLIC_BOOTSTRAP_IMPORTED = true
                    PUBLIC_BOOTSTRAP_ERROR = null
                    PENDING_EXTERNAL_BOOTSTRAP = null
                    startPublicDeviceEnrollment(context.applicationContext, pending.raw)
                },
            )
        }
    }
}

@Composable
private fun ExternalBootstrapConfirmDialog(
    pending: PendingExternalBootstrap,
    onDismiss: () -> Unit,
    onConfirm: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(text = stringResource(R.string.public_bootstrap_external_title)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(text = stringResource(R.string.public_bootstrap_external_body))
                Text(text = "orchestrator_url: ${pending.orchestratorUrl}")
                Text(text = "config_pubkey_pin: ${pending.configPubkeyPin}")
            }
        },
        confirmButton = {
            TextButton(onClick = onConfirm) {
                Text(text = stringResource(R.string.public_bootstrap_external_confirm))
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text(text = stringResource(R.string.public_bootstrap_scan_cancel))
            }
        },
    )
}

@Composable
private fun PublicBootstrapPendingScreen() {
    Column(
        modifier = Modifier.fillMaxWidth(),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        AppHeader()
        Surface(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(8.dp),
            color = MaterialTheme.colorScheme.surfaceVariant,
        ) {
            Column(
                modifier = Modifier.padding(14.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Text(
                    text = stringResource(R.string.public_bootstrap_imported),
                    style = MaterialTheme.typography.titleLarge,
                    fontWeight = FontWeight.Bold,
                )
                Text(
                    text = stringResource(R.string.public_bootstrap_pending_body),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

@Composable
private fun PublicBootstrapScreen(context: Context) {
    var input by remember { mutableStateOf(publicBootstrapRaw(context)) }
    var showScanner by remember { mutableStateOf(false) }
    fun importBootstrap(raw: String) {
        try {
            PublicPlatformConfigParser.parseBootstrap(raw)
            savePublicBootstrap(context, raw)
            input = raw
            PUBLIC_BOOTSTRAP_IMPORTED = true
            PUBLIC_BOOTSTRAP_ERROR = null
            startPublicDeviceEnrollment(context.applicationContext, raw)
        } catch (_: Throwable) {
            PUBLIC_BOOTSTRAP_ERROR = context.getString(R.string.public_bootstrap_invalid)
        }
    }
    val documentLauncher = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri == null) return@rememberLauncherForActivityResult
        runCatching {
            val raw = readBootstrapDocument(context, uri)
            importBootstrap(raw)
        }.onFailure {
            PUBLIC_BOOTSTRAP_ERROR = context.getString(R.string.public_bootstrap_invalid)
        }
    }
    val cameraPermissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { granted ->
        if (granted) {
            PUBLIC_BOOTSTRAP_ERROR = null
            showScanner = true
        } else {
            PUBLIC_BOOTSTRAP_ERROR = context.getString(R.string.public_bootstrap_camera_denied)
        }
    }
    fun openScanner() {
        if (ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED) {
            PUBLIC_BOOTSTRAP_ERROR = null
            showScanner = true
        } else {
            cameraPermissionLauncher.launch(Manifest.permission.CAMERA)
        }
    }
    Column(
        modifier = Modifier.fillMaxWidth(),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        AppHeader()
        if (showScanner) {
            BootstrapQrScanner(
                onScanned = { raw ->
                    showScanner = false
                    importBootstrap(raw)
                },
                onCancel = { showScanner = false },
                onError = {
                    showScanner = false
                    PUBLIC_BOOTSTRAP_ERROR = context.getString(R.string.public_bootstrap_camera_error)
                },
            )
            return@Column
        }
        Surface(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(8.dp),
            color = MaterialTheme.colorScheme.surfaceVariant,
        ) {
            Column(
                modifier = Modifier.padding(14.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                Text(
                    text = stringResource(R.string.public_bootstrap_title),
                    style = MaterialTheme.typography.titleLarge,
                    fontWeight = FontWeight.Bold,
                )
                Text(
                    text = stringResource(R.string.public_bootstrap_body),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                OutlinedTextField(
                    value = input,
                    onValueChange = {
                        input = it
                        PUBLIC_BOOTSTRAP_ERROR = null
                    },
                    modifier = Modifier.fillMaxWidth(),
                    minLines = 5,
                    label = { Text(text = stringResource(R.string.public_bootstrap_input_label)) },
                )
                PUBLIC_BOOTSTRAP_ERROR?.let { error ->
                    Text(
                        text = error,
                        color = MaterialTheme.colorScheme.error,
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
                Button(
                    onClick = {
                        importBootstrap(input)
                    },
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text(text = stringResource(R.string.public_bootstrap_import))
                }
                OutlinedButton(
                    onClick = { openScanner() },
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text(text = stringResource(R.string.public_bootstrap_scan_qr))
                }
                Text(
                    text = stringResource(R.string.public_bootstrap_camera_rationale),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                OutlinedButton(
                    onClick = {
                        documentLauncher.launch(arrayOf("application/json", "text/plain", "*/*"))
                    },
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text(text = stringResource(R.string.public_bootstrap_import_file))
                }
            }
        }
    }
}

@Composable
private fun BootstrapQrScanner(
    onScanned: (String) -> Unit,
    onCancel: () -> Unit,
    onError: () -> Unit,
) {
    val context = LocalContext.current
    val lifecycleOwner = LocalLifecycleOwner.current
    val cameraExecutor = remember { Executors.newSingleThreadExecutor() }
    val providerRef = remember { AtomicReference<ProcessCameraProvider?>() }

    androidx.compose.runtime.DisposableEffect(Unit) {
        onDispose {
            providerRef.get()?.unbindAll()
            cameraExecutor.shutdown()
        }
    }

    Surface(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(8.dp),
        color = MaterialTheme.colorScheme.surfaceVariant,
    ) {
        Column(
            modifier = Modifier.padding(14.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text(
                text = stringResource(R.string.public_bootstrap_scan_title),
                style = MaterialTheme.typography.titleLarge,
                fontWeight = FontWeight.Bold,
            )
            Text(
                text = stringResource(R.string.public_bootstrap_scan_hint),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            AndroidView(
                modifier = Modifier
                    .fillMaxWidth()
                    .height(360.dp)
                    .clip(RoundedCornerShape(8.dp)),
                factory = { viewContext ->
                    PreviewView(viewContext).apply {
                        implementationMode = PreviewView.ImplementationMode.COMPATIBLE
                        val providerFuture = ProcessCameraProvider.getInstance(viewContext)
                        providerFuture.addListener(
                            {
                                runCatching {
                                    val provider = providerFuture.get()
                                    providerRef.set(provider)
                                    val preview = Preview.Builder().build().also { preview ->
                                        preview.setSurfaceProvider(surfaceProvider)
                                    }
                                    val analysis = ImageAnalysis.Builder()
                                        .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                                        .build()
                                        .also { imageAnalysis ->
                                            imageAnalysis.setAnalyzer(
                                                cameraExecutor,
                                                BootstrapQrAnalyzer { raw ->
                                                    Handler(Looper.getMainLooper()).post {
                                                        provider.unbindAll()
                                                        onScanned(raw)
                                                    }
                                                },
                                            )
                                        }
                                    provider.unbindAll()
                                    provider.bindToLifecycle(
                                        lifecycleOwner,
                                        CameraSelector.DEFAULT_BACK_CAMERA,
                                        preview,
                                        analysis,
                                    )
                                }.onFailure {
                                    Handler(Looper.getMainLooper()).post { onError() }
                                }
                            },
                            ContextCompat.getMainExecutor(viewContext),
                        )
                    }
                },
            )
            OutlinedButton(
                onClick = {
                    providerRef.get()?.unbindAll()
                    onCancel()
                },
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(text = stringResource(R.string.public_bootstrap_scan_cancel))
            }
        }
    }
}

@Composable
private fun MainScreen(
    context: Context,
    transport: TransportUiState,
    auth: AuthUiState,
    apps: AppSelectionState,
    updates: DistributionUiState,
    batteryRestriction: BatteryRestrictionState,
    selectedTransport: TransportChoice,
    selectedApp: InstalledAppInfo?,
    stableDurationText: String?,
    attentionRefreshTick: Long,
) {
    val socksListen = activeSocks(transport, auth).ifBlank { DEFAULT_ROUTER_SOCKS_LISTEN }
    val transportRunning = isTransportRunningForToggle(transport)
    val transportConnected = isTransportConnectedForToggle(transport)
    val connectInProgress = CONNECT_IN_PROGRESS
    val connecting = (connectInProgress || transportRunning) &&
        !transportConnected &&
        !isTransportTerminalForConnect(transport)
    LaunchedEffect(connectInProgress, transportConnected, transport.stateTextRes) {
        if (!connectInProgress) return@LaunchedEffect
        if (transportConnected || isTransportTerminalForConnect(transport)) {
            CONNECT_IN_PROGRESS = false
            return@LaunchedEffect
        }
        delay(CONNECT_TIMEOUT_MS)
        val current = TransportRuntime.state
        if (CONNECT_IN_PROGRESS && !isTransportConnectedForToggle(current)) {
            CONNECT_IN_PROGRESS = false
        }
    }

    AppHeader()
    Spacer(modifier = Modifier.height(18.dp))
    ConnectionStatusCard(
        transport = transport,
        connected = transportConnected,
        connecting = connecting,
        stableDurationText = stableDurationText,
    )
    PrimaryTransportButton(
        context = context,
        auth = auth,
        transportRunning = transportRunning,
        connecting = connecting,
    )
    AttentionBanners(
        context = context,
        auth = auth,
        updates = updates,
        batteryRestriction = batteryRestriction,
        socksListen = socksListen,
        attentionRefreshTick = attentionRefreshTick,
    )
    ConnectionModeSelector(
        context = context,
        auth = auth,
        selectedTransport = selectedTransport,
        connecting = connecting,
    )
    ConsumerAppsPanel(
        context = context,
        apps = apps,
        selectedApp = selectedApp,
        socksListen = socksListen,
    )
}

@Composable
private fun AppHeader() {
    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Image(
            painter = painterResource(R.drawable.ic_launcher_foreground),
            contentDescription = null,
            modifier = Modifier
                .size(32.dp)
                .clip(CircleShape),
        )
        Text(
            text = stringResource(R.string.app_name),
            modifier = Modifier
                .weight(1f)
                .padding(start = 10.dp),
            style = MaterialTheme.typography.headlineSmall,
            fontWeight = FontWeight.Bold,
        )
        IconButton(onClick = { SHOW_SETTINGS_SCREEN = true }) {
            Text(text = "⚙", style = MaterialTheme.typography.titleLarge)
        }
    }
}

@Composable
private fun ConnectionStatusCard(
    transport: TransportUiState,
    connected: Boolean,
    connecting: Boolean,
    stableDurationText: String?,
) {
    val backgroundColor: Color
    val textColor: Color
    val titleRes: Int
    val detail: String
    when {
        connected -> {
            backgroundColor = Color(0xFFE6F4EA)
            textColor = Color(0xFF14532D)
            titleRes = R.string.main_status_connected
            detail = "${displayTransportLabel(transport.activeTransport)} · ${stringResource(R.string.main_status_connected_hint)}"
        }
        connecting -> {
            backgroundColor = Color(0xFFFFF4D6)
            textColor = Color(0xFF6F4B00)
            titleRes = R.string.main_status_connecting
            detail = stringResource(transport.stateTextRes)
        }
        else -> {
            backgroundColor = Color(0xFFFFEBEE)
            textColor = Color(0xFF8B1A1A)
            titleRes = R.string.main_status_disconnected
            detail = stringResource(R.string.main_status_disconnected_hint)
        }
    }
    Surface(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(8.dp),
        color = backgroundColor,
    ) {
        Column(modifier = Modifier.padding(18.dp)) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                if (connecting) {
                    CircularProgressIndicator(
                        modifier = Modifier.size(22.dp),
                        strokeWidth = 2.dp,
                        color = textColor,
                    )
                }
                Text(
                    text = stringResource(titleRes),
                    color = textColor,
                    style = MaterialTheme.typography.headlineSmall,
                    fontWeight = FontWeight.Bold,
                )
            }
            Text(
                text = detail,
                modifier = Modifier.padding(top = 6.dp),
                color = textColor,
                style = MaterialTheme.typography.bodyLarge,
            )
            if (connected && stableDurationText != null) {
                Text(
                    text = stableDurationText,
                    modifier = Modifier.padding(top = 10.dp),
                    color = textColor,
                    style = MaterialTheme.typography.headlineMedium,
                    fontWeight = FontWeight.SemiBold,
                )
            }
        }
    }
}

@Composable
private fun PrimaryTransportButton(
    context: Context,
    auth: AuthUiState,
    transportRunning: Boolean,
    connecting: Boolean,
) {
    Button(
        enabled = !connecting && (auth.authorized || transportRunning),
        onClick = {
            if (transportRunning) {
                stopAllTransports(context.applicationContext)
            } else {
                connectSelectedTransport(context.applicationContext)
            }
        },
        modifier = Modifier
            .fillMaxWidth()
            .padding(top = 14.dp)
            .height(52.dp),
    ) {
        if (connecting) {
            CircularProgressIndicator(
                modifier = Modifier
                    .size(18.dp)
                    .padding(end = 6.dp),
                strokeWidth = 2.dp,
                color = MaterialTheme.colorScheme.onPrimary,
            )
        }
        Text(
            text = stringResource(
                when {
                    connecting -> R.string.connecting_button
                    transportRunning -> R.string.disconnect_button
                    else -> R.string.connect_button
                },
            ),
            style = MaterialTheme.typography.titleMedium,
        )
    }
}

@Composable
private fun AttentionBanners(
    context: Context,
    auth: AuthUiState,
    updates: DistributionUiState,
    batteryRestriction: BatteryRestrictionState,
    socksListen: String,
    attentionRefreshTick: Long,
) {
    val notificationsOff = notificationsDisabled(context, attentionRefreshTick)
    val updateAvailable = updates.availableVersionCode > BuildConfig.VERSION_CODE.toLong()
    val updateBusy = updates.downloadInProgress || updates.installInProgress
    val updateError = updates.errorTextRes != null || updates.installErrorTextRes != null
    val showUpdateBanner = updateAvailable || updateBusy || (updateError && updates.availableVersionCode > 0)
    val installPermissionProblem = updates.installErrorTextRes == R.string.update_install_permission_required ||
        installPermissionNeeded(context)
    if (!showUpdateBanner && !batteryRestriction.restricted && !notificationsOff && !installPermissionProblem) {
        return
    }
    Column(
        modifier = Modifier.padding(top = 14.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        if (showUpdateBanner) {
            UpdateAttentionBanner(
                context = context,
                auth = auth,
                socksListen = socksListen,
                updates = updates,
            )
        }
        if (batteryRestriction.restricted) {
            AttentionBanner(
                title = stringResource(R.string.attention_battery),
                action = stringResource(R.string.attention_fix),
                onClick = { openBatteryRestrictionFlow(context) },
            )
        }
        if (notificationsOff) {
            AttentionBanner(
                title = stringResource(R.string.attention_notifications),
                action = stringResource(R.string.attention_enable_notifications),
                onClick = { requestPostNotificationsPermission(context) },
            )
        }
        if (installPermissionProblem) {
            AttentionBanner(
                title = stringResource(R.string.attention_install_permission),
                action = stringResource(R.string.attention_allow_install),
                onClick = { DistributionChannel.openInstallSettings(context.applicationContext) },
            )
        }
    }
}

@Composable
private fun UpdateAttentionBanner(
    context: Context,
    auth: AuthUiState,
    socksListen: String,
    updates: DistributionUiState,
) {
    val installPermissionError = updates.installErrorTextRes == R.string.update_install_permission_required
    val errorTextRes = updates.installErrorTextRes ?: updates.errorTextRes
    val title = when {
        updates.downloadInProgress -> stringResource(R.string.attention_update_downloading_title)
        updates.installInProgress -> stringResource(R.string.attention_update_installing_title)
        errorTextRes != null -> stringResource(R.string.attention_update_error_title)
        else -> stringResource(R.string.attention_update, updates.availableVersionName)
    }
    val detail = when {
        updates.downloadInProgress && updates.totalBytes > 0 -> {
            val percent = ((updates.downloadedBytes * 100) / updates.totalBytes).coerceIn(0, 100)
            stringResource(
                R.string.update_progress_downloading_percent,
                formatUpdateMegabytes(updates.downloadedBytes),
                formatUpdateMegabytes(updates.totalBytes),
                percent,
            )
        }
        updates.downloadInProgress -> stringResource(R.string.update_progress_downloading_unknown)
        updates.installInProgress -> updates.installStatusTextRes?.let { stringResource(it) }
            ?: stringResource(R.string.update_progress_installing)
        errorTextRes != null -> stringResource(errorTextRes)
        else -> ""
    }
    val busy = updates.downloadInProgress || updates.installInProgress
    val actionText = when {
        updates.downloadInProgress -> stringResource(R.string.attention_update_downloading_action)
        updates.installInProgress -> stringResource(R.string.attention_update_installing_action)
        installPermissionError -> stringResource(R.string.attention_allow_install)
        errorTextRes != null -> stringResource(R.string.attention_update_retry)
        else -> stringResource(R.string.attention_update_install)
    }
    val actionEnabled = !busy
    val onClick = {
        if (installPermissionError) {
            DistributionChannel.openInstallSettings(context.applicationContext)
        } else {
            DistributionChannel.requestInstall(
                context = context.applicationContext,
                auth = auth,
                socksListen = socksListen,
                updates = updates,
            )
        }
    }

    Surface(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(8.dp),
        color = Color(0xFFFFF4D6),
    ) {
        Column(
            modifier = Modifier.padding(12.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                Text(
                    text = title,
                    modifier = Modifier.weight(1f),
                    color = Color(0xFF6F4B00),
                    style = MaterialTheme.typography.bodyMedium,
                    fontWeight = FontWeight.SemiBold,
                )
                if (busy) {
                    CircularProgressIndicator(
                        modifier = Modifier.size(18.dp),
                        strokeWidth = 2.dp,
                        color = Color(0xFF6F4B00),
                    )
                }
            }
            if (detail.isNotBlank()) {
                Text(
                    text = detail,
                    color = Color(0xFF6F4B00),
                    style = MaterialTheme.typography.bodySmall,
                )
            }
            if (updates.downloadInProgress && updates.totalBytes > 0) {
                LinearProgressIndicator(
                    progress = {
                        (updates.downloadedBytes.toFloat() / updates.totalBytes.toFloat()).coerceIn(0f, 1f)
                    },
                    modifier = Modifier.fillMaxWidth(),
                )
            } else if (busy) {
                LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
            }
            OutlinedButton(
                enabled = actionEnabled,
                onClick = onClick,
            ) {
                Text(text = actionText)
            }
        }
    }
}

@Composable
private fun AttentionBanner(
    title: String,
    action: String,
    onClick: () -> Unit,
) {
    Surface(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(8.dp),
        color = Color(0xFFFFF4D6),
    ) {
        Row(
            modifier = Modifier.padding(12.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Text(
                text = title,
                modifier = Modifier.weight(1f),
                color = Color(0xFF6F4B00),
                style = MaterialTheme.typography.bodyMedium,
                fontWeight = FontWeight.SemiBold,
            )
            OutlinedButton(onClick = onClick) {
                Text(text = action)
            }
        }
    }
}

private fun formatUpdateMegabytes(bytes: Long): String =
    String.format(Locale.US, "%.1f МБ", bytes.toDouble() / (1024.0 * 1024.0))

@Composable
private fun ConnectionModeSelector(
    context: Context,
    auth: AuthUiState,
    selectedTransport: TransportChoice,
    connecting: Boolean,
) {
    fun enabled(choice: TransportChoice): Boolean =
        !connecting && transportChoiceConfigured(choice, auth)

    @Composable
    fun unavailableDetail(choice: TransportChoice): String? =
        if (!transportChoiceConfigured(choice, auth)) {
            stringResource(R.string.transport_route_unavailable)
        } else {
            null
        }

    Text(
        text = stringResource(R.string.transport_mode_title),
        modifier = Modifier.padding(top = 18.dp),
        style = MaterialTheme.typography.titleLarge,
        fontWeight = FontWeight.SemiBold,
    )
    TransportModeCard(
        context = context,
        choice = TransportChoice.AUTO,
        selectedTransport = selectedTransport,
        auth = auth,
        enabled = enabled(TransportChoice.AUTO),
        modifier = Modifier
            .fillMaxWidth()
            .padding(top = 10.dp),
        detail = unavailableDetail(TransportChoice.AUTO) ?: stringResource(R.string.mode_recommended),
    )
    Column(
        modifier = Modifier.padding(top = 8.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            TransportModeCard(
                context = context,
                choice = TransportChoice.AWG_RU,
                selectedTransport = selectedTransport,
                auth = auth,
                enabled = enabled(TransportChoice.AWG_RU),
                modifier = Modifier.weight(1f),
                detail = unavailableDetail(TransportChoice.AWG_RU),
            )
            TransportModeCard(
                context = context,
                choice = TransportChoice.REALITY2,
                selectedTransport = selectedTransport,
                auth = auth,
                enabled = enabled(TransportChoice.REALITY2),
                modifier = Modifier.weight(1f),
                detail = unavailableDetail(TransportChoice.REALITY2),
            )
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            TransportModeCard(
                context = context,
                choice = TransportChoice.AWG,
                selectedTransport = selectedTransport,
                auth = auth,
                enabled = enabled(TransportChoice.AWG),
                modifier = Modifier.weight(1f),
                detail = unavailableDetail(TransportChoice.AWG),
            )
            TransportModeCard(
                context = context,
                choice = TransportChoice.REALITY,
                selectedTransport = selectedTransport,
                auth = auth,
                enabled = enabled(TransportChoice.REALITY),
                modifier = Modifier.weight(1f),
                detail = unavailableDetail(TransportChoice.REALITY),
            )
        }
    }
    Text(
        text = stringResource(R.string.transport_mode_auto_detail),
        modifier = Modifier.padding(top = 8.dp),
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
}

@Composable
private fun TransportModeCard(
    context: Context,
    choice: TransportChoice,
    selectedTransport: TransportChoice,
    auth: AuthUiState,
    enabled: Boolean,
    modifier: Modifier = Modifier,
    detail: String? = null,
) {
    val selected = selectedTransport == choice
    Surface(
        modifier = modifier
            .height(if (detail == null) 64.dp else 74.dp)
            .clickable(enabled = enabled) {
                TransportRuntime.selectedTransport = choice
                if (auth.authorized) {
                    connectSelectedTransport(context.applicationContext)
                }
            },
        shape = RoundedCornerShape(8.dp),
        color = if (selected) MaterialTheme.colorScheme.primaryContainer else MaterialTheme.colorScheme.surfaceVariant,
        border = if (selected) BorderStroke(2.dp, MaterialTheme.colorScheme.primary) else null,
    ) {
        Row(
            modifier = Modifier.padding(12.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = stringResource(transportChoiceLabelRes(choice)),
                    fontWeight = FontWeight.SemiBold,
                    color = if (enabled) MaterialTheme.colorScheme.onSurface else MaterialTheme.colorScheme.onSurfaceVariant,
                )
                detail?.let {
                    Text(
                        text = it,
                        modifier = Modifier.padding(top = 2.dp),
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
            }
            if (selected) {
                Text(
                    text = "✓",
                    color = MaterialTheme.colorScheme.primary,
                    fontWeight = FontWeight.Bold,
                )
            }
        }
    }
}

@Composable
private fun ConsumerAppsPanel(
    context: Context,
    apps: AppSelectionState,
    selectedApp: InstalledAppInfo?,
    socksListen: String,
) {
    val telegramLabel = apps.apps.firstOrNull { it.packageName == TELEGRAM_PACKAGE }?.label ?: "Telegram"
    val effectiveSocks = socksListen.ifBlank { DEFAULT_ROUTER_SOCKS_LISTEN }
    Text(
        text = stringResource(R.string.apps_title),
        modifier = Modifier.padding(top = 18.dp),
        style = MaterialTheme.typography.titleLarge,
        fontWeight = FontWeight.SemiBold,
    )
    Surface(
        modifier = Modifier
            .fillMaxWidth()
            .padding(top = 10.dp),
        shape = RoundedCornerShape(8.dp),
        color = MaterialTheme.colorScheme.surfaceVariant,
    ) {
        Column(modifier = Modifier.padding(14.dp)) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                Text(
                    text = telegramLabel,
                    modifier = Modifier.weight(1f),
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold,
                )
                Button(onClick = { openTelegramProxy(context.applicationContext, effectiveSocks) }) {
                    Text(text = stringResource(R.string.telegram_proxy_button))
                }
            }
            Text(
                text = stringResource(R.string.apps_other_title),
                modifier = Modifier.padding(top = 16.dp),
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.SemiBold,
            )
            Row(
                modifier = Modifier.padding(top = 8.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                Text(
                    text = "SOCKS5 $effectiveSocks",
                    modifier = Modifier.weight(1f),
                    style = MaterialTheme.typography.bodyLarge,
                    fontWeight = FontWeight.SemiBold,
                )
                OutlinedButton(onClick = { copySocksAddress(context, effectiveSocks) }) {
                    Text(text = stringResource(R.string.copy_button))
                }
            }
            Text(
                text = stringResource(R.string.apps_socks_hint),
                modifier = Modifier.padding(top = 6.dp),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            if (apps.loading) {
                Text(
                    text = stringResource(R.string.app_choice_loading),
                    modifier = Modifier.padding(top = 8.dp),
                    style = MaterialTheme.typography.bodySmall,
                )
            } else if (selectedApp != null && selectedApp.packageName != TELEGRAM_PACKAGE) {
                Text(
                    text = stringResource(R.string.app_choice_selected, selectedApp.label),
                    modifier = Modifier.padding(top = 8.dp),
                    style = MaterialTheme.typography.bodySmall,
                )
            }
        }
    }
}

@Composable
private fun SettingsScreen(
    context: Context,
    transport: TransportUiState,
    auth: AuthUiState,
    updates: DistributionUiState,
    batteryRestriction: BatteryRestrictionState,
    attentionRefreshTick: Long,
    onBack: () -> Unit,
) {
    val socksListen = activeSocks(transport, auth).ifBlank { DEFAULT_ROUTER_SOCKS_LISTEN }
    var permissionCheckRequested by remember { mutableStateOf(0) }
    var permissionChecking by remember { mutableStateOf(false) }
    var permissionResults by remember { mutableStateOf<List<PermissionCheckResult>?>(null) }

    LaunchedEffect(permissionCheckRequested) {
        if (permissionCheckRequested == 0) return@LaunchedEffect
        permissionChecking = true
        refreshAttentionState(context.applicationContext)
        delay(150)
        permissionResults = buildPermissionCheckResults(context.applicationContext)
        permissionChecking = false
    }

    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        TextButton(onClick = onBack) {
            Text(text = "‹")
        }
        Text(
            text = stringResource(R.string.settings_title),
            modifier = Modifier.weight(1f),
            style = MaterialTheme.typography.headlineSmall,
            fontWeight = FontWeight.Bold,
        )
    }

    SettingsSection(title = stringResource(R.string.settings_about_title)) {
        DetailRow(stringResource(R.string.settings_version), "${BuildConfig.VERSION_NAME} (${BuildConfig.VERSION_CODE})")
        DetailRow(stringResource(R.string.settings_status), stringResource(auth.statusTextRes))
        DetailRow(stringResource(R.string.settings_alias), auth.alias.ifBlank { stringResource(R.string.value_empty) })
        DetailRow(stringResource(R.string.settings_model), auth.model.ifBlank { stringResource(R.string.value_empty) })
        DetailRow(stringResource(R.string.settings_device_id), auth.deviceID.ifBlank { stringResource(R.string.value_empty) })
        DetailRow(
            stringResource(R.string.settings_identity),
            auth.deviceIdentityPublicSuffix.ifBlank { stringResource(R.string.value_empty) },
        )
        DetailRow(stringResource(R.string.settings_keystore), stringResource(auth.keystoreTextRes))
        DetailRow(stringResource(R.string.settings_internal_ip), auth.internalIP.ifBlank { stringResource(R.string.value_empty) })
    }

    SettingsSection(title = stringResource(R.string.settings_update_title)) {
        Button(
            enabled = !updates.inProgress && auth.authorized,
            onClick = {
                DistributionChannel.requestUpdateCheck(
                    context = context.applicationContext,
                    auth = auth,
                    socksListen = socksListen,
                )
            },
            modifier = Modifier.fillMaxWidth(),
        ) {
            if (updates.inProgress && !updates.downloadInProgress) {
                CircularProgressIndicator(
                    modifier = Modifier
                        .size(18.dp)
                        .padding(end = 6.dp),
                    strokeWidth = 2.dp,
                    color = MaterialTheme.colorScheme.onPrimary,
                )
            }
            Text(text = stringResource(R.string.update_check_button))
        }
        Text(
            text = stringResource(updateSettingsStatusTextRes(updates)),
            modifier = Modifier.padding(top = 8.dp),
        )
        if (updates.availableVersionCode > BuildConfig.VERSION_CODE.toLong()) {
            Row(
                modifier = Modifier.padding(top = 8.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                Text(
                    text = stringResource(
                        R.string.update_available_version,
                        updates.availableVersionName,
                        updates.availableVersionCode,
                    ),
                    modifier = Modifier.weight(1f),
                )
                Button(
                    enabled = !updates.installInProgress,
                    onClick = {
                        DistributionChannel.requestInstall(
                            context = context.applicationContext,
                            auth = auth,
                            socksListen = socksListen,
                            updates = updates,
                        )
                    },
                ) {
                    Text(text = stringResource(R.string.update_install_button))
                }
            }
        }
        updates.errorTextRes?.takeUnless { suppressUpdateErrorInSettings(updates, it) }?.let { errorRes ->
            Text(
                text = stringResource(errorRes),
                modifier = Modifier.padding(top = 8.dp),
                color = MaterialTheme.colorScheme.error,
            )
        }
    }

    SettingsSection(title = stringResource(R.string.settings_permissions_title)) {
        Button(
            enabled = !permissionChecking,
            onClick = { permissionCheckRequested += 1 },
            modifier = Modifier.fillMaxWidth(),
        ) {
            if (permissionChecking) {
                CircularProgressIndicator(
                    modifier = Modifier
                        .size(18.dp)
                        .padding(end = 6.dp),
                    strokeWidth = 2.dp,
                    color = MaterialTheme.colorScheme.onPrimary,
                )
            }
            Text(text = stringResource(R.string.permissions_check_button))
        }
        permissionResults?.forEach { result ->
            PermissionResultRow(context = context, result = result)
        } ?: Text(
            text = permissionSummary(context, batteryRestriction, attentionRefreshTick),
            modifier = Modifier.padding(top = 8.dp),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }

    SettingsSection(title = stringResource(R.string.settings_battery_title)) {
        Text(text = stringResource(R.string.battery_guide_title))
        Text(
            text = oemBatteryGuide().body,
            modifier = Modifier.padding(top = 6.dp),
            style = MaterialTheme.typography.bodySmall,
        )
        Row(
            modifier = Modifier.padding(top = 10.dp),
            horizontalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            OutlinedButton(onClick = { openBatteryRestrictionFlow(context) }) {
                Text(text = stringResource(R.string.attention_fix))
            }
            OutlinedButton(onClick = { openOemBatterySettings(context) }) {
                Text(text = stringResource(R.string.battery_guide_open))
            }
        }
    }

    SettingsSection(title = stringResource(R.string.telemetry_title)) {
        TelemetryPanel(context)
    }
}

@Composable
private fun SettingsSection(title: String, content: @Composable () -> Unit) {
    Surface(
        modifier = Modifier
            .fillMaxWidth()
            .padding(top = 14.dp),
        shape = RoundedCornerShape(8.dp),
        color = MaterialTheme.colorScheme.surfaceVariant,
    ) {
        Column(modifier = Modifier.padding(14.dp)) {
            Text(
                text = title,
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.SemiBold,
            )
            Spacer(modifier = Modifier.height(10.dp))
            content()
        }
    }
}

@Composable
private fun DetailRow(label: String, value: String) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(top = 4.dp),
        horizontalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        Text(
            text = label,
            modifier = Modifier.weight(0.42f),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Text(
            text = value,
            modifier = Modifier.weight(0.58f),
            style = MaterialTheme.typography.bodySmall,
        )
    }
}

@Composable
private fun PermissionResultRow(context: Context, result: PermissionCheckResult) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(top = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = stringResource(result.titleRes),
                style = MaterialTheme.typography.bodyMedium,
                fontWeight = FontWeight.SemiBold,
            )
            Text(
                text = stringResource(if (result.ok) R.string.permission_status_ok else R.string.permission_status_needed),
                style = MaterialTheme.typography.bodySmall,
                color = if (result.ok) Color(0xFF14532D) else MaterialTheme.colorScheme.error,
            )
        }
        if (!result.ok && result.fix != null) {
            OutlinedButton(onClick = { result.fix.invoke(context) }) {
                Text(text = stringResource(R.string.attention_fix))
            }
        }
    }
}

@Composable
private fun TelemetryPanel(context: Context) {
    var telemetryOn by remember {
        mutableStateOf(TransportLifecycleStore.telemetryEnabled(context.applicationContext))
    }
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(top = 14.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = stringResource(R.string.telemetry_title),
                style = MaterialTheme.typography.titleMedium,
            )
            Text(
                text = stringResource(R.string.telemetry_disclaimer),
                modifier = Modifier.padding(top = 4.dp),
                style = MaterialTheme.typography.bodySmall,
            )
        }
        Switch(
            checked = telemetryOn,
            onCheckedChange = { enabled ->
                TransportLifecycleStore.setTelemetryEnabled(context.applicationContext, enabled)
                telemetryOn = TransportLifecycleStore.telemetryEnabled(context.applicationContext)
                if (telemetryOn) {
                    Telemetry.event(context.applicationContext, "telemetry_opt_in", "action" to "enabled")
                    Telemetry.flush(context.applicationContext)
                }
            },
        )
    }
}

@Composable
private fun BackgroundRestrictionBanner(context: Context, restriction: BatteryRestrictionState) {
    if (!restriction.restricted) return
    val oemOnly = restriction.oemHintNeeded &&
        !restriction.batteryOptimizationRestricted &&
        !restriction.backgroundRestricted
    LaunchedEffect(
        restriction.restricted,
        restriction.batteryOptimizationRestricted,
        restriction.backgroundRestricted,
        restriction.oemHintNeeded,
        restriction.oemMakerKey,
    ) {
        sendBatteryHintTelemetry(
            context.applicationContext,
            BATTERY_HINT_ACTION_SHOWN,
            restricted = true,
            oem = restriction.oemMakerKey,
        )
    }
    Surface(
        modifier = Modifier
            .fillMaxWidth()
            .padding(top = 14.dp)
            .clickable { openBatteryRestrictionFlow(context) },
        shape = RoundedCornerShape(8.dp),
        color = MaterialTheme.colorScheme.errorContainer,
    ) {
        Text(
            text = if (oemOnly) {
                stringResource(R.string.battery_oem_banner_text, oemDisplayName(restriction.oemMakerKey))
            } else {
                stringResource(R.string.battery_banner_text)
            },
            modifier = Modifier.padding(14.dp),
            color = MaterialTheme.colorScheme.onErrorContainer,
            fontWeight = FontWeight.SemiBold,
            style = MaterialTheme.typography.bodyMedium,
        )
    }
}

@Composable
private fun OemBatteryGuideDialog(context: Context) {
    if (!TransportRuntime.showBatteryGuide) return
    val guide = remember { oemBatteryGuide() }
    val restriction = TransportRuntime.batteryRestriction
    AlertDialog(
        onDismissRequest = {
            val state = currentBatteryRestrictionState(context.applicationContext)
            sendBatteryHintTelemetry(
                context.applicationContext,
                BATTERY_HINT_ACTION_DISMISSED,
                restricted = state.restricted,
                oem = state.oemMakerKey,
            )
            TransportRuntime.showBatteryGuide = false
        },
        title = { Text(text = stringResource(R.string.battery_guide_title)) },
        text = { Text(text = guide.body) },
        confirmButton = {
            TextButton(
                onClick = {
                    TransportRuntime.showBatteryGuide = false
                    openOemBatterySettings(context)
                },
            ) {
                Text(text = stringResource(R.string.battery_guide_open))
            }
        },
        dismissButton = {
            TextButton(
                onClick = {
                    if (restriction.oemHintNeeded) {
                        acknowledgeOemBatteryHint(context)
                    } else {
                        val state = currentBatteryRestrictionState(context.applicationContext)
                        sendBatteryHintTelemetry(
                            context.applicationContext,
                            BATTERY_HINT_ACTION_DISMISSED,
                            restricted = state.restricted,
                            oem = state.oemMakerKey,
                        )
                        TransportRuntime.showBatteryGuide = false
                    }
                },
            ) {
                Text(
                    text = stringResource(
                        if (restriction.oemHintNeeded) {
                            R.string.battery_guide_oem_ack
                        } else {
                            R.string.battery_guide_done
                        },
                    ),
                )
            }
        },
    )
}

@Composable
private fun Header() {
    Text(
        text = stringResource(R.string.app_name),
        style = MaterialTheme.typography.headlineMedium,
    )
    Text(
        text = stringResource(R.string.version_label, BuildConfig.VERSION_NAME),
        modifier = Modifier.padding(top = 6.dp),
        style = MaterialTheme.typography.bodyLarge,
    )
}

@Composable
private fun EnrollmentPanel(auth: AuthUiState) {
    Text(
        text = stringResource(R.string.enrollment_title),
        modifier = Modifier.padding(top = 18.dp),
        style = MaterialTheme.typography.titleLarge,
    )
    Row(
        modifier = Modifier.padding(top = 10.dp),
        horizontalArrangement = Arrangement.spacedBy(12.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(text = stringResource(auth.statusTextRes))
    }
    auth.errorTextRes?.let { errorRes ->
        Text(
            text = stringResource(errorRes),
            modifier = Modifier.padding(top = 8.dp),
            color = MaterialTheme.colorScheme.error,
        )
    }
    Text(
        text = stringResource(R.string.keystore_status, stringResource(auth.keystoreTextRes)),
        modifier = Modifier.padding(top = 8.dp),
        style = MaterialTheme.typography.bodyMedium,
    )
    if (auth.deviceID.isNotBlank()) {
        Text(
            text = stringResource(R.string.enrollment_device_id, auth.deviceID),
            modifier = Modifier.padding(top = 4.dp),
            style = MaterialTheme.typography.bodyMedium,
        )
    }
    if (auth.alias.isNotBlank()) {
        Text(
            text = stringResource(R.string.enrollment_alias, auth.alias),
            modifier = Modifier.padding(top = 4.dp),
            style = MaterialTheme.typography.bodyMedium,
        )
    }
    if (auth.model.isNotBlank()) {
        Text(
            text = stringResource(R.string.enrollment_model, auth.model),
            modifier = Modifier.padding(top = 4.dp),
            style = MaterialTheme.typography.bodyMedium,
        )
    }
    if (auth.deviceIdentityPublicSuffix.isNotBlank()) {
        Text(
            text = stringResource(R.string.identity_suffix, auth.deviceIdentityPublicSuffix),
            modifier = Modifier.padding(top = 4.dp),
            style = MaterialTheme.typography.bodyMedium,
        )
    }
    if (auth.message.isNotBlank()) {
        Text(
            text = auth.message,
            modifier = Modifier.padding(top = 4.dp),
            style = MaterialTheme.typography.bodyMedium,
        )
    }
    if (auth.internalIP.isNotBlank()) {
        Text(
            text = stringResource(R.string.provisioned_internal_ip, auth.internalIP),
            modifier = Modifier.padding(top = 4.dp),
            style = MaterialTheme.typography.bodyMedium,
        )
    }
}

@Composable
private fun AppSelectionPanel(apps: AppSelectionState, selectedApp: InstalledAppInfo?, socksListen: String) {
    val context = LocalContext.current
    Text(
        text = stringResource(R.string.app_choice_title),
        style = MaterialTheme.typography.titleLarge,
    )
    if (apps.loading) {
        Text(
            text = stringResource(R.string.app_choice_loading),
            modifier = Modifier.padding(top = 8.dp),
        )
        return
    }
    Text(
        text = stringResource(R.string.app_choice_selected, selectedApp?.label ?: stringResource(R.string.value_empty)),
        modifier = Modifier.padding(top = 8.dp),
    )
    Text(
        text = supportText(selectedApp?.support, socksListen),
        modifier = Modifier.padding(top = 6.dp),
        style = MaterialTheme.typography.bodyMedium,
    )
    if (selectedApp?.packageName == TELEGRAM_PACKAGE) {
        Button(
            onClick = { openTelegramProxy(context.applicationContext, socksListen) },
            modifier = Modifier
                .fillMaxWidth()
                .padding(top = 10.dp),
        ) {
            Text(text = stringResource(R.string.telegram_proxy_button))
        }
    }
    AppGroup(
        titleRes = R.string.app_group_auto,
        emptyRes = R.string.app_group_auto_empty,
        apps = apps.apps.filter { it.support == ProxySupport.AUTO_TELEGRAM },
    )
    AppGroup(
        titleRes = R.string.app_group_manual,
        emptyRes = R.string.app_group_manual_empty,
        apps = apps.apps.filter { it.support == ProxySupport.MANUAL_PROXY },
    )
    AppGroup(
        titleRes = R.string.app_group_unavailable,
        emptyRes = R.string.app_group_unavailable_empty,
        apps = apps.apps.filter { it.support == ProxySupport.UNSUPPORTED }.take(MAX_UNSUPPORTED_APPS_SHOWN),
    )
}

@Composable
private fun AppGroup(titleRes: Int, emptyRes: Int, apps: List<InstalledAppInfo>) {
    Text(
        text = stringResource(titleRes),
        modifier = Modifier.padding(top = 14.dp),
        style = MaterialTheme.typography.titleMedium,
    )
    if (apps.isEmpty()) {
        Text(
            text = stringResource(emptyRes),
            modifier = Modifier.padding(top = 6.dp),
            style = MaterialTheme.typography.bodyMedium,
        )
        return
    }
    apps.forEach { app ->
        AppRow(app)
    }
}

@Composable
private fun AppRow(app: InstalledAppInfo) {
    val selected = TransportRuntime.apps.selectedPackage == app.packageName
    Surface(
        modifier = Modifier
            .fillMaxWidth()
            .padding(top = 6.dp)
            .clickable {
                TransportRuntime.apps = TransportRuntime.apps.copy(selectedPackage = app.packageName)
            },
        color = if (selected) MaterialTheme.colorScheme.primaryContainer else MaterialTheme.colorScheme.surfaceVariant,
        shape = MaterialTheme.shapes.small,
    ) {
        Row(
            modifier = Modifier.padding(10.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            AndroidView(
                factory = { viewContext ->
                    ImageView(viewContext).apply {
                        setImageDrawable(app.icon)
                        scaleType = ImageView.ScaleType.CENTER_INSIDE
                    }
                },
                update = { it.setImageDrawable(app.icon) },
                modifier = Modifier.size(36.dp),
            )
            Column {
                Text(text = app.label, style = MaterialTheme.typography.bodyLarge)
                Text(text = app.packageName, style = MaterialTheme.typography.bodySmall)
            }
        }
    }
}

@Composable
private fun TransportPanel(
    context: Context,
    transport: TransportUiState,
    auth: AuthUiState,
    selectedTransport: TransportChoice,
    empty: String,
    clockText: String,
    handshakeText: String,
    stabilityText: String,
    stableDurationText: String?,
    lastExchangeText: String,
) {
    val transportRunning = isTransportRunningForToggle(transport)
    val transportConnected = isTransportConnectedForToggle(transport)
    val connectInProgress = CONNECT_IN_PROGRESS
    val connecting = connectInProgress && !transportConnected && !isTransportTerminalForConnect(transport)
    LaunchedEffect(connectInProgress, transportConnected, transport.stateTextRes) {
        if (!connectInProgress) return@LaunchedEffect
        if (transportConnected || isTransportTerminalForConnect(transport)) {
            CONNECT_IN_PROGRESS = false
            return@LaunchedEffect
        }
        delay(CONNECT_TIMEOUT_MS)
        val current = TransportRuntime.state
        if (CONNECT_IN_PROGRESS && !isTransportConnectedForToggle(current)) {
            CONNECT_IN_PROGRESS = false
        }
    }
    Text(
        text = stringResource(R.string.state_title),
        style = MaterialTheme.typography.titleLarge,
    )
    Text(
        text = stringResource(R.string.transport_mode_title),
        modifier = Modifier.padding(top = 10.dp),
        style = MaterialTheme.typography.bodyMedium,
    )
    Column(
        modifier = Modifier.padding(top = 8.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            TransportModeButton(
                context = context,
                choice = TransportChoice.AUTO,
                selectedTransport = selectedTransport,
                auth = auth,
                labelRes = R.string.transport_mode_auto,
                enabled = !connecting && transportChoiceConfigured(TransportChoice.AUTO, auth),
            )
            TransportModeButton(
                context = context,
                choice = TransportChoice.AWG_RU,
                selectedTransport = selectedTransport,
                auth = auth,
                labelRes = R.string.transport_mode_awg_ru,
                enabled = !connecting && transportChoiceConfigured(TransportChoice.AWG_RU, auth),
            )
        }
        Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            TransportModeButton(
                context = context,
                choice = TransportChoice.REALITY2,
                selectedTransport = selectedTransport,
                auth = auth,
                labelRes = R.string.transport_mode_reality2,
                enabled = !connecting && transportChoiceConfigured(TransportChoice.REALITY2, auth),
            )
            TransportModeButton(
                context = context,
                choice = TransportChoice.AWG,
                selectedTransport = selectedTransport,
                auth = auth,
                labelRes = R.string.transport_mode_awg,
                enabled = !connecting && transportChoiceConfigured(TransportChoice.AWG, auth),
            )
        }
        Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            TransportModeButton(
                context = context,
                choice = TransportChoice.REALITY,
                selectedTransport = selectedTransport,
                auth = auth,
                labelRes = R.string.transport_mode_reality,
                enabled = !connecting && transportChoiceConfigured(TransportChoice.REALITY, auth),
            )
        }
    }
    Text(
        text = stringResource(R.string.transport_mode_auto_detail),
        modifier = Modifier.padding(top = 6.dp),
        style = MaterialTheme.typography.bodySmall,
    )
    if (selectedTransport == TransportChoice.REALITY && auth.reality?.isComplete() != true) {
        Text(
            text = stringResource(R.string.reality_tw_config_missing),
            modifier = Modifier.padding(top = 8.dp),
            color = MaterialTheme.colorScheme.error,
        )
    }
    if (selectedTransport == TransportChoice.AWG_RU && auth.awgRu?.isComplete() != true) {
        Text(
            text = stringResource(R.string.awg_ru_config_missing),
            modifier = Modifier.padding(top = 8.dp),
            color = MaterialTheme.colorScheme.error,
        )
    }
    if (selectedTransport == TransportChoice.REALITY2 && auth.reality2?.isComplete() != true) {
        Text(
            text = stringResource(R.string.reality2_config_missing),
            modifier = Modifier.padding(top = 8.dp),
            color = MaterialTheme.colorScheme.error,
        )
    }
    Button(
        enabled = !connecting && (auth.authorized || transportRunning),
        onClick = {
            if (transportRunning) {
                stopAllTransports(context.applicationContext)
            } else {
                connectSelectedTransport(context.applicationContext)
            }
        },
        modifier = Modifier
            .fillMaxWidth()
            .padding(top = 10.dp),
    ) {
        Text(
            text = stringResource(
                when {
                    connecting -> R.string.connecting_button
                    transportRunning -> R.string.disconnect_button
                    else -> R.string.connect_button
                },
            ),
        )
    }
    Text(
        text = stringResource(transport.stateTextRes),
        modifier = Modifier.padding(top = 12.dp),
        style = MaterialTheme.typography.bodyLarge,
    )
    Text(
        text = if (transport.clockSkewSeconds != null) {
            stringResource(R.string.status_clock_skew, clockText, transport.clockSkewSeconds)
        } else {
            stringResource(R.string.status_clock, clockText)
        },
        modifier = Modifier.padding(top = 8.dp),
    )
    Text(
        text = stringResource(R.string.status_handshake, handshakeText),
        modifier = Modifier.padding(top = 8.dp),
    )
    Text(
        text = stringResource(R.string.status_transport, transport.activeTransport.ifBlank { empty }),
        modifier = Modifier.padding(top = 6.dp),
    )
    Text(
        text = stringResource(R.string.status_stability, stabilityText),
        modifier = Modifier.padding(top = 6.dp),
    )
    stableDurationText?.let {
        Text(
            text = stringResource(R.string.status_stable_duration, it),
            modifier = Modifier.padding(top = 6.dp),
        )
    }
    Text(
        text = stringResource(R.string.status_last_exchange, lastExchangeText),
        modifier = Modifier.padding(top = 6.dp),
    )
    Text(
        text = stringResource(R.string.status_socks, activeSocks(transport, auth).ifBlank { empty }),
        modifier = Modifier.padding(top = 6.dp),
    )
    Text(
        text = stringResource(R.string.status_rx, transport.rxBytes),
        modifier = Modifier.padding(top = 6.dp),
    )
    Text(
        text = stringResource(R.string.status_tx, transport.txBytes),
        modifier = Modifier.padding(top = 6.dp),
    )
    Text(
        text = stringResource(R.string.status_ip, transport.outboundIp.ifBlank { empty }),
        modifier = Modifier.padding(top = 6.dp),
    )
}

@Composable
private fun rememberStableDurationText(stableSinceElapsedRealtimeMs: Long?): String? {
    var nowMs by remember { mutableLongStateOf(SystemClock.elapsedRealtime()) }
    LaunchedEffect(stableSinceElapsedRealtimeMs) {
        if (stableSinceElapsedRealtimeMs == null) return@LaunchedEffect
        while (true) {
            nowMs = SystemClock.elapsedRealtime()
            delay(1000)
        }
    }
    return stableSinceElapsedRealtimeMs?.let { since ->
        formatStableDuration(((nowMs - since) / 1000).coerceAtLeast(0))
    }
}

private fun formatStableDuration(totalSeconds: Long): String {
    val hours = totalSeconds / 3600
    val minutes = (totalSeconds % 3600) / 60
    val seconds = totalSeconds % 60
    return if (hours > 0) {
        String.format(Locale.ROOT, "%d:%02d:%02d", hours, minutes, seconds)
    } else {
        String.format(Locale.ROOT, "%02d:%02d", minutes, seconds)
    }
}

@Composable
private fun TransportModeButton(
    context: Context,
    choice: TransportChoice,
    selectedTransport: TransportChoice,
    auth: AuthUiState,
    labelRes: Int,
    enabled: Boolean = true,
) {
    val selected = selectedTransport == choice
    if (selected) {
        Button(
            enabled = enabled,
            onClick = {
                TransportRuntime.selectedTransport = choice
                if (auth.authorized) {
                    connectSelectedTransport(context.applicationContext)
                }
            },
        ) {
            Text(text = stringResource(labelRes))
        }
    } else {
        OutlinedButton(
            enabled = enabled,
            onClick = {
                TransportRuntime.selectedTransport = choice
                if (auth.authorized) {
                    connectSelectedTransport(context.applicationContext)
                }
            },
        ) {
            Text(text = stringResource(labelRes))
        }
    }
}

@Composable
private fun supportText(support: ProxySupport?, socksListen: String): String =
    when (support) {
        ProxySupport.AUTO_TELEGRAM -> stringResource(R.string.app_support_auto)
        ProxySupport.MANUAL_PROXY -> stringResource(
            R.string.app_support_manual,
            socksListen.ifBlank { DEFAULT_SOCKS_LISTEN },
        )
        ProxySupport.UNSUPPORTED -> stringResource(R.string.app_support_unavailable)
        null -> stringResource(R.string.app_support_none)
    }

private data class PermissionCheckResult(
    @StringRes val titleRes: Int,
    val ok: Boolean,
    val fix: ((Context) -> Unit)? = null,
)

@StringRes
private fun transportChoiceLabelRes(choice: TransportChoice): Int =
    when (choice) {
        TransportChoice.AUTO -> R.string.transport_mode_auto
        TransportChoice.AWG_RU -> R.string.transport_mode_awg_ru
        TransportChoice.AWG -> R.string.transport_mode_awg
        TransportChoice.REALITY -> R.string.transport_mode_reality
        TransportChoice.REALITY2 -> R.string.transport_mode_reality2
    }

private fun transportChoiceConfigured(choice: TransportChoice, auth: AuthUiState): Boolean {
    if (DeploymentConfig.IS_PUBLIC_PLATFORM && auth.authorized) {
        val priorities = TransportRuntime.publicPlatformRouteSlots.routePriorities
        return when (choice) {
            TransportChoice.AUTO -> priorities.isNotEmpty()
            TransportChoice.AWG_RU -> priorities.containsKey("AWG_RU") && auth.awgRu?.isComplete() == true
            TransportChoice.AWG -> priorities.containsKey("AWG")
            TransportChoice.REALITY -> priorities.containsKey("REALITY") && auth.reality?.isComplete() == true
            TransportChoice.REALITY2 -> priorities.containsKey("REALITY2") && auth.reality2?.isComplete() == true
        }
    }
    return when (choice) {
        TransportChoice.AUTO -> true
        TransportChoice.AWG_RU -> auth.awgRu?.isComplete() == true
        TransportChoice.AWG -> true
        TransportChoice.REALITY -> auth.reality?.isComplete() == true
        TransportChoice.REALITY2 -> auth.reality2?.isComplete() == true
    }
}

private fun displayTransportLabel(raw: String): String =
    when (raw) {
        TRANSPORT_LABEL_AWG_RU -> "AWG-RU"
        TRANSPORT_LABEL_AWG -> "AWG-NL"
        TRANSPORT_LABEL_REALITY -> "REALITY-TW"
        TRANSPORT_LABEL_REALITY2 -> "REALITY-RU"
        else -> raw.ifBlank { "Авто" }
    }

private fun refreshAttentionState(context: Context) {
    refreshBatteryRestrictionRuntime(context.applicationContext)
    ATTENTION_REFRESH_TICK = SystemClock.elapsedRealtime()
}

private fun notificationsDisabled(context: Context, attentionRefreshTick: Long): Boolean {
    if (attentionRefreshTick < 0L) return false
    return Build.VERSION.SDK_INT >= 33 &&
        context.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
}

private fun requestPostNotificationsPermission(context: Context) {
    if (Build.VERSION.SDK_INT < 33) return
    val activity = context as? Activity
    if (activity != null) {
        activity.requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 1001)
    } else {
        openNotificationSettings(context.applicationContext)
    }
}

private fun openNotificationSettings(context: Context) {
    val intent = Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS)
        .putExtra(Settings.EXTRA_APP_PACKAGE, context.packageName)
        .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
    runCatching { context.startActivity(intent) }
        .onFailure { openThisAppDetailsSettings(context) }
}

private fun openThisAppDetailsSettings(context: Context) {
    val intent = Intent(
        Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
        Uri.parse("package:${context.packageName}"),
    ).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
    runCatching { context.startActivity(intent) }
}

private fun copySocksAddress(context: Context, socksListen: String) {
    val clipboard = context.getSystemService(ClipboardManager::class.java)
    clipboard?.setPrimaryClip(ClipData.newPlainText("TrafficWrapper SOCKS5", socksListen))
    Toast.makeText(context, R.string.copied_to_clipboard, Toast.LENGTH_SHORT).show()
}

private fun publicBootstrapRaw(context: Context): String =
    SecureIdentityStore(context).readPublicPlatformState().bootstrapRaw.ifBlank {
        context.applicationContext
            .getSharedPreferences(PUBLIC_PLATFORM_PREFS, Context.MODE_PRIVATE)
            .getString(KEY_PUBLIC_BOOTSTRAP_RAW, "")
            .orEmpty()
    }

private fun savePublicBootstrap(context: Context, raw: String) {
    context.applicationContext
        .getSharedPreferences(PUBLIC_PLATFORM_PREFS, Context.MODE_PRIVATE)
        .edit()
        .putString(KEY_PUBLIC_BOOTSTRAP_RAW, raw.trim())
        .apply()
}

private fun readBootstrapDocument(context: Context, uri: Uri): String =
    context.contentResolver.openInputStream(uri)
        ?.bufferedReader(Charsets.UTF_8)
        ?.use { it.readText() }
        ?.trim()
        .orEmpty()
        .ifBlank { error("bootstrap document is empty") }

private data class PendingExternalBootstrap(
    val raw: String,
    val orchestratorUrl: String,
    val configPubkeyPin: String,
)

private fun buildPermissionCheckResults(context: Context): List<PermissionCheckResult> {
    val state = currentBatteryRestrictionState(context.applicationContext)
    TransportRuntime.batteryRestriction = state
    return listOf(
        PermissionCheckResult(
            titleRes = R.string.permission_battery_optimization,
            ok = !state.batteryOptimizationRestricted,
            fix = if (state.batteryOptimizationRestricted) {
                { openBatteryRestrictionFlow(it) }
            } else {
                null
            },
        ),
        PermissionCheckResult(
            titleRes = R.string.permission_oem_background,
            ok = !state.oemHintNeeded,
            fix = if (state.oemHintNeeded || state.backgroundRestricted) {
                { openBatteryRestrictionFlow(it) }
            } else {
                null
            },
        ),
        PermissionCheckResult(
            titleRes = R.string.permission_notifications,
            ok = !notificationsDisabled(context, ATTENTION_REFRESH_TICK),
            fix = if (notificationsDisabled(context, ATTENTION_REFRESH_TICK)) {
                { requestPostNotificationsPermission(it) }
            } else {
                null
            },
        ),
        PermissionCheckResult(
            titleRes = R.string.permission_install_packages,
            ok = !installPermissionNeeded(context),
            fix = if (installPermissionNeeded(context)) {
                { DistributionChannel.openInstallSettings(it.applicationContext) }
            } else {
                null
            },
        ),
    )
}

private fun permissionSummary(
    context: Context,
    batteryRestriction: BatteryRestrictionState,
    attentionRefreshTick: Long,
): String {
    val batteryText = if (batteryRestriction.restricted) {
        context.getString(R.string.permission_summary_battery_needed)
    } else {
        context.getString(R.string.permission_summary_battery_ok)
    }
    val notificationText = if (notificationsDisabled(context, attentionRefreshTick)) {
        context.getString(R.string.permission_summary_notifications_needed)
    } else {
        context.getString(R.string.permission_summary_notifications_ok)
    }
    return "$batteryText · $notificationText"
}

private fun installPermissionNeeded(context: Context): Boolean =
    BuildConfig.FLAVOR == PRIVATE_FLAVOR_NAME &&
        Build.VERSION.SDK_INT >= 26 &&
        !context.packageManager.canRequestPackageInstalls()

@StringRes
private fun updateSettingsStatusTextRes(updates: DistributionUiState): Int =
    if (updates.errorTextRes?.let { suppressUpdateErrorInSettings(updates, it) } == true) {
        R.string.update_status_latest
    } else {
        updates.statusTextRes
    }

private fun suppressUpdateErrorInSettings(updates: DistributionUiState, @StringRes errorRes: Int): Boolean =
    errorRes == R.string.update_error_downgrade &&
        (updates.availableVersionCode == 0L || updates.availableVersionCode < BuildConfig.VERSION_CODE.toLong())

private fun restorePublicPlatformState(context: Context): Boolean {
    if (!DeploymentConfig.IS_PUBLIC_PLATFORM) return false
    val store = SecureIdentityStore(context)
    val stored = store.readPublicPlatformState()
    if (
        stored.clientBundleJson.isBlank() ||
        stored.configPubkeyPin.isBlank() ||
        stored.awgPrivateKey.isBlank() ||
        stored.realityUUID.isBlank()
    ) {
        return false
    }
    return runCatching {
        val config = PublicPlatformConfigParser.verifyAndParseClientConfig(
            envelopeRaw = stored.clientBundleJson,
            expectedPublicKey = stored.configPubkeyPin,
            maxSeenSeq = stored.maxSeenConfigSeq,
            nowMs = 0L,
        )
        applyPublicPlatformState(
            context = context.applicationContext,
            store = store,
            stored = stored,
            config = config,
            persist = false,
        )
        true
    }.getOrElse { error ->
        Log.w(TAG, "public platform cached config restore failed", error)
        false
    }
}

private fun startPublicDeviceEnrollment(context: Context, bootstrapRaw: String = publicBootstrapRaw(context)) {
    if (!DeploymentConfig.IS_PUBLIC_PLATFORM) return
    if (!ENROLLMENT_ACTIVE.compareAndSet(false, true)) return
    TransportRuntime.auth = TransportRuntime.auth.copy(
        inProgress = true,
        authorized = false,
        statusTextRes = R.string.public_enrollment_status_registering,
        errorTextRes = null,
    )
    ENROLLMENT_EXECUTOR.execute {
        val mainHandler = Handler(Looper.getMainLooper())
        try {
            val parsed = PublicPlatformConfigParser.parseBootstrap(bootstrapRaw)
            val androidID = Settings.Secure.getString(context.contentResolver, Settings.Secure.ANDROID_ID).orEmpty()
            if (androidID.isBlank()) {
                postEnrollmentFailure(mainHandler, R.string.enrollment_error_device_id)
                return@execute
            }
            val store = SecureIdentityStore(context)
            val previous = store.readPublicPlatformState()
            val noiseIdentity = store.getOrCreateIdentity { Transport.generateIdentity() }
            val deviceIdentity = store.getOrCreateDeviceIdentity()
            val model = deviceModel()
            val nonce = randomNonce()
            val request = JSONObject()
                .put(JSON_PUBLIC_ORCHESTRATOR_URL, parsed.orchestratorUrl)
                .put(JSON_PUBLIC_ORCH_NOISE_PUBLIC, parsed.orchNoisePublic)
                .put(JSON_PUBLIC_BOOTSTRAP_TOKEN, parsed.bootstrapToken)
                .put(JSON_NOISE_PRIVATE_KEY, noiseIdentity.privateKey)
                .put(JSON_NOISE_PUBLIC_KEY, noiseIdentity.publicKey)
                .put(JSON_DEVICE_ID, androidID)
                .put(JSON_ANDROID_ID, androidID)
                .put(JSON_MODEL, model)
                .put(JSON_IDENTITY_PUBLIC_KEY, deviceIdentity.publicKey)
                .put(JSON_IDENTITY_KEY_TYPE, deviceIdentity.keyType)
                .put(JSON_ENROLLMENT_NONCE, nonce)
                .put(JSON_CLIENT_VERSION, BuildConfig.VERSION_NAME)
                .put(JSON_TIMEOUT_SECONDS, PUBLIC_ENROLL_TIMEOUT_SECONDS)
            val response = JSONObject(Transport.publicDeviceEnroll(request.toString()))
            if (!response.optBoolean(JSON_OK, false)) {
                throw IllegalStateException(response.optString(JSON_ERROR))
            }
            val clientBundle = response.optJSONObject(JSON_PUBLIC_CLIENT_BUNDLE)
                ?: throw IllegalStateException("missing client bundle")
            val config = PublicPlatformConfigParser.verifyAndParseClientConfig(
                envelopeRaw = clientBundle.toString(),
                expectedPublicKey = parsed.configPubkeyPin,
                maxSeenSeq = previous.maxSeenConfigSeq,
            )
            val stored = StoredPublicPlatformState(
                bootstrapRaw = bootstrapRaw.trim(),
                configPubkeyPin = parsed.configPubkeyPin,
                updatePubkeyPin = config.updatePubkey.ifBlank { parsed.updatePubkey },
                maxSeenConfigSeq = maxOf(previous.maxSeenConfigSeq, config.seq),
                maxSeenUpdateSeq = previous.maxSeenUpdateSeq,
                clientConfigJson = clientBundle.getString(JSON_PUBLIC_CONFIG_JSON),
                clientBundleJson = clientBundle.toString(),
                deviceID = response.optString(JSON_DEVICE_ID).ifBlank { androidID },
                realityUUID = response.getString(JSON_PUBLIC_REALITY_UUID),
                internalIP = response.getString(JSON_INTERNAL_IP),
                psk2 = response.getString(JSON_PUBLIC_PSK2),
                serverAWGPublic = response.getString(JSON_PUBLIC_SERVER_AWG_PUBLIC),
                awgPrivateKey = response.getString(JSON_PUBLIC_AWG_PRIVATE_KEY),
                awgPublicKey = response.getString(JSON_PUBLIC_AWG_PUBLIC_KEY),
            )
            applyPublicPlatformState(
                context = context.applicationContext,
                store = store,
                stored = stored,
                config = config,
                noiseIdentity = noiseIdentity,
                deviceIdentity = deviceIdentity,
                androidID = androidID,
                model = model,
                persist = true,
            )
            savePublicBootstrap(context, bootstrapRaw)
        } catch (error: Throwable) {
            Log.w(TAG, "public device enrollment failed", error)
            mainHandler.post {
                PUBLIC_BOOTSTRAP_ERROR = Telemetry.safeErrorMessage(error)
            }
            postEnrollmentFailure(mainHandler, R.string.public_enrollment_error)
        } finally {
            ENROLLMENT_ACTIVE.set(false)
        }
    }
}

private fun applyPublicPlatformState(
    context: Context,
    store: SecureIdentityStore,
    stored: StoredPublicPlatformState,
    config: PublicClientConfig,
    noiseIdentity: StoredIdentity = store.getOrCreateIdentity { Transport.generateIdentity() },
    deviceIdentity: StoredDeviceIdentity = store.getOrCreateDeviceIdentity(),
    androidID: String = stored.deviceID,
    model: String = deviceModel(),
    persist: Boolean,
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
    if (!slots.hasUsableRoute()) {
        throw IllegalStateException("public client config has no usable route")
    }
    val applyRequest = JSONObject()
        .put(JSON_PUBLIC_AWG_PRIVATE_KEY, stored.awgPrivateKey)
        .put(JSON_INTERNAL_IP, stored.internalIP)
        .put(JSON_PUBLIC_PSK2, stored.psk2)
        .put(JSON_PUBLIC_SERVER_AWG_PUBLIC, stored.serverAWGPublic)
        .put(JSON_SOCKS_LISTEN, DEFAULT_AWG_INTERNAL_SOCKS_LISTEN)
        .put(JSON_AWG_RU_SOCKS_LISTEN, DEFAULT_AWG_RU_INTERNAL_SOCKS_LISTEN)
        .put(JSON_MTU, DEFAULT_MTU)
    slots.awgRu?.let { applyRequest.put(JSON_AWG_RU, PublicPlatformConfigParser.awgRouteJson(it)) }
    slots.awg?.let { applyRequest.put(JSON_AWG, PublicPlatformConfigParser.awgRouteJson(it)) }
    val applyResponse = JSONObject(Transport.applyPublicPlatformConfig(applyRequest.toString()))
    if (!applyResponse.optBoolean(JSON_OK, false)) {
        throw IllegalStateException(applyResponse.optString(JSON_ERROR))
    }
    if (persist) {
        store.writePublicPlatformState(stored)
    }
    TransportRuntime.publicPlatformConfig = config
    TransportRuntime.publicPlatformRouteSlots = slots
    TransportRuntime.publicReality2EgressIp = slots.reality2ExpectedEgressIp
    TransportRuntime.publicRealityEgressIp = slots.realityExpectedEgressIp
    TransportRuntime.selectedTransport = TransportChoice.AUTO
    val mainHandler = Handler(Looper.getMainLooper())
    postEnrollmentBaseState(
        mainHandler = mainHandler,
        noiseIdentity = noiseIdentity,
        deviceIdentity = deviceIdentity,
        deviceID = stored.deviceID,
        androidID = androidID,
        model = model,
        statusTextRes = R.string.enrollment_status_approved,
        authorized = true,
        alias = config.workers.firstOrNull()?.label.orEmpty(),
        message = context.getString(R.string.public_config_applied, config.seq),
        internalIP = stored.internalIP,
        endpoint = publicAwgEndpoint(slots.awgRu ?: slots.awg),
        socksListen = DEFAULT_ROUTER_SOCKS_LISTEN,
        awgRu = publicAwgUiConfig(slots.awgRu, stored),
        reality = slots.reality,
        reality2 = slots.reality2,
    )
}

private fun publicAwgUiConfig(route: PublicRouteConfig?, stored: StoredPublicPlatformState): AwgUiConfig? {
    if (route == null) return null
    return AwgUiConfig(
        internalIP = stored.internalIP,
        endpoint = publicAwgEndpoint(route),
        serverPublicKey = route.params.optString(JSON_PUBLIC_KEY_SNAKE).ifBlank { stored.serverAWGPublic },
    )
}

private fun publicAwgEndpoint(route: PublicRouteConfig?): String {
    if (route == null) return ""
    return route.params.optString(JSON_ENDPOINT).ifBlank { "${route.address}:${route.port}" }
}

private fun startDeviceEnrollment(context: Context) {
    if (!ENROLLMENT_ACTIVE.compareAndSet(false, true)) return
    TransportRuntime.auth = TransportRuntime.auth.copy(
        inProgress = true,
        authorized = false,
        statusTextRes = R.string.enrollment_status_starting,
        errorTextRes = null,
    )
    ENROLLMENT_EXECUTOR.execute {
        val mainHandler = Handler(Looper.getMainLooper())
        try {
            val androidID = Settings.Secure.getString(context.contentResolver, Settings.Secure.ANDROID_ID).orEmpty()
            if (androidID.isBlank()) {
                Telemetry.event(
                    context,
                    "enroll_fail",
                    "enr" to "error",
                    "err_where" to "android_id",
                    "err_kind" to "config",
                )
                postEnrollmentFailure(mainHandler, R.string.enrollment_error_device_id)
                return@execute
            }
            val enrollmentSecret = BuildConfig.ENROLLMENT_SECRET
            if (enrollmentSecret.isBlank()) {
                Telemetry.event(
                    context,
                    "enroll_fail",
                    "enr" to "error",
                    "err_where" to "enrollment_secret",
                    "err_kind" to "config",
                )
                postEnrollmentFailure(mainHandler, R.string.enrollment_error_secret_missing)
                return@execute
            }
            val store = SecureIdentityStore(context)
            val noiseIdentity = store.getOrCreateIdentity { Transport.generateIdentity() }
            val deviceIdentity = store.getOrCreateDeviceIdentity()
            store.getOrCreateSessionToken()
            val model = deviceModel()
            postEnrollmentBaseState(
                mainHandler = mainHandler,
                noiseIdentity = noiseIdentity,
                deviceIdentity = deviceIdentity,
                deviceID = androidID,
                androidID = androidID,
                model = model,
                statusTextRes = R.string.enrollment_status_registering,
                authorized = false,
            )
            var routeDownSinceMs: Long? = null
            var nextAutoKeyRequestAtMs = 0L
            var autoKeyRequestBackoffMs = AUTO_RECOVERY_MIN_KEY_REQUEST_INTERVAL_MS
            while (ENROLLMENT_ACTIVE.get()) {
                val authorized = TransportRuntime.auth.authorized
                val selectedTransport = TransportRuntime.selectedTransport
                val routeRunning = authorized && isRunningOnCurrentRoute(selectedTransport)
                val nowMs = SystemClock.elapsedRealtime()
                if (routeRunning) {
                    routeDownSinceMs = null
                    nextAutoKeyRequestAtMs = 0L
                    autoKeyRequestBackoffMs = AUTO_RECOVERY_MIN_KEY_REQUEST_INTERVAL_MS
                } else if (authorized && TRANSPORT_KEEP_ALIVE.get()) {
                    val downSince = routeDownSinceMs ?: nowMs.also { routeDownSinceMs = it }
                    val downForMs = nowMs - downSince
                    if (
                        downForMs >= AUTO_RECOVERY_GRACE_MS &&
                        !FORCE_KEY_REQUEST.get() &&
                        nowMs >= nextAutoKeyRequestAtMs
                    ) {
                        if (selectedTransport == TransportChoice.REALITY && TransportRuntime.auth.reality?.isComplete() == true) {
                            Log.w(TAG, "auto recovery restarting REALITY transport after ${downForMs}ms down")
                            mainHandler.post {
                                if (TRANSPORT_KEEP_ALIVE.get()) {
                                    startSelectedTransport(context.applicationContext)
                                } else {
                                    Log.i(TAG, "skip auto recovery restart after manual stop")
                                }
                            }
                        } else if (selectedTransport == TransportChoice.AWG_RU && TransportRuntime.auth.awgRu?.isComplete() == true) {
                            Log.w(TAG, "auto recovery restarting AWG-RU transport after ${downForMs}ms down")
                            mainHandler.post {
                                if (TRANSPORT_KEEP_ALIVE.get()) {
                                    startSelectedTransport(context.applicationContext)
                                } else {
                                    Log.i(TAG, "skip auto recovery restart after manual stop")
                                }
                            }
                        } else if (
                            (selectedTransport == TransportChoice.AUTO && (
                                TransportRuntime.auth.awgRu?.isComplete() == true ||
                                    TransportRuntime.auth.reality2?.isComplete() == true
                                )) ||
                            (selectedTransport == TransportChoice.REALITY2 && TransportRuntime.auth.reality2?.isComplete() == true)
                        ) {
                            Log.w(TAG, "auto recovery restarting $selectedTransport transport after ${downForMs}ms down")
                            mainHandler.post {
                                if (TRANSPORT_KEEP_ALIVE.get()) {
                                    startSelectedTransport(context.applicationContext)
                                } else {
                                    Log.i(TAG, "skip auto recovery restart after manual stop")
                                }
                            }
                        } else {
                            Log.w(TAG, "auto recovery requesting fresh keys after ${downForMs}ms down route=$selectedTransport")
                            FORCE_KEY_REQUEST.set(true)
                        }
                        nextAutoKeyRequestAtMs = nowMs + autoKeyRequestBackoffMs
                        autoKeyRequestBackoffMs =
                            (autoKeyRequestBackoffMs * 2).coerceAtMost(AUTO_RECOVERY_MAX_KEY_REQUEST_INTERVAL_MS)
                    }
                }
                val shouldRequestKeys = FORCE_KEY_REQUEST.getAndSet(false) || !authorized
                if (authorized && !shouldRequestKeys) {
                    sleepEnrollment(
                        when {
                            routeRunning -> APPROVED_RUNNING_POLL_INTERVAL_MS
                            TRANSPORT_KEEP_ALIVE.get() -> APPROVED_RECOVERY_CHECK_INTERVAL_MS
                            else -> APPROVED_RUNNING_POLL_INTERVAL_MS
                        },
                    )
                    continue
                }
                val response = try {
                    enrollDevice(
                        store = store,
                        noiseIdentity = noiseIdentity,
                        deviceIdentity = deviceIdentity,
                        deviceID = androidID,
                        androidID = androidID,
                        model = model,
                        enrollmentSecret = enrollmentSecret,
                        requestKeys = shouldRequestKeys,
                    )
                } catch (error: Throwable) {
                    Log.w(TAG, "device enrollment poll failed", error)
                    Telemetry.event(
                        context,
                        "enroll_fail",
                        "enr" to "error",
                        "err_where" to "enroll_poll",
                        "err_kind" to Telemetry.errorKind(error),
                        "err_msg" to Telemetry.safeErrorMessage(error),
                    )
                    if (!TransportRuntime.auth.authorized) {
                        postEnrollmentFailure(mainHandler, R.string.enrollment_error_network)
                    }
                    sleepEnrollment(PENDING_POLL_INTERVAL_MS)
                    continue
                }
                val status = response.optString(JSON_STATUS)
                val message = response.optString(JSON_MESSAGE)
                when (status) {
                    DEVICE_STATUS_APPROVED -> {
                        val configStored = response.optBoolean(JSON_CONFIG_STORED, false)
                        postEnrollmentApproved(
                            context = context.applicationContext,
                            mainHandler = mainHandler,
                            noiseIdentity = noiseIdentity,
                            deviceIdentity = deviceIdentity,
                            deviceID = androidID,
                            androidID = androidID,
                            model = model,
                            response = response,
                        )
                        if (configStored) {
                            mainHandler.post {
                                if (TRANSPORT_KEEP_ALIVE.get()) {
                                    startSelectedTransport(context)
                                } else {
                                    Log.i(TAG, "skip transport start for stored config after manual stop")
                                }
                            }
                        }
                        sleepEnrollment(APPROVED_POLL_INTERVAL_MS)
                    }

                    DEVICE_STATUS_PENDING, "" -> {
                        Telemetry.event(
                            context,
                            "enroll_pending",
                            "enr" to "pending",
                        )
                        postEnrollmentBaseState(
                            mainHandler = mainHandler,
                            noiseIdentity = noiseIdentity,
                            deviceIdentity = deviceIdentity,
                            deviceID = androidID,
                            androidID = androidID,
                            model = model,
                            statusTextRes = R.string.enrollment_status_pending,
                            authorized = false,
                            alias = response.optString(JSON_ALIAS),
                            message = message,
                        )
                        sleepEnrollment(PENDING_POLL_INTERVAL_MS)
                    }

                    DEVICE_STATUS_BLOCKED -> {
                        Telemetry.event(
                            context,
                            "enroll_blocked",
                            "enr" to if (message.contains(LIMIT_TEXT_MARKER, ignoreCase = true)) "limit" else "blocked",
                            "rsn" to if (message.contains(LIMIT_TEXT_MARKER, ignoreCase = true)) "limit" else "blocked",
                        )
                        mainHandler.post { stopAllTransports(context, keepAlive = false) }
                        postEnrollmentBaseState(
                            mainHandler = mainHandler,
                            noiseIdentity = noiseIdentity,
                            deviceIdentity = deviceIdentity,
                            deviceID = androidID,
                            androidID = androidID,
                            model = model,
                            statusTextRes = if (message.contains(LIMIT_TEXT_MARKER, ignoreCase = true)) {
                                R.string.enrollment_status_limit
                            } else {
                                R.string.enrollment_status_blocked
                            },
                            authorized = false,
                            alias = response.optString(JSON_ALIAS),
                            message = message,
                        )
                        sleepEnrollment(BLOCKED_POLL_INTERVAL_MS)
                    }

                    else -> {
                        Telemetry.event(
                            context,
                            "enroll_fail",
                            "enr" to "error",
                            "err_where" to "enroll_status",
                            "err_kind" to "unknown",
                            "err_msg" to status,
                        )
                        postEnrollmentFailure(mainHandler, R.string.enrollment_error_network)
                        sleepEnrollment(PENDING_POLL_INTERVAL_MS)
                    }
                }
            }
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
        } catch (error: Throwable) {
            Log.w(TAG, "device enrollment failed", error)
            Telemetry.event(
                context,
                "enroll_fail",
                "enr" to "error",
                "err_where" to "enroll_worker",
                "err_kind" to Telemetry.errorKind(error),
                "err_msg" to Telemetry.safeErrorMessage(error),
            )
            postEnrollmentFailure(mainHandler, R.string.enrollment_error_network)
        } finally {
            ENROLLMENT_ACTIVE.set(false)
        }
    }
}

fun requestFreshDeviceKeys(context: Context, userInitiated: Boolean = true) {
    val appContext = context.applicationContext
    if (DeploymentConfig.IS_PUBLIC_PLATFORM) {
        if (restorePublicPlatformState(appContext)) {
            if (userInitiated) {
                TRANSPORT_KEEP_ALIVE.set(true)
                TransportLifecycleStore.rememberActiveTransport(appContext, TransportRuntime.selectedTransport)
            }
            startSelectedTransport(appContext)
        } else {
            startPublicDeviceEnrollment(appContext)
        }
        return
    }
    if (userInitiated) {
        TRANSPORT_KEEP_ALIVE.set(true)
        TransportLifecycleStore.rememberActiveTransport(appContext, TransportRuntime.selectedTransport)
    } else if (!TRANSPORT_KEEP_ALIVE.get()) {
        Log.i(TAG, "skip automatic fresh key request after manual stop")
        return
    }
    stopAllTransports(appContext, keepAlive = true)
    runCatching { Transport.stop() }
        .onFailure { Log.w(TAG, "transport stop before key request failed", it) }
    FORCE_KEY_REQUEST.set(true)
    startDeviceEnrollment(appContext)
}

private fun requestStartupAutoconnect(context: Context) {
    if (!STARTUP_AUTOCONNECT_REQUESTED.compareAndSet(false, true)) return
    if (!TransportLifecycleStore.shouldKeepAlive(context)) return
    TransportRuntime.selectedTransport = TransportLifecycleStore.preferredMode(context)
    TRANSPORT_KEEP_ALIVE.set(true)
    CONNECT_IN_PROGRESS = true
    TransportRuntime.state = TransportRuntime.state.copy(
        stateTextRes = R.string.state_starting,
        socksListen = DEFAULT_ROUTER_SOCKS_LISTEN,
    )
}

private fun connectSelectedTransport(context: Context) {
    TRANSPORT_KEEP_ALIVE.set(true)
    TransportLifecycleStore.rememberActiveTransport(context.applicationContext, TransportRuntime.selectedTransport)
    CONNECT_IN_PROGRESS = true
    TransportRuntime.state = TransportRuntime.state.copy(
        stateTextRes = R.string.state_starting,
        socksListen = DEFAULT_ROUTER_SOCKS_LISTEN,
    )
    if (DeploymentConfig.IS_PUBLIC_PLATFORM) {
        if (TransportRuntime.auth.authorized || restorePublicPlatformState(context.applicationContext)) {
            startSelectedTransport(context.applicationContext)
        } else {
            startPublicDeviceEnrollment(context.applicationContext)
        }
        return
    }
    when (TransportRuntime.selectedTransport) {
        TransportChoice.AUTO -> {
            if (isRunningOnCurrentRoute(TransportChoice.AUTO)) {
                startSelectedTransport(context.applicationContext)
            } else {
                requestFreshDeviceKeys(context.applicationContext)
            }
        }
        TransportChoice.AWG_RU -> {
            if (TransportRuntime.auth.awgRu?.isComplete() == true && isRunningOnCurrentRoute(TransportChoice.AWG_RU)) {
                startSelectedTransport(context.applicationContext)
            } else {
                requestFreshDeviceKeys(context.applicationContext)
            }
        }
        TransportChoice.AWG -> {
            if (isRunningOnCurrentRoute(TransportChoice.AWG)) {
                startSelectedTransport(context.applicationContext)
            } else {
                requestFreshDeviceKeys(context.applicationContext)
            }
        }
        TransportChoice.REALITY -> {
            if (TransportRuntime.auth.reality?.isComplete() == true) {
                startSelectedTransport(context.applicationContext)
            } else {
                requestFreshDeviceKeys(context.applicationContext)
            }
        }
        TransportChoice.REALITY2 -> {
            if (TransportRuntime.auth.reality2?.isComplete() == true) {
                startSelectedTransport(context.applicationContext)
            } else {
                requestFreshDeviceKeys(context.applicationContext)
            }
        }
    }
}

private fun isRunningOnCurrentRoute(choice: TransportChoice): Boolean {
    val state = TransportRuntime.state
    if (state.socksListen != DEFAULT_ROUTER_SOCKS_LISTEN) return false
    if (state.stateTextRes == R.string.state_idle || state.stateTextRes == R.string.state_error) return false
    return when (choice) {
        TransportChoice.AUTO -> state.activeTransport in setOf(
            TRANSPORT_LABEL_AWG_RU,
            TRANSPORT_LABEL_AWG,
            TRANSPORT_LABEL_REALITY,
            TRANSPORT_LABEL_REALITY2,
        )
        TransportChoice.AWG_RU -> state.activeTransport == TRANSPORT_LABEL_AWG_RU
        TransportChoice.AWG -> state.activeTransport == TRANSPORT_LABEL_AWG
        TransportChoice.REALITY -> state.activeTransport == TRANSPORT_LABEL_REALITY
        TransportChoice.REALITY2 -> state.activeTransport == TRANSPORT_LABEL_REALITY2
    }
}

private fun isTransportRunningForToggle(state: TransportUiState): Boolean =
    state.socksListen == DEFAULT_ROUTER_SOCKS_LISTEN &&
        state.stateTextRes != R.string.state_idle &&
        state.stateTextRes != R.string.state_error

private fun isTransportConnectedForToggle(state: TransportUiState): Boolean =
    state.socksListen == DEFAULT_ROUTER_SOCKS_LISTEN &&
        (
            state.handshakeEstablished ||
                state.tunnelStable ||
                state.stateTextRes == R.string.state_connected ||
                state.stateTextRes == R.string.state_connected_stable
            )

private fun isTransportTerminalForConnect(state: TransportUiState): Boolean =
    state.stateTextRes == R.string.state_error ||
        state.stateTextRes == R.string.state_clock_error

private fun enrollDevice(
    store: SecureIdentityStore,
    noiseIdentity: StoredIdentity,
    deviceIdentity: StoredDeviceIdentity,
    deviceID: String,
    androidID: String,
    model: String,
    enrollmentSecret: String,
    requestKeys: Boolean,
): JSONObject {
    val nonce = randomNonce()
    val canonicalPayload = deviceEnrollmentCanonicalPayload(
        deviceID = deviceID,
        androidID = androidID,
        model = model,
        identityKeyType = deviceIdentity.keyType,
        identityPubKey = deviceIdentity.publicKey,
        nonce = nonce,
    )
    val signature = store.signDeviceEnrollment(canonicalPayload)
    val request = JSONObject()
        .put(JSON_PROVISION_ADDR, PROVISION_ADDR)
        .put(JSON_PROVISION_SERVER_PUBLIC, PROVISION_SERVER_PUBLIC)
        .put(JSON_EXPECTED_SERVER_AWG_PUBLIC, SERVER_AWG_PUBLIC)
        .put(JSON_REQUIRE_EXPECTED_AWG_PUBLIC, true)
        .put(JSON_EXPECTED_SERVER_AWG_RU_PUBLIC, SERVER_AWG_RU_PUBLIC)
        .put(JSON_REQUIRE_EXPECTED_AWG_RU_PUBLIC, true)
        .put(JSON_NOISE_PRIVATE_KEY, noiseIdentity.privateKey)
        .put(JSON_NOISE_PUBLIC_KEY, noiseIdentity.publicKey)
        .put(JSON_DEVICE_ID, deviceID)
        .put(JSON_ANDROID_ID, androidID)
        .put(JSON_MODEL, model)
        .put(JSON_IDENTITY_PUBLIC_KEY, deviceIdentity.publicKey)
        .put(JSON_IDENTITY_KEY_TYPE, deviceIdentity.keyType)
        .put(JSON_ENROLLMENT_SECRET, enrollmentSecret)
        .put(JSON_ENROLLMENT_SIGNATURE, signature)
        .put(JSON_ENROLLMENT_NONCE, nonce)
        .put(JSON_CLIENT_VERSION, BuildConfig.VERSION_NAME)
        .put(JSON_REQUEST_KEYS, requestKeys)
        .put(JSON_SOCKS_LISTEN, DEFAULT_AWG_INTERNAL_SOCKS_LISTEN)
        .put(JSON_AWG_RU_SOCKS_LISTEN, DEFAULT_AWG_RU_INTERNAL_SOCKS_LISTEN)
        .put(JSON_MTU, DEFAULT_MTU)
    val response = JSONObject(Transport.deviceEnroll(request.toString()))
    if (!response.optBoolean(JSON_OK, false)) {
        throw IllegalStateException(response.optString(JSON_ERROR))
    }
    return response
}

private fun postEnrollmentApproved(
    context: Context,
    mainHandler: Handler,
    noiseIdentity: StoredIdentity,
    deviceIdentity: StoredDeviceIdentity,
    deviceID: String,
    androidID: String,
    model: String,
    response: JSONObject,
) {
    val message = if (
        response.optBoolean(JSON_CONFIG_STORED, false) ||
        response.optString(JSON_INTERNAL_IP).isNotBlank()
    ) {
        response.optString(JSON_MESSAGE)
    } else {
        ""
    }
    val preferredTransport = response.preferredTransportChoice()
    postEnrollmentBaseState(
        mainHandler = mainHandler,
        noiseIdentity = noiseIdentity,
        deviceIdentity = deviceIdentity,
        deviceID = deviceID,
        androidID = androidID,
        model = model,
        statusTextRes = R.string.enrollment_status_approved,
        authorized = true,
        alias = response.optString(JSON_ALIAS),
        message = message,
        internalIP = response.optString(JSON_INTERNAL_IP),
        endpoint = response.optString(JSON_ENDPOINT),
        socksListen = response.optString(JSON_SOCKS_LISTEN),
        awgRu = response.optJSONObject(JSON_AWG_RU)?.toAwgUiConfig(),
        reality = response.optJSONObject(JSON_REALITY)?.toRealityUiConfig(),
        reality2 = response.optJSONObject(JSON_REALITY2)?.toRealityUiConfig(),
    )
    if (preferredTransport != null) {
        mainHandler.post {
            val previous = TransportRuntime.selectedTransport
            if (previous != TransportChoice.AUTO && preferredTransport != previous) {
                Log.i(TAG, "server preferred transport $preferredTransport ignored while manual $previous is selected")
                return@post
            }
            if (
                preferredTransport == TransportChoice.AWG_RU &&
                TransportRuntime.auth.awgRu?.isComplete() != true
            ) {
                if (previous == TransportChoice.AWG_RU) {
                    TransportRuntime.selectedTransport = TransportChoice.AUTO
                }
                Log.w(TAG, "приоритет AWG-RU отложен: набор AWG-RU неполный")
                return@post
            }
            if (
                preferredTransport == TransportChoice.REALITY &&
                TransportRuntime.auth.reality?.isComplete() != true
            ) {
                if (previous == TransportChoice.REALITY) {
                    TransportRuntime.selectedTransport = TransportChoice.AUTO
                }
                Log.w(TAG, "приоритет REALITY отложен: набор REALITY неполный")
                return@post
            }
            if (
                preferredTransport == TransportChoice.REALITY2 &&
                TransportRuntime.auth.reality2?.isComplete() != true
            ) {
                if (previous == TransportChoice.REALITY2) {
                    TransportRuntime.selectedTransport = TransportChoice.AUTO
                }
                Log.w(TAG, "приоритет REALITY2 отложен: набор REALITY2 неполный")
                return@post
            }
            TransportRuntime.selectedTransport = preferredTransport
            if (
                previous != preferredTransport &&
                TransportRuntime.auth.authorized &&
                isTransportRunningForToggle(TransportRuntime.state)
            ) {
                startSelectedTransport(context.applicationContext)
            }
        }
    }
}

private fun postEnrollmentBaseState(
    mainHandler: Handler,
    noiseIdentity: StoredIdentity,
    deviceIdentity: StoredDeviceIdentity,
    deviceID: String,
    androidID: String,
    model: String,
    statusTextRes: Int,
    authorized: Boolean,
    alias: String = "",
    message: String = "",
    internalIP: String = "",
    endpoint: String = "",
    socksListen: String = "",
    awgRu: AwgUiConfig? = null,
    reality: RealityUiConfig? = null,
    reality2: RealityUiConfig? = null,
) {
    mainHandler.post {
        val current = TransportRuntime.auth
        val effectiveInternalIP = if (authorized) internalIP.ifBlank { current.internalIP } else internalIP
        val effectiveEndpoint = if (authorized) endpoint.ifBlank { current.endpoint } else endpoint
        val effectiveSOCKS = if (authorized) socksListen.ifBlank { current.provisionedSOCKS } else socksListen
        val effectiveAWGRU = if (authorized) awgRu ?: current.awgRu else awgRu
        val effectiveReality = if (authorized) reality ?: current.reality else reality
        val effectiveReality2 = if (authorized) reality2 ?: current.reality2 else reality2
        TransportRuntime.auth = AuthUiState(
            authorized = authorized,
            inProgress = !authorized,
            statusTextRes = statusTextRes,
            errorTextRes = null,
            keystoreTextRes = if (deviceIdentity.strongBoxBacked) {
                R.string.keystore_status_strongbox
            } else {
                R.string.keystore_status_tee
            },
            deviceIdentityPublicSuffix = deviceIdentity.publicKey.takeLast(KEY_SUFFIX_LENGTH),
            noiseIdentityPublicSuffix = noiseIdentity.publicKey.takeLast(KEY_SUFFIX_LENGTH),
            deviceID = deviceID,
            androidID = androidID,
            model = model,
            alias = alias,
            message = message,
            internalIP = effectiveInternalIP,
            endpoint = effectiveEndpoint,
            provisionedSOCKS = effectiveSOCKS,
            awgRu = effectiveAWGRU,
            reality = effectiveReality,
            reality2 = effectiveReality2,
        )
        if (authorized && effectiveSOCKS.isNotBlank()) {
            TransportRuntime.state = TransportRuntime.state.copy(socksListen = DEFAULT_ROUTER_SOCKS_LISTEN)
        }
    }
}

private fun postEnrollmentFailure(mainHandler: Handler, errorRes: Int) {
    mainHandler.post {
        TransportRuntime.auth = TransportRuntime.auth.copy(
            authorized = false,
            inProgress = false,
            statusTextRes = R.string.enrollment_status_error,
            errorTextRes = errorRes,
        )
    }
}

private fun deviceEnrollmentCanonicalPayload(
    deviceID: String,
    androidID: String,
    model: String,
    identityKeyType: String,
    identityPubKey: String,
    nonce: String,
): String = listOf(
    DEVICE_ENROLLMENT_SIGNATURE_DOMAIN,
    deviceID,
    androidID,
    model,
    identityKeyType,
    identityPubKey,
    nonce,
).joinToString("\n")

private fun randomNonce(): String {
    val bytes = ByteArray(ENROLLMENT_NONCE_BYTES)
    SecureRandom().nextBytes(bytes)
    return Base64.encodeToString(bytes, Base64.NO_WRAP)
}

private fun deviceModel(): String =
    listOf(Build.MANUFACTURER, Build.MODEL)
        .joinToString(" ")
        .trim()
        .ifBlank { Build.DEVICE }

private fun requestForegroundResync(context: Context) {
    if (!TransportLifecycleStore.shouldKeepAlive(context)) return
    if (!TransportRuntime.auth.authorized && !isTransportRunningForToggle(TransportRuntime.state)) return
    val intent = Intent(context, AutoTransportService::class.java)
        .setAction(AutoTransportService.ACTION_RESYNC)
        .putExtra(AutoTransportService.EXTRA_MODE, TransportLifecycleStore.preferredMode(context).name)
    if (Build.VERSION.SDK_INT >= 26) {
        context.startForegroundService(intent)
    } else {
        context.startService(intent)
    }
}

fun recoverStoredTransportKeys(context: Context) {
    val appContext = context.applicationContext
    if (!TransportLifecycleStore.shouldKeepAlive(appContext)) return
    TransportRuntime.selectedTransport = TransportLifecycleStore.preferredMode(appContext)
    TRANSPORT_KEEP_ALIVE.set(true)
    FORCE_KEY_REQUEST.set(true)
    startDeviceEnrollment(appContext)
}

private fun startTransport(context: Context) {
    val intent = Intent(context, TransportService::class.java).setAction(TransportService.ACTION_START)
    if (BuildConfig.DEBUG) {
        TransportRuntime.debugClockSkewSeconds?.let {
            intent.putExtra(TransportService.EXTRA_FAKE_CLOCK_SKEW_SECONDS, it)
        }
    }
    if (Build.VERSION.SDK_INT >= 26) {
        context.startForegroundService(intent)
    } else {
        context.startService(intent)
    }
}

private fun startRealityTransport(context: Context) {
    stopTransport(context)
    val intent = Intent(context, RealityService::class.java).setAction(RealityService.ACTION_START)
    if (Build.VERSION.SDK_INT >= 26) {
        context.startForegroundService(intent)
    } else {
        context.startService(intent)
    }
}

private fun startSelectedTransport(context: Context) {
    TRANSPORT_KEEP_ALIVE.set(true)
    TransportLifecycleStore.rememberActiveTransport(context.applicationContext, TransportRuntime.selectedTransport)
    val intent = Intent(context, AutoTransportService::class.java)
        .setAction(AutoTransportService.ACTION_START)
        .putExtra(AutoTransportService.EXTRA_MODE, TransportRuntime.selectedTransport.name)
    if (Build.VERSION.SDK_INT >= 26) {
        context.startForegroundService(intent)
    } else {
        context.startService(intent)
    }
}

private fun stopTransport(context: Context) {
    context.startService(
        Intent(context, TransportService::class.java).setAction(TransportService.ACTION_STOP),
    )
}

private fun stopRealityTransport(context: Context) {
    context.startService(
        Intent(context, RealityService::class.java).setAction(RealityService.ACTION_STOP),
    )
}

private fun stopAllTransports(context: Context, keepAlive: Boolean = false) {
    if (!keepAlive) {
        TRANSPORT_KEEP_ALIVE.set(false)
        FORCE_KEY_REQUEST.set(false)
        CONNECT_IN_PROGRESS = false
        TransportLifecycleStore.rememberStopped(context)
    }
    context.startService(
        Intent(context, AutoTransportService::class.java)
            .setAction(AutoTransportService.ACTION_STOP)
            .putExtra(AutoTransportService.EXTRA_KEEP_ALIVE_AFTER_STOP, keepAlive),
    )
    stopTransport(context)
    stopRealityTransport(context)
}

private fun sleepEnrollment(durationMs: Long) {
    var remainingMs = durationMs
    while (ENROLLMENT_ACTIVE.get() && remainingMs > 0L && !FORCE_KEY_REQUEST.get()) {
        val sliceMs = remainingMs.coerceAtMost(ENROLLMENT_SLEEP_SLICE_MS)
        Thread.sleep(sliceMs)
        remainingMs -= sliceMs
    }
}

private fun openTelegramProxy(context: Context, socksListen: String) {
    val listen = socksListen.ifBlank { DEFAULT_SOCKS_LISTEN }
    val host = listen.substringBefore(":", DEFAULT_SOCKS_HOST).ifBlank { DEFAULT_SOCKS_HOST }
    val port = listen.substringAfterLast(":", DEFAULT_SOCKS_PORT)
        .takeIf { it.toIntOrNull() != null }
        ?: DEFAULT_SOCKS_PORT
    val uri = Uri.Builder()
        .scheme(TELEGRAM_SCHEME)
        .authority(TELEGRAM_SOCKS_AUTHORITY)
        .appendQueryParameter(TELEGRAM_SERVER_PARAM, host)
        .appendQueryParameter(TELEGRAM_PORT_PARAM, port)
        .build()
    val intent = Intent(Intent.ACTION_VIEW, uri)
        .setPackage(TELEGRAM_PACKAGE)
        .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
    try {
        context.startActivity(intent)
    } catch (_: ActivityNotFoundException) {
        Toast.makeText(context, R.string.telegram_not_found, Toast.LENGTH_LONG).show()
    }
}

private fun activeSocks(transport: TransportUiState, auth: AuthUiState): String =
    transport.socksListen.ifBlank {
        if (auth.authorized) {
            DEFAULT_ROUTER_SOCKS_LISTEN
        } else {
            auth.provisionedSOCKS
        }
    }

private fun JSONObject.toAwgUiConfig(): AwgUiConfig =
    AwgUiConfig(
        internalIP = optString(JSON_INTERNAL_IP),
        endpoint = optString(JSON_ENDPOINT),
        serverPublicKey = optString(JSON_SERVER_PUBLIC_KEY),
    )

private fun JSONObject.toRealityUiConfig(): RealityUiConfig =
    RealityUiConfig(
        transport = optString(JSON_REALITY_TRANSPORT),
        address = optString(JSON_REALITY_ADDRESS),
        ip = optString(JSON_REALITY_IP),
        port = optInt(JSON_REALITY_PORT, 0),
        uuid = optString(JSON_REALITY_UUID),
        email = optString(JSON_REALITY_EMAIL),
        flow = optString(JSON_REALITY_FLOW),
        security = optString(JSON_REALITY_SECURITY),
        network = optString(JSON_REALITY_NETWORK),
        serverName = optString(JSON_REALITY_SERVER_NAME),
        publicKey = optString(JSON_REALITY_PUBLIC_KEY),
        shortId = optString(JSON_REALITY_SHORT_ID),
        fingerprint = optString(JSON_REALITY_FINGERPRINT),
        spiderX = optString(JSON_REALITY_SPIDER_X),
        dest = optString(JSON_REALITY_DEST),
    )

private fun JSONObject.preferredTransportChoice(): TransportChoice? {
    val raw = optString(JSON_PREFERRED_TRANSPORT).ifBlank {
        optString(JSON_TRANSPORT_PRIORITY)
    }
    return when (raw.uppercase(Locale.ROOT)) {
        "AUTO", "АВТО" -> TransportChoice.AUTO
        "AWG_RU", "AWGRU", "AWG-RU" -> TransportChoice.AWG_RU
        "AWG" -> TransportChoice.AWG
        "REALITY" -> TransportChoice.REALITY
        "REALITY2", "REALITY-2" -> TransportChoice.REALITY2
        else -> null
    }
}

internal fun supportForPackage(packageName: String): ProxySupport =
    when {
        packageName == TELEGRAM_PACKAGE -> ProxySupport.AUTO_TELEGRAM
        packageName in MANUAL_PROXY_PACKAGES -> ProxySupport.MANUAL_PROXY
        else -> ProxySupport.UNSUPPORTED
    }

internal fun supportOrder(support: ProxySupport): Int =
    when (support) {
        ProxySupport.AUTO_TELEGRAM -> 0
        ProxySupport.MANUAL_PROXY -> 1
        ProxySupport.UNSUPPORTED -> 2
    }

private val ENROLLMENT_EXECUTOR = Executors.newSingleThreadExecutor()
private val ENROLLMENT_ACTIVE = AtomicBoolean(false)
private val FORCE_KEY_REQUEST = AtomicBoolean(false)
private val TRANSPORT_KEEP_ALIVE = AtomicBoolean(false)
private val STARTUP_AUTOCONNECT_REQUESTED = AtomicBoolean(false)
private var CONNECT_IN_PROGRESS by mutableStateOf(false)
private var SHOW_SETTINGS_SCREEN by mutableStateOf(false)
private var PUBLIC_BOOTSTRAP_IMPORTED by mutableStateOf(false)
private var PUBLIC_BOOTSTRAP_ERROR by mutableStateOf<String?>(null)
private var PENDING_EXTERNAL_BOOTSTRAP by mutableStateOf<PendingExternalBootstrap?>(null)
private var ATTENTION_REFRESH_TICK by mutableLongStateOf(0L)

private val MANUAL_PROXY_PACKAGES = setOf(
    "org.thunderdog.challegram",
    "org.telegram.plus",
    "org.telegram.messenger.web",
    "org.mozilla.firefox",
    "org.mozilla.fenix",
    "org.torproject.torbrowser",
)

private val PROVISION_ADDR: String get() = DeploymentConfig.PROVISION_ADDR
private val PROVISION_SERVER_PUBLIC: String get() = DeploymentConfig.PROVISION_SERVER_PUBLIC
private val SERVER_AWG_PUBLIC: String get() = DeploymentConfig.SERVER_AWG_PUBLIC
private val SERVER_AWG_RU_PUBLIC: String get() = DeploymentConfig.SERVER_AWG_RU_PUBLIC
private const val DEFAULT_SOCKS_HOST = "127.0.0.1"
private const val DEFAULT_SOCKS_PORT = "18080"
private const val DEFAULT_SOCKS_LISTEN = "$DEFAULT_SOCKS_HOST:$DEFAULT_SOCKS_PORT"
private const val DEFAULT_ROUTER_SOCKS_LISTEN = DEFAULT_SOCKS_LISTEN
private const val DEFAULT_AWG_INTERNAL_SOCKS_LISTEN = "127.0.0.1:18082"
private const val DEFAULT_AWG_RU_INTERNAL_SOCKS_LISTEN = "127.0.0.1:18084"
private const val DEFAULT_MTU = 1420
private const val TRANSPORT_LABEL_AWG_RU = "awg-ru"
private const val TRANSPORT_LABEL_AWG = "AWG"
private const val TRANSPORT_LABEL_REALITY = "REALITY"
private const val TRANSPORT_LABEL_REALITY2 = "REALITY2"
private const val PRIVATE_FLAVOR_NAME = "private"
private const val KEY_SUFFIX_LENGTH = 8
private const val MAX_UNSUPPORTED_APPS_SHOWN = 80
private const val PENDING_POLL_INTERVAL_MS = 5_000L
private const val APPROVED_POLL_INTERVAL_MS = 7_000L
private const val APPROVED_RUNNING_POLL_INTERVAL_MS = 45_000L
private const val APPROVED_RECOVERY_CHECK_INTERVAL_MS = 1_000L
private const val BLOCKED_POLL_INTERVAL_MS = 10_000L
private const val AUTO_RECOVERY_GRACE_MS = 12_000L
private const val AUTO_RECOVERY_MIN_KEY_REQUEST_INTERVAL_MS = 45_000L
private const val AUTO_RECOVERY_MAX_KEY_REQUEST_INTERVAL_MS = 5 * 60 * 1000L
private const val ENROLLMENT_SLEEP_SLICE_MS = 1_000L
private const val PUBLIC_PLATFORM_PREFS = "public_platform"
private const val KEY_PUBLIC_BOOTSTRAP_RAW = "bootstrap_raw"
private const val EXTRA_PUBLIC_BOOTSTRAP_PAYLOAD = "bootstrap_payload"
private const val PUBLIC_ENROLL_TIMEOUT_SECONDS = 35L
private const val CONNECT_TIMEOUT_MS = 60_000L
private const val ENROLLMENT_NONCE_BYTES = 24
private const val DEVICE_ENROLLMENT_SIGNATURE_DOMAIN = "TrafficWrapper device enrollment v1"
private const val LIMIT_TEXT_MARKER = "Лимит"

private const val TELEGRAM_SCHEME = "tg"
private const val TELEGRAM_SOCKS_AUTHORITY = "socks"
private const val TELEGRAM_SERVER_PARAM = "server"
private const val TELEGRAM_PORT_PARAM = "port"

private const val JSON_OK = "ok"
private const val JSON_PROVISION_ADDR = "provision_addr"
private const val JSON_PROVISION_SERVER_PUBLIC = "provision_server_public"
private const val JSON_EXPECTED_SERVER_AWG_PUBLIC = "expected_server_awg_public"
private const val JSON_REQUIRE_EXPECTED_AWG_PUBLIC = "require_expected_awg_public"
private const val JSON_EXPECTED_SERVER_AWG_RU_PUBLIC = "expected_server_awg_ru_public"
private const val JSON_REQUIRE_EXPECTED_AWG_RU_PUBLIC = "require_expected_awg_ru_public"
private const val JSON_ERROR = "error"
private const val JSON_STATUS = "status"
private const val JSON_ALIAS = "alias"
private const val JSON_MESSAGE = "message"
private const val JSON_CONFIG_STORED = "config_stored"
private const val JSON_NOISE_PRIVATE_KEY = "noise_private_key"
private const val JSON_NOISE_PUBLIC_KEY = "noise_public_key"
private const val JSON_DEVICE_ID = "device_id"
private const val JSON_ANDROID_ID = "android_id"
private const val JSON_MODEL = "model"
private const val JSON_IDENTITY_PUBLIC_KEY = "identity_pubkey"
private const val JSON_IDENTITY_KEY_TYPE = "identity_key_type"
private const val JSON_ENROLLMENT_SECRET = "enrollment_secret"
private const val JSON_ENROLLMENT_SIGNATURE = "enrollment_signature"
private const val JSON_ENROLLMENT_NONCE = "enrollment_nonce"
private const val JSON_CLIENT_VERSION = "client_version"
private const val JSON_REQUEST_KEYS = "request_keys"
private const val JSON_SOCKS_LISTEN = "socks_listen"
private const val JSON_AWG_RU_SOCKS_LISTEN = "awg_ru_socks_listen"
private const val JSON_MTU = "mtu"
private const val JSON_INTERNAL_IP = "internal_ip"
private const val JSON_ENDPOINT = "endpoint"
private const val JSON_SERVER_PUBLIC_KEY = "server_public_key"
private const val JSON_AWG_RU = "awg_ru"
private const val JSON_AWG = "awg"
private const val JSON_REALITY = "reality"
private const val JSON_REALITY2 = "reality2"
private const val JSON_PREFERRED_TRANSPORT = "preferred_transport"
private const val JSON_TRANSPORT_PRIORITY = "transport_priority"
private const val JSON_REALITY_TRANSPORT = "transport"
private const val JSON_REALITY_ADDRESS = "address"
private const val JSON_REALITY_IP = "ip"
private const val JSON_REALITY_PORT = "port"
private const val JSON_REALITY_UUID = "uuid"
private const val JSON_REALITY_EMAIL = "email"
private const val JSON_REALITY_FLOW = "flow"
private const val JSON_REALITY_SECURITY = "security"
private const val JSON_REALITY_NETWORK = "network"
private const val JSON_REALITY_SERVER_NAME = "serverName"
private const val JSON_REALITY_PUBLIC_KEY = "publicKey"
private const val JSON_REALITY_SHORT_ID = "shortId"
private const val JSON_REALITY_FINGERPRINT = "fingerprint"
private const val JSON_REALITY_SPIDER_X = "spiderX"
private const val JSON_REALITY_DEST = "dest"
private const val JSON_PUBLIC_ORCHESTRATOR_URL = "orchestrator_url"
private const val JSON_PUBLIC_ORCH_NOISE_PUBLIC = "orch_noise_public"
private const val JSON_PUBLIC_BOOTSTRAP_TOKEN = "bootstrap_token"
private const val JSON_PUBLIC_CLIENT_BUNDLE = "client_bundle"
private const val JSON_PUBLIC_CONFIG_JSON = "config_json"
private const val JSON_PUBLIC_REALITY_UUID = "reality_uuid"
private const val JSON_PUBLIC_PSK2 = "psk2"
private const val JSON_PUBLIC_SERVER_AWG_PUBLIC = "server_awg_public"
private const val JSON_PUBLIC_AWG_PRIVATE_KEY = "awg_private_key"
private const val JSON_PUBLIC_AWG_PUBLIC_KEY = "awg_public_key"
private const val JSON_PUBLIC_KEY_SNAKE = "public_key"
private const val JSON_TIMEOUT_SECONDS = "timeout_seconds"
private const val DEVICE_STATUS_PENDING = "pending"
private const val DEVICE_STATUS_APPROVED = "approved"
private const val DEVICE_STATUS_BLOCKED = "blocked"
private const val TAG = "TWClient"
