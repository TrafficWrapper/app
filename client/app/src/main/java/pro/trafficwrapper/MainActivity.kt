package pro.trafficwrapper

import android.Manifest
import android.app.Activity
import android.app.AlarmManager
import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.PersistableBundle
import android.os.SystemClock
import android.provider.Settings
import android.util.Base64
import android.util.Log
import android.view.WindowManager
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
import androidx.compose.material3.Checkbox
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
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
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.LocalLifecycleOwner
import org.json.JSONArray
import org.json.JSONObject
import pro.trafficwrapper.go.transport.Transport
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import java.security.SecureRandom
import java.util.Locale
import java.net.URI
import java.net.URLDecoder
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

/** Debug-only launch extra that fakes a clock skew for the clock diagnostics. */
private const val EXTRA_FAKE_CLOCK_SKEW_SECONDS = "pro.trafficwrapper.extra.FAKE_CLOCK_SKEW_SECONDS"

class MainActivity : ComponentActivity() {
    private val mainHandler = Handler(Looper.getMainLooper())
    private val appListExecutor = Executors.newSingleThreadExecutor()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // APP-L15: a recreated activity (rotation, process restore) or a relaunch from recents must
        // not replay the launch intent (bootstrap dialog, battery hint) once more.
        val handleLaunchIntent = shouldHandleLaunchIntent(
            hasSavedInstanceState = savedInstanceState != null,
            intentFlags = intent?.flags ?: 0,
        )
        if (BuildConfig.DEBUG && handleLaunchIntent) {
            readIntentExtrasSafely {
                if (intent.hasExtra(EXTRA_FAKE_CLOCK_SKEW_SECONDS)) {
                    TransportRuntime.debugClockSkewSeconds =
                        intent.getLongExtra(EXTRA_FAKE_CLOCK_SKEW_SECONDS, 0L)
                }
            }
        }
        requestNotificationPermission()
        if (DeploymentConfig.IS_PUBLIC_PLATFORM) {
            // Decrypting the sealed state (Keystore/StrongBox), minisign verification and the Go
            // core apply are slow, so they run on the public-state executor; the UI shows a
            // loading placeholder until the result is applied on the main thread. Intents queued
            // below run on the same single-thread executor, i.e. strictly after the restore.
            // APP-L15: the restore runs once per process; runtime state outlives the activity.
            if (PUBLIC_STARTUP_RESTORE_REQUESTED.compareAndSet(false, true)) {
                startPublicStartupRestore(applicationContext)
            }
            if (handleLaunchIntent) {
                handlePublicBootstrapIntent(intent)
                handlePublicDeepLinkIntent(intent)
            }
        } else {
            requestStartupAutoconnect(applicationContext)
        }
        refreshAttentionState(applicationContext)
        setContent {
            TrafficWrapperApp()
        }
        if (handleLaunchIntent) {
            handleBatteryHintIntent(intent)
        }
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
        VpnAutoRestore.maybeRestoreWithTransport(applicationContext, "activity_resume")
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        // A new intent is a fresh delivery (not a replay), so it is always handled.
        handleBatteryHintIntent(intent)
        handlePublicBootstrapIntent(intent)
        handlePublicDeepLinkIntent(intent)
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
        // APP-L16: a public enrollment task owns the flag and clears it when it ends; only the
        // private flavor's activity-scoped polling loop is stopped here.
        if (resetEnrollmentFlagOnActivityDestroy(DeploymentConfig.IS_PUBLIC_PLATFORM)) {
            ENROLLMENT_ACTIVE.set(false)
        }
        appListExecutor.shutdownNow()
        super.onDestroy()
    }

    private fun requestNotificationPermission() {
        if (Build.VERSION.SDK_INT >= 33 &&
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            markNotificationPermissionRequested(this)
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
        // APP-L17: only this app's own notification (through the non-exported alias) opens it.
        if (isTrustedBatteryHintIntent(intent?.action, intent?.component?.className)) {
            openBatteryRestrictionFlow(this)
        }
    }

    private fun handlePublicBootstrapIntent(intent: Intent?) {
        if (!DeploymentConfig.IS_PUBLIC_PLATFORM || intent == null) return
        // APP-L17: only the expected SEND/VIEW deliveries, and extras from another app are read
        // defensively (an unknown Parcelable must not crash the process together with the VPN).
        if (externalBootstrapExtra(intent.action, intent.type) == ExternalBootstrapExtra.NONE) return
        val raw = readIntentExtrasSafely {
            intent.getStringExtra(EXTRA_PUBLIC_BOOTSTRAP_PAYLOAD)
                ?: if (intent.action == Intent.ACTION_SEND) intent.getStringExtra(Intent.EXTRA_TEXT) else null
        } ?: return
        if (raw.isBlank()) return
        handleExternalBootstrap(applicationContext, raw)
    }

    private fun handlePublicDeepLinkIntent(intent: Intent?) {
        if (!DeploymentConfig.IS_PUBLIC_PLATFORM || intent == null) return
        if (externalBootstrapExtra(intent.action, intent.type) != ExternalBootstrapExtra.VIEW) return
        val raw = publicEnrollDeepLinkBootstrap(readIntentExtrasSafely { intent.dataString }) ?: return
        handleExternalBootstrap(applicationContext, raw)
    }
}

internal fun publicEnrollDeepLinkBootstrap(uriText: String?): String? {
    val uri = runCatching { URI(uriText?.trim().orEmpty()) }.getOrNull() ?: return null
    if (!uri.scheme.equals("twp", ignoreCase = true) || !uri.host.equals("enroll", ignoreCase = true)) {
        return null
    }
    val params = parseQueryParams(uri.rawQuery.orEmpty())
    return params["bootstrap"]?.takeIf { it.isNotBlank() }
        ?: params["payload"]?.takeIf { it.isNotBlank() }
}

private fun parseQueryParams(rawQuery: String): Map<String, String> {
    if (rawQuery.isBlank()) return emptyMap()
    return rawQuery.split('&').mapNotNull { part ->
        val key = part.substringBefore('=', "").takeIf { it.isNotBlank() } ?: return@mapNotNull null
        val value = part.substringAfter('=', "")
        urlDecode(key) to urlDecode(value)
    }.toMap()
}

private fun urlDecode(value: String): String =
    URLDecoder.decode(value.replace("+", "%2B"), Charsets.UTF_8.name())

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
                if (DeploymentConfig.IS_PUBLIC_PLATFORM && PUBLIC_STATE_LOADING) {
                    PublicStateLoadingScreen()
                } else if (DeploymentConfig.IS_PUBLIC_PLATFORM && !PUBLIC_BOOTSTRAP_IMPORTED) {
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
                    PublicBootstrapPendingScreen(context = context, auth = auth)
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
                    PENDING_EXTERNAL_BOOTSTRAP = null
                    importPublicBootstrap(context, pending.raw)
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
    // APP-L13: replacing pins/keys takes a second, explicit step.
    var keyStep by remember(pending) { mutableStateOf(false) }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = {
            Text(
                text = stringResource(
                    if (keyStep) R.string.public_bootstrap_external_keys_title else R.string.public_bootstrap_external_title,
                ),
            )
        },
        text = {
            // APP-L13: a confirmation must not be tapped through an overlay window.
            FilterTouchesWhenObscured()
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                if (keyStep) {
                    Text(
                        text = stringResource(R.string.public_bootstrap_external_keys_warning),
                        color = MaterialTheme.colorScheme.error,
                    )
                    pending.changes.filter { it.keyMaterial }.forEach { change -> BootstrapChangeRow(change) }
                    return@Column
                }
                Text(text = stringResource(R.string.public_bootstrap_external_body))
                if (pending.replacesExisting) {
                    Text(
                        text = stringResource(
                            R.string.public_bootstrap_external_replace_warning,
                            pending.currentOrchestratorUrl.ifBlank { stringResource(R.string.value_empty) },
                            pending.orchestratorUrl,
                        ),
                        color = MaterialTheme.colorScheme.error,
                    )
                    if (pending.changes.isNotEmpty()) {
                        Text(text = stringResource(R.string.public_bootstrap_external_changes_title))
                        pending.changes.forEach { change -> BootstrapChangeRow(change) }
                    }
                }
                Text(text = "orchestrator_url: ${pending.orchestratorUrl}")
                Text(text = "config_pubkey_pin: ${pending.configPubkeyPin}")
                Text(text = "orch_noise_public: ${pending.orchNoisePublic}")
                if (pending.updatePubkey.isNotBlank()) {
                    Text(text = "update_pubkey: ${pending.updatePubkey}")
                }
            }
        },
        confirmButton = {
            TextButton(
                onClick = {
                    if (pending.needsKeyConfirmation && !keyStep) keyStep = true else onConfirm()
                },
            ) {
                Text(
                    text = stringResource(
                        when {
                            keyStep -> R.string.public_bootstrap_external_keys_confirm
                            pending.needsKeyConfirmation -> R.string.public_bootstrap_external_continue
                            else -> R.string.public_bootstrap_external_confirm
                        },
                    ),
                )
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
private fun BootstrapChangeRow(change: BootstrapFieldChange) {
    Text(
        text = stringResource(
            R.string.public_bootstrap_external_change_row,
            change.field,
            change.current.ifBlank { stringResource(R.string.value_empty) },
            change.incoming.ifBlank { stringResource(R.string.value_empty) },
        ),
        style = MaterialTheme.typography.bodySmall,
        color = if (change.keyMaterial) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurface,
    )
}

/** Drops touches that reach the hosting window through another app's overlay (tapjacking). */
@Composable
private fun FilterTouchesWhenObscured() {
    val view = LocalView.current
    androidx.compose.runtime.DisposableEffect(view) {
        val previous = view.filterTouchesWhenObscured
        view.filterTouchesWhenObscured = true
        onDispose { view.filterTouchesWhenObscured = previous }
    }
}

/** Keeps the window out of screenshots and the recents preview while shown (APP-L20). */
@Composable
private fun SecureWindowWhileShown() {
    val activity = LocalContext.current as? Activity ?: return
    androidx.compose.runtime.DisposableEffect(activity) {
        activity.window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        onDispose { activity.window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE) }
    }
}

@Composable
private fun PublicStateLoadingScreen() {
    Column(
        modifier = Modifier.fillMaxWidth(),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        AppHeader()
        CircularProgressIndicator(modifier = Modifier.size(24.dp))
    }
}

@Composable
private fun PublicBootstrapPendingScreen(context: Context, auth: AuthUiState) {
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
                    text = stringResource(auth.statusTextRes),
                    style = MaterialTheme.typography.titleLarge,
                    fontWeight = FontWeight.Bold,
                )
                auth.errorTextRes?.let { errorTextRes ->
                    Text(
                        text = stringResource(errorTextRes),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.error,
                    )
                } ?: Text(
                    text = stringResource(R.string.public_bootstrap_pending_body),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                if (auth.inProgress) {
                    CircularProgressIndicator(modifier = Modifier.size(24.dp))
                }
                if (auth.enrollmentRetryAllowed && !auth.inProgress) {
                    Button(
                        onClick = {
                            withPublicBootstrapRaw(context) { bootstrapRaw ->
                                retryPublicEnrollmentIfAllowed(
                                    auth = TransportRuntime.auth,
                                    bootstrapRaw = bootstrapRaw,
                                ) { raw -> startPublicDeviceEnrollment(context.applicationContext, raw) }
                            }
                        },
                    ) {
                        Text(text = stringResource(R.string.public_enrollment_retry))
                    }
                }
                if (showImportAnotherBootstrap(auth)) {
                    // APP-M13: a used-up or wrong bootstrap is not a dead end.
                    OutlinedButton(
                        onClick = {
                            discardPendingPublicBootstrap(context) { enrolled ->
                                PUBLIC_BOOTSTRAP_ERROR = null
                                if (enrolled) {
                                    // Back to the platform this device is enrolled with.
                                    restorePublicPlatformStateAsync(context) { restored ->
                                        if (!restored) PUBLIC_BOOTSTRAP_IMPORTED = false
                                    }
                                } else {
                                    PUBLIC_BOOTSTRAP_IMPORTED = false
                                    TransportRuntime.auth = AuthUiState(
                                        statusTextRes = R.string.public_bootstrap_required,
                                    )
                                }
                            }
                        },
                    ) {
                        Text(text = stringResource(R.string.public_bootstrap_import_another))
                    }
                }
            }
        }
    }
}

@Composable
private fun PublicBootstrapScreen(context: Context) {
    // This screen is only shown when no bootstrap is stored (see PUBLIC_BOOTSTRAP_IMPORTED), so
    // there is nothing to prefill; avoid decrypting the secure store on the main thread.
    var input by remember { mutableStateOf("") }
    var showScanner by remember { mutableStateOf(false) }
    fun importBootstrap(raw: String) {
        try {
            PublicPlatformConfigParser.parseBootstrap(raw)
            input = raw
            importPublicBootstrap(context, raw)
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
        transport.carryingTransport.isBlank() &&
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
        auth = auth,
        transport = transport,
        selectedTransport = selectedTransport,
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
    if (BuildConfig.VPN_ENABLED) {
        MainVpnToggle(context = context, transport = transport)
    }
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
    auth: AuthUiState,
    transport: TransportUiState,
    selectedTransport: TransportChoice,
    connected: Boolean,
    connecting: Boolean,
    stableDurationText: String?,
) {
    val backgroundColor: Color
    val textColor: Color
    val titleRes: Int
    val detail: String
    val context = LocalContext.current
    val route = statusRouteForUi(transport, selectedTransport)
    val routeRegion = routeRegionForUi(route, TransportRuntime.publicPlatformRouteSlots.routeRegions)
    val traffic = rememberSessionTrafficSnapshot(connected, route)
    when {
        connected -> {
            backgroundColor = Color(0xFFE6F4EA)
            textColor = Color(0xFF14532D)
            titleRes = R.string.main_status_connected
            detail = connectedStatusDetail(
                label = displayTransportLabel(route),
                region = routeRegion,
                stableText = stringResource(R.string.main_status_connected_hint),
            )
        }
        connecting -> {
            backgroundColor = Color(0xFFFFF4D6)
            textColor = Color(0xFF6F4B00)
            titleRes = R.string.main_status_connecting
            detail = connectingStatusDetail(
                label = displayTransportLabel(route),
                region = routeRegion,
                fallback = stringResource(transport.stateTextRes),
                formatNoRegion = { context.getString(R.string.main_status_connecting_detail, it) },
                formatWithRegion = { label, region ->
                    context.getString(R.string.main_status_connecting_detail_region, label, region)
                },
            )
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
            if (connected) {
                Text(
                    text = stringResource(
                        R.string.main_status_traffic,
                        formatTrafficBytes(traffic.sessionRxBytes),
                        formatTrafficBytes(traffic.sessionTxBytes),
                    ),
                    modifier = Modifier.padding(top = 8.dp),
                    color = textColor,
                    style = MaterialTheme.typography.bodyMedium,
                    fontWeight = FontWeight.Medium,
                )
                Text(
                    text = stringResource(
                        R.string.main_status_speed,
                        formatTrafficSpeed(traffic.rxBytesPerSecond),
                        formatTrafficSpeed(traffic.txBytesPerSecond),
                    ),
                    modifier = Modifier.padding(top = 3.dp),
                    color = textColor,
                    style = MaterialTheme.typography.bodyMedium,
                )
                Text(
                    text = stringResource(
                        R.string.main_status_quality,
                        formatExchangeRecency(transport.lastExchangeAgeSeconds),
                    ),
                    modifier = Modifier.padding(top = 3.dp),
                    color = textColor,
                    style = MaterialTheme.typography.bodyMedium,
                )
                QuotaIndicator(
                    quota = auth.quota,
                    textColor = textColor,
                )
            }
        }
    }
}

@Composable
private fun QuotaIndicator(quota: QuotaUiState, textColor: Color) {
    if (!quota.hasTrafficLimit) return
    val limit = quota.limitBytes.coerceAtLeast(1L)
    val remaining = quota.remainingBytes?.coerceIn(0L, limit)
    if (remaining != null) {
        val usedFraction = 1f - (remaining.toFloat() / limit.toFloat()).coerceIn(0f, 1f)
        Text(
            text = stringResource(
                R.string.main_status_quota_remaining,
                formatTrafficBytes(remaining),
                formatTrafficBytes(limit),
            ),
            modifier = Modifier.padding(top = 8.dp),
            color = textColor,
            style = MaterialTheme.typography.bodyMedium,
            fontWeight = FontWeight.Medium,
        )
        LinearProgressIndicator(
            progress = { usedFraction },
            modifier = Modifier
                .fillMaxWidth()
                .padding(top = 4.dp),
            color = textColor,
        )
        return
    }
    Text(
        text = stringResource(
            R.string.main_status_quota_limit,
            formatTrafficBytes(limit),
            quota.rateLimit.ifBlank { stringResource(R.string.value_empty) },
            quota.expiresAt.ifBlank { stringResource(R.string.value_empty) },
        ),
        modifier = Modifier.padding(top = 8.dp),
        color = textColor,
        style = MaterialTheme.typography.bodyMedium,
    )
}

private data class SessionTrafficSnapshot(
    val sessionRxBytes: Long = 0L,
    val sessionTxBytes: Long = 0L,
    val rxBytesPerSecond: Long = 0L,
    val txBytesPerSecond: Long = 0L,
)

@Composable
private fun rememberSessionTrafficSnapshot(connected: Boolean, route: String): SessionTrafficSnapshot {
    var snapshot by remember { mutableStateOf(SessionTrafficSnapshot()) }
    LaunchedEffect(connected, route) {
        if (!connected) {
            snapshot = SessionTrafficSnapshot()
            return@LaunchedEffect
        }
        var baselineRx = TransportRuntime.state.rxBytes.coerceAtLeast(0L)
        var baselineTx = TransportRuntime.state.txBytes.coerceAtLeast(0L)
        var lastRx = baselineRx
        var lastTx = baselineTx
        var lastAtMs = SystemClock.elapsedRealtime()
        snapshot = SessionTrafficSnapshot()
        while (currentCoroutineContext().isActive) {
            delay(1000)
            val nowMs = SystemClock.elapsedRealtime()
            val state = TransportRuntime.state
            val rx = state.rxBytes.coerceAtLeast(0L)
            val tx = state.txBytes.coerceAtLeast(0L)
            if (rx < baselineRx || tx < baselineTx || rx < lastRx || tx < lastTx) {
                baselineRx = rx
                baselineTx = tx
                lastRx = rx
                lastTx = tx
                lastAtMs = nowMs
                snapshot = SessionTrafficSnapshot()
                continue
            }
            val elapsedMs = (nowMs - lastAtMs).coerceAtLeast(1L)
            snapshot = SessionTrafficSnapshot(
                sessionRxBytes = (rx - baselineRx).coerceAtLeast(0L),
                sessionTxBytes = (tx - baselineTx).coerceAtLeast(0L),
                rxBytesPerSecond = ((rx - lastRx).coerceAtLeast(0L) * 1000L) / elapsedMs,
                txBytesPerSecond = ((tx - lastTx).coerceAtLeast(0L) * 1000L) / elapsedMs,
            )
            lastRx = rx
            lastTx = tx
            lastAtMs = nowMs
        }
    }
    return snapshot
}

internal fun formatTrafficBytes(bytes: Long): String {
    val units = arrayOf("B", "KB", "MB", "GB", "TB")
    var value = bytes.coerceAtLeast(0L).toDouble()
    var unitIndex = 0
    while (value >= 1024.0 && unitIndex < units.lastIndex) {
        value /= 1024.0
        unitIndex += 1
    }
    return if (unitIndex == 0) {
        String.format(Locale.US, "%d %s", value.toLong(), units[unitIndex])
    } else {
        String.format(Locale.US, "%.1f %s", value, units[unitIndex])
    }
}

internal fun formatTrafficSpeed(bytesPerSecond: Long): String =
    "${formatTrafficBytes(bytesPerSecond)}/s"

internal fun formatExchangeRecency(seconds: Long?): String =
    when {
        seconds == null -> "exchange now"
        seconds <= 2L -> "exchange now"
        seconds < 60L -> "exchange ${seconds}s ago"
        else -> "exchange ${seconds / 60L}m ago"
    }

@Composable
private fun PrimaryTransportButton(
    context: Context,
    auth: AuthUiState,
    transportRunning: Boolean,
    connecting: Boolean,
) {
    Button(
        enabled = connecting || auth.authorized || transportRunning,
        onClick = {
            when (primaryTransportAction(connecting, transportRunning)) {
                PrimaryTransportAction.CANCEL_CONNECTING -> {
                    CONNECT_IN_PROGRESS = false
                    stopAllTransports(context.applicationContext)
                }
                PrimaryTransportAction.DISCONNECT -> stopAllTransports(context.applicationContext)
                PrimaryTransportAction.CONNECT -> connectSelectedTransport(context.applicationContext)
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

internal enum class PrimaryTransportAction {
    CANCEL_CONNECTING,
    DISCONNECT,
    CONNECT,
}

internal fun primaryTransportAction(connecting: Boolean, transportRunning: Boolean): PrimaryTransportAction =
    when {
        connecting -> PrimaryTransportAction.CANCEL_CONNECTING
        transportRunning -> PrimaryTransportAction.DISCONNECT
        else -> PrimaryTransportAction.CONNECT
    }

@Composable
private fun MainVpnToggle(context: Context, transport: TransportUiState) {
    if (!BuildConfig.VPN_ENABLED) return
    val appContext = context.applicationContext
    var vpnOn by remember { mutableStateOf(TransportLifecycleStore.vpnEnabled(appContext)) }
    var vpnMode by remember { mutableStateOf(TransportLifecycleStore.vpnMode(appContext)) }
    var allowedApps by remember { mutableStateOf(TransportLifecycleStore.vpnAllowedApps(appContext)) }
    LaunchedEffect(transport.vpnEnabled, transport.vpnActive) {
        vpnOn = TransportLifecycleStore.vpnEnabled(appContext)
        vpnMode = TransportLifecycleStore.vpnMode(appContext)
        allowedApps = TransportLifecycleStore.vpnAllowedApps(appContext)
    }
    val onToggle = rememberVpnToggleHandler(
        context = context,
        vpnMode = vpnMode,
        allowedApps = allowedApps,
        onPreferenceChanged = { enabled -> vpnOn = enabled },
    )
    Surface(
        modifier = Modifier
            .fillMaxWidth()
            .padding(top = 12.dp),
        shape = RoundedCornerShape(8.dp),
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant),
    ) {
        Row(
            modifier = Modifier.padding(horizontal = 16.dp, vertical = 12.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = stringResource(R.string.vpn_mode_title),
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold,
                )
                Text(
                    text = stringResource(if (vpnMode == VpnTrafficMode.FULL) R.string.vpn_scope_full else R.string.vpn_scope_split),
                    modifier = Modifier.padding(top = 2.dp),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Text(
                    text = stringResource(vpnStatusTextRes(transport)),
                    modifier = Modifier.padding(top = 2.dp),
                    style = MaterialTheme.typography.bodySmall,
                    color = vpnStatusColor(transport),
                )
            }
            Switch(checked = vpnOn, onCheckedChange = onToggle)
        }
    }
}

@Composable
private fun rememberVpnToggleHandler(
    context: Context,
    vpnMode: VpnTrafficMode,
    allowedApps: Set<String>,
    onPreferenceChanged: (Boolean) -> Unit,
): (Boolean) -> Unit {
    val appContext = context.applicationContext
    val permissionLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.StartActivityForResult(),
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            setVpnPreference(appContext, enabled = true, transition = VpnTransition.STARTING)
            onPreferenceChanged(true)
            startVpnModeService(appContext)
        } else {
            Toast.makeText(appContext, R.string.vpn_permission_denied, Toast.LENGTH_LONG).show()
            setVpnPreference(appContext, enabled = false)
            onPreferenceChanged(false)
        }
    }
    return onToggle@{ enabled ->
        if (enabled) {
            if (vpnMode == VpnTrafficMode.SPLIT && allowedApps.isEmpty()) {
                Toast.makeText(appContext, R.string.vpn_split_empty, Toast.LENGTH_LONG).show()
                setVpnPreference(appContext, enabled = false)
                onPreferenceChanged(false)
                return@onToggle
            }
            val prepareIntent = VpnService.prepare(context)
            if (prepareIntent != null) {
                permissionLauncher.launch(prepareIntent)
            } else {
                setVpnPreference(appContext, enabled = true, transition = VpnTransition.STARTING)
                onPreferenceChanged(true)
                startVpnModeService(appContext)
            }
        } else {
            setVpnPreference(appContext, enabled = false, transition = VpnTransition.STOPPING)
            onPreferenceChanged(false)
            stopVpnModeService(appContext)
        }
    }
}

@StringRes
private fun vpnStatusTextRes(transport: TransportUiState): Int =
    when (transport.vpnTransition) {
        VpnTransition.STARTING -> R.string.vpn_mode_starting
        VpnTransition.STOPPING -> R.string.vpn_mode_stopping
        VpnTransition.NONE -> if (transport.vpnActive) R.string.vpn_mode_active else R.string.vpn_mode_off
    }

@Composable
private fun vpnStatusColor(transport: TransportUiState): Color =
    when {
        transport.vpnTransition != VpnTransition.NONE -> Color(0xFF6F4B00)
        transport.vpnActive -> Color(0xFF14532D)
        else -> MaterialTheme.colorScheme.onSurfaceVariant
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
    val exactAlarmsOff = exactAlarmsDenied(context, attentionRefreshTick)
    val updateAvailable = updates.availableVersionCode > BuildConfig.VERSION_CODE.toLong()
    val updateBusy = updates.downloadInProgress || updates.installInProgress
    val updateError = updates.errorTextRes != null || updates.installErrorTextRes != null
    val showUpdateBanner = updateAvailable || updateBusy || (updateError && updates.availableVersionCode > 0)
    val installPermissionProblem = updates.installErrorTextRes == R.string.update_install_permission_required ||
        installPermissionNeeded(context)
    if (!showUpdateBanner && !batteryRestriction.restricted && !notificationsOff && !exactAlarmsOff &&
        !installPermissionProblem
    ) {
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
        if (exactAlarmsOff) {
            AttentionBanner(
                title = stringResource(R.string.attention_exact_alarms),
                action = stringResource(R.string.attention_allow_exact_alarms),
                onClick = { openExactAlarmSettings(context) },
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
    val region = transportChoiceRegion(choice, TransportRuntime.publicPlatformRouteSlots.routeRegions)
    val subtitle = transportModeCardSubtitle(detail = detail, region = region)
    Surface(
        modifier = modifier
            .height(if (subtitle == null) 64.dp else 82.dp)
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
            Column(
                modifier = Modifier.weight(1f),
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                Text(
                    text = stringResource(transportChoiceLabelRes(choice)),
                    fontWeight = FontWeight.SemiBold,
                    color = if (enabled) MaterialTheme.colorScheme.onSurface else MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    textAlign = TextAlign.Center,
                )
                subtitle?.let {
                    Text(
                        text = it,
                        modifier = Modifier.padding(top = 2.dp),
                        style = MaterialTheme.typography.bodySmall,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        textAlign = TextAlign.Center,
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
    val frontEndCredentials = remember {
        LocalSocksAuth.requiredFrontEndCredentials(context.applicationContext)
    }
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
            if (frontEndCredentials != null) {
                Text(
                    // APP-L20: the password is not shown on the main screen, only in the settings.
                    text = stringResource(
                        R.string.local_proxy_auth_apps_hint_settings,
                        frontEndCredentials.username,
                    ),
                    modifier = Modifier.padding(top = 6.dp),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
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
    var directUpdateFallbackOn by remember {
        mutableStateOf(TransportLifecycleStore.directUpdateFallbackEnabled(context.applicationContext))
    }
    var autoDownloadOn by remember {
        mutableStateOf(TransportLifecycleStore.autoDownloadUpdatesEnabled(context.applicationContext))
    }
    var autoDownloadWifiOn by remember {
        mutableStateOf(TransportLifecycleStore.autoDownloadWifiEnabled(context.applicationContext))
    }
    var autoDownloadMobileOn by remember {
        mutableStateOf(TransportLifecycleStore.autoDownloadMobileEnabled(context.applicationContext))
    }
    var discoverySubscriptionOn by remember {
        mutableStateOf(TransportLifecycleStore.discoverySubscriptionEnabled(context.applicationContext))
    }
    var serviceNotificationsOn by remember {
        mutableStateOf(TransportLifecycleStore.serviceNotificationsEnabled(context.applicationContext))
    }

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
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(bottom = 12.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = stringResource(R.string.direct_update_fallback_title),
                    style = MaterialTheme.typography.titleSmall,
                )
                Text(
                    text = stringResource(R.string.direct_update_fallback_warning),
                    modifier = Modifier.padding(top = 4.dp),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Switch(
                checked = directUpdateFallbackOn,
                onCheckedChange = { enabled ->
                    TransportLifecycleStore.setDirectUpdateFallbackEnabled(context.applicationContext, enabled)
                    directUpdateFallbackOn =
                        TransportLifecycleStore.directUpdateFallbackEnabled(context.applicationContext)
                },
            )
        }
        SettingsToggleRow(
            title = stringResource(R.string.auto_update_download_title),
            body = stringResource(R.string.auto_update_download_warning),
            checked = autoDownloadOn,
            onCheckedChange = { enabled ->
                TransportLifecycleStore.setAutoDownloadUpdatesEnabled(context.applicationContext, enabled)
                autoDownloadOn = TransportLifecycleStore.autoDownloadUpdatesEnabled(context.applicationContext)
            },
        )
        if (autoDownloadOn) {
            SettingsToggleRow(
                title = stringResource(R.string.auto_update_wifi_title),
                body = stringResource(R.string.auto_update_wifi_body),
                checked = autoDownloadWifiOn,
                onCheckedChange = { enabled ->
                    TransportLifecycleStore.setAutoDownloadWifiEnabled(context.applicationContext, enabled)
                    autoDownloadWifiOn = TransportLifecycleStore.autoDownloadWifiEnabled(context.applicationContext)
                },
            )
            SettingsToggleRow(
                title = stringResource(R.string.auto_update_mobile_title),
                body = stringResource(R.string.auto_update_mobile_body),
                checked = autoDownloadMobileOn,
                onCheckedChange = { enabled ->
                    TransportLifecycleStore.setAutoDownloadMobileEnabled(context.applicationContext, enabled)
                    autoDownloadMobileOn = TransportLifecycleStore.autoDownloadMobileEnabled(context.applicationContext)
                },
            )
        }
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(bottom = 12.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = stringResource(R.string.discovery_subscription_title),
                    style = MaterialTheme.typography.titleSmall,
                )
                Text(
                    text = stringResource(R.string.discovery_subscription_warning),
                    modifier = Modifier.padding(top = 4.dp),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Switch(
                checked = discoverySubscriptionOn,
                onCheckedChange = { enabled ->
                    TransportLifecycleStore.setDiscoverySubscriptionEnabled(context.applicationContext, enabled)
                    discoverySubscriptionOn =
                        TransportLifecycleStore.discoverySubscriptionEnabled(context.applicationContext)
                },
            )
        }
        Button(
            enabled = !updates.inProgress && (auth.authorized || directUpdateFallbackOn),
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
        ServiceNotificationsPanel(
            notificationsOn = serviceNotificationsOn,
            onChanged = { enabled ->
                TransportLifecycleStore.setServiceNotificationsEnabled(context.applicationContext, enabled)
                serviceNotificationsOn = TransportLifecycleStore.serviceNotificationsEnabled(context.applicationContext)
            },
        )
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

    SettingsSection(title = stringResource(R.string.http_proxy_title)) {
        HttpProxyPanel(context, transport)
    }

    SettingsSection(title = stringResource(R.string.local_proxy_auth_title)) {
        LocalProxyAuthPanel(context)
    }

    if (BuildConfig.VPN_ENABLED) {
        SettingsSection(title = stringResource(R.string.vpn_mode_title)) {
            VpnModePanel(context, transport)
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
private fun SettingsToggleRow(
    title: String,
    body: String,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(bottom = 12.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(text = title, style = MaterialTheme.typography.titleSmall)
            Text(
                text = body,
                modifier = Modifier.padding(top = 4.dp),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        Switch(checked = checked, onCheckedChange = onCheckedChange)
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
private fun ServiceNotificationsPanel(
    notificationsOn: Boolean,
    onChanged: (Boolean) -> Unit,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(bottom = 12.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = stringResource(R.string.service_notifications_switch),
                style = MaterialTheme.typography.titleSmall,
            )
            Text(
                text = stringResource(R.string.service_notifications_description),
                modifier = Modifier.padding(top = 4.dp),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        Switch(
            checked = notificationsOn,
            onCheckedChange = onChanged,
        )
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
private fun HttpProxyPanel(context: Context, transport: TransportUiState) {
    var proxyOn by remember {
        mutableStateOf(TransportLifecycleStore.httpProxyEnabled(context.applicationContext))
    }
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = stringResource(R.string.http_proxy_description),
                style = MaterialTheme.typography.bodySmall,
            )
        }
        Switch(
            checked = proxyOn,
            onCheckedChange = { enabled ->
                TransportLifecycleStore.setHttpProxyEnabled(context.applicationContext, enabled)
                proxyOn = TransportLifecycleStore.httpProxyEnabled(context.applicationContext)
                notifyHttpProxyPreferenceChanged(context.applicationContext)
            },
        )
    }
    if (proxyOn) {
        val listen = transport.httpProxyListen.ifBlank { LOCAL_HTTP_PROXY_LISTEN }
        Text(
            text = stringResource(R.string.http_proxy_listen, listen),
            modifier = Modifier.padding(top = 8.dp),
            style = MaterialTheme.typography.bodyMedium,
        )
        Text(
            text = stringResource(
                if (transport.httpProxyRunning) R.string.http_proxy_running else R.string.http_proxy_waiting,
            ),
            modifier = Modifier.padding(top = 4.dp),
            style = MaterialTheme.typography.bodySmall,
            color = if (transport.httpProxyRunning) Color(0xFF14532D) else MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Text(
            text = stringResource(R.string.http_proxy_instruction),
            modifier = Modifier.padding(top = 8.dp),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

@Composable
private fun LocalProxyAuthPanel(context: Context) {
    val appContext = context.applicationContext
    var authOn by remember { mutableStateOf(LocalSocksAuth.isFrontEndAuthEnabled(appContext)) }
    var credentials by remember {
        mutableStateOf(if (authOn) LocalSocksAuth.frontEndCredentials(appContext) else null)
    }
    SettingsToggleRow(
        title = stringResource(R.string.local_proxy_auth_switch),
        body = stringResource(R.string.local_proxy_auth_description),
        checked = authOn,
        onCheckedChange = { enabled ->
            LocalSocksAuth.setFrontEndAuthEnabled(appContext, enabled)
            authOn = LocalSocksAuth.isFrontEndAuthEnabled(appContext)
            credentials = if (authOn) LocalSocksAuth.frontEndCredentials(appContext) else null
            notifyHttpProxyPreferenceChanged(appContext)
        },
    )
    val current = credentials
    if (!authOn) {
        val vpnMode = BuildConfig.VPN_ENABLED && TransportLifecycleStore.vpnEnabled(appContext)
        Text(
            text = stringResource(
                if (vpnMode) R.string.local_proxy_vpn_internal_only else R.string.local_proxy_no_auth_warning,
            ),
            modifier = Modifier.padding(top = 8.dp),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.error,
        )
    }
    if (authOn && current != null) {
        CredentialRow(
            label = stringResource(R.string.local_proxy_auth_username),
            value = current.username,
            onCopy = { copySensitiveText(appContext, "TrafficWrapper proxy username", current.username, sensitive = false) },
        )
        // APP-L20: hidden until asked for; while shown the window is FLAG_SECURE.
        var passwordShown by remember { mutableStateOf(false) }
        if (passwordShown) SecureWindowWhileShown()
        CredentialRow(
            label = stringResource(R.string.local_proxy_auth_password),
            value = if (passwordShown) current.password else stringResource(R.string.local_proxy_auth_password_hidden),
            onCopy = { copySensitiveText(appContext, "TrafficWrapper proxy password", current.password, sensitive = true) },
        )
        TextButton(onClick = { passwordShown = !passwordShown }) {
            Text(
                text = stringResource(
                    if (passwordShown) R.string.local_proxy_auth_password_hide else R.string.local_proxy_auth_password_show,
                ),
            )
        }
        OutlinedButton(
            onClick = {
                credentials = LocalSocksAuth.regenerateFrontEndCredentials(appContext)
                notifyHttpProxyPreferenceChanged(appContext)
            },
            modifier = Modifier.padding(top = 8.dp),
        ) {
            Text(text = stringResource(R.string.local_proxy_auth_regenerate))
        }
        Text(
            text = stringResource(R.string.local_proxy_auth_hint),
            modifier = Modifier.padding(top = 8.dp),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

@Composable
private fun CredentialRow(label: String, value: String, onCopy: () -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(top = 6.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = label,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Text(
                text = value,
                style = MaterialTheme.typography.bodyMedium,
                fontWeight = FontWeight.SemiBold,
            )
        }
        OutlinedButton(onClick = onCopy) {
            Text(text = stringResource(R.string.copy_button))
        }
    }
}

@Composable
private fun VpnModePanel(context: Context, transport: TransportUiState) {
    if (!BuildConfig.VPN_ENABLED) return
    val appContext = context.applicationContext
    var vpnOn by remember { mutableStateOf(TransportLifecycleStore.vpnEnabled(appContext)) }
    var vpnMode by remember { mutableStateOf(TransportLifecycleStore.vpnMode(appContext)) }
    var allowedApps by remember { mutableStateOf(TransportLifecycleStore.vpnAllowedApps(appContext)) }
    var killSwitchOn by remember { mutableStateOf(TransportLifecycleStore.vpnKillSwitchEnabled(appContext)) }
    LaunchedEffect(transport.vpnEnabled, transport.vpnActive) {
        vpnOn = TransportLifecycleStore.vpnEnabled(appContext)
        vpnMode = TransportLifecycleStore.vpnMode(appContext)
        allowedApps = TransportLifecycleStore.vpnAllowedApps(appContext)
        killSwitchOn = TransportLifecycleStore.vpnKillSwitchEnabled(appContext)
    }
    Text(
        text = stringResource(R.string.vpn_mode_description),
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
    Text(
        text = stringResource(vpnStatusTextRes(transport)),
        modifier = Modifier.padding(top = 8.dp),
        style = MaterialTheme.typography.bodyMedium,
        color = vpnStatusColor(transport),
    )
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(top = 12.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            text = stringResource(R.string.vpn_mode_title),
            modifier = Modifier.weight(1f),
            style = MaterialTheme.typography.bodyMedium,
            fontWeight = FontWeight.SemiBold,
        )
        val onToggle = rememberVpnToggleHandler(
            context = context,
            vpnMode = vpnMode,
            allowedApps = allowedApps,
            onPreferenceChanged = { enabled -> vpnOn = enabled },
        )
        Switch(checked = vpnOn, onCheckedChange = onToggle)
    }
    Text(
        text = stringResource(R.string.vpn_scope_title),
        modifier = Modifier.padding(top = 14.dp),
        style = MaterialTheme.typography.titleSmall,
        fontWeight = FontWeight.SemiBold,
    )
    VpnModeOption(
        title = stringResource(R.string.vpn_scope_full),
        detail = stringResource(R.string.vpn_scope_full_detail),
        selected = vpnMode == VpnTrafficMode.FULL,
        onClick = {
            TransportLifecycleStore.setVpnMode(appContext, VpnTrafficMode.FULL)
            vpnMode = VpnTrafficMode.FULL
            if (vpnOn) startVpnModeService(appContext)
        },
    )
    VpnModeOption(
        title = stringResource(R.string.vpn_scope_split),
        detail = stringResource(R.string.vpn_scope_split_detail),
        selected = vpnMode == VpnTrafficMode.SPLIT,
        onClick = {
            TransportLifecycleStore.setVpnMode(appContext, VpnTrafficMode.SPLIT)
            vpnMode = VpnTrafficMode.SPLIT
            if (vpnOn) startVpnModeService(appContext)
        },
    )
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(top = 12.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = stringResource(R.string.vpn_kill_switch_title),
                style = MaterialTheme.typography.bodyMedium,
                fontWeight = FontWeight.SemiBold,
            )
            Text(
                text = stringResource(R.string.vpn_kill_switch_detail),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        Switch(
            checked = killSwitchOn,
            onCheckedChange = { enabled ->
                TransportLifecycleStore.setVpnKillSwitchEnabled(appContext, enabled)
                killSwitchOn = TransportLifecycleStore.vpnKillSwitchEnabled(appContext)
                if (vpnOn) startVpnModeService(appContext)
            },
        )
    }
    if (vpnMode == VpnTrafficMode.SPLIT) {
        Text(
            text = stringResource(R.string.vpn_split_apps_title),
            modifier = Modifier.padding(top = 12.dp),
            style = MaterialTheme.typography.titleSmall,
            fontWeight = FontWeight.SemiBold,
        )
        if (TransportRuntime.apps.loading) {
            Text(
                text = stringResource(R.string.app_choice_loading),
                modifier = Modifier.padding(top = 8.dp),
                style = MaterialTheme.typography.bodySmall,
            )
        } else {
            val selectableApps = TransportRuntime.apps.apps.filter { it.packageName != appContext.packageName }
            if (selectableApps.isEmpty()) {
                Text(
                    text = stringResource(R.string.vpn_split_no_apps),
                    modifier = Modifier.padding(top = 8.dp),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error,
                )
            }
            selectableApps.forEach { app ->
                VpnSplitAppRow(
                    app = app,
                    checked = app.packageName in allowedApps,
                    onCheckedChange = { checked ->
                        val next = if (checked) allowedApps + app.packageName else allowedApps - app.packageName
                        TransportLifecycleStore.setVpnAllowedApps(appContext, next)
                        allowedApps = TransportLifecycleStore.vpnAllowedApps(appContext)
                        if (vpnOn) startVpnModeService(appContext)
                    },
                )
            }
            if (allowedApps.isEmpty()) {
                Text(
                    text = stringResource(R.string.vpn_split_empty),
                    modifier = Modifier.padding(top = 8.dp),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error,
                )
            }
        }
    }
}

@Composable
private fun VpnModeOption(title: String, detail: String, selected: Boolean, onClick: () -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(top = 10.dp),
        horizontalArrangement = Arrangement.spacedBy(10.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        RadioButton(selected = selected, onClick = onClick)
        Column(modifier = Modifier.weight(1f)) {
            Text(text = title, style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.SemiBold)
            Text(
                text = detail,
                modifier = Modifier.padding(top = 2.dp),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
private fun VpnSplitAppRow(app: InstalledAppInfo, checked: Boolean, onCheckedChange: (Boolean) -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable { onCheckedChange(!checked) }
            .padding(top = 8.dp),
        horizontalArrangement = Arrangement.spacedBy(10.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Checkbox(checked = checked, onCheckedChange = onCheckedChange)
        Text(text = app.label, style = MaterialTheme.typography.bodyMedium)
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
        TRANSPORT_LABEL_AWG_RU -> "AWG A"
        TRANSPORT_LABEL_AWG -> "AWG B"
        TRANSPORT_LABEL_REALITY -> "REALITY A"
        TRANSPORT_LABEL_REALITY2 -> "REALITY B"
        else -> raw.ifBlank { "AUTO" }
    }

private fun transportChoiceRegion(choice: TransportChoice, regions: Map<String, String>): String =
    routeRegionForUi(defaultRouteForChoice(choice), regions)

internal fun routeRegionForUi(route: String, regions: Map<String, String>): String =
    regions[route].orEmpty().ifBlank {
        regions[routeRegionLookupKey(route)].orEmpty()
    }

private fun routeRegionLookupKey(route: String): String =
    route.trim().uppercase(Locale.ROOT).replace('-', '_')

internal fun transportModeCardSubtitle(detail: String?, region: String): String? =
    detail ?: region.trim().ifBlank { null }

internal fun connectedStatusDetail(label: String, region: String, stableText: String): String =
    listOf(label, region.trim(), stableText)
        .filter { it.isNotBlank() }
        .joinToString(" · ")

internal fun connectingStatusDetail(
    label: String,
    region: String,
    fallback: String,
    formatNoRegion: (String) -> String,
    formatWithRegion: (String, String) -> String,
): String {
    val normalizedLabel = label.trim()
    if (normalizedLabel.isBlank() || normalizedLabel == "AUTO") {
        return fallback
    }
    val normalizedRegion = region.trim()
    return if (normalizedRegion.isBlank()) {
        formatNoRegion(normalizedLabel)
    } else {
        formatWithRegion(normalizedLabel, normalizedRegion)
    }
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

private fun exactAlarmsDenied(context: Context, attentionRefreshTick: Long): Boolean {
    if (attentionRefreshTick < 0L || Build.VERSION.SDK_INT < 31) return false
    val alarmManager = context.getSystemService(AlarmManager::class.java) ?: return false
    return !alarmManager.canScheduleExactAlarms()
}

private fun openExactAlarmSettings(context: Context) {
    if (Build.VERSION.SDK_INT < 31) return
    val intent = Intent(
        Settings.ACTION_REQUEST_SCHEDULE_EXACT_ALARM,
        Uri.parse("package:${context.packageName}"),
    ).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
    runCatching { context.startActivity(intent) }
        .onFailure { openThisAppDetailsSettings(context) }
}

private fun requestPostNotificationsPermission(context: Context) {
    val activity = context as? Activity
    val granted = Build.VERSION.SDK_INT < 33 ||
        context.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED
    val action = notificationPermissionAction(
        sdkInt = Build.VERSION.SDK_INT,
        granted = granted,
        canRequestInActivity = activity != null,
        requestedBefore = notificationPermissionRequestedBefore(context),
        shouldShowRationale = Build.VERSION.SDK_INT >= 33 && activity != null &&
            activity.shouldShowRequestPermissionRationale(Manifest.permission.POST_NOTIFICATIONS),
    )
    when (action) {
        NotificationPermissionAction.NONE -> Unit
        NotificationPermissionAction.REQUEST -> {
            markNotificationPermissionRequested(context)
            activity?.requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 1001)
        }
        // APP-L18: denied for good, the system dialog no longer shows; open the app's settings.
        NotificationPermissionAction.OPEN_SETTINGS -> openNotificationSettings(context.applicationContext)
    }
}

private fun notificationPermissionRequestedBefore(context: Context): Boolean =
    context.applicationContext.getSharedPreferences(UI_PREFS, Context.MODE_PRIVATE)
        .getBoolean(KEY_NOTIFICATION_PERMISSION_REQUESTED, false)

private fun markNotificationPermissionRequested(context: Context) {
    context.applicationContext.getSharedPreferences(UI_PREFS, Context.MODE_PRIVATE)
        .edit()
        .putBoolean(KEY_NOTIFICATION_PERMISSION_REQUESTED, true)
        .apply()
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

private fun copySensitiveText(context: Context, label: String, text: String, sensitive: Boolean) {
    val clipboard = context.getSystemService(ClipboardManager::class.java) ?: return
    val clip = ClipData.newPlainText(label, text)
    if (sensitive && Build.VERSION.SDK_INT >= 33) {
        clip.description.extras = PersistableBundle().apply {
            putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true)
        }
    }
    clipboard.setPrimaryClip(clip)
    Toast.makeText(context, R.string.local_proxy_auth_copied, Toast.LENGTH_SHORT).show()
}

private fun copySocksAddress(context: Context, socksListen: String) {
    val clipboard = context.getSystemService(ClipboardManager::class.java)
    clipboard?.setPrimaryClip(ClipData.newPlainText("TrafficWrapper SOCKS5", socksListen))
    Toast.makeText(context, R.string.copied_to_clipboard, Toast.LENGTH_SHORT).show()
}

/**
 * The bootstrap an enrollment should use, from the one sealed record (APP-M12): the pending
 * bootstrap first, else the enrolled one; see [publicBootstrapForEnrollment].
 */
private fun publicBootstrapRaw(context: Context, silent: Boolean = false): String {
    migrateLegacyPublicBootstrapCopy(context)
    return publicBootstrapForEnrollment(SecureIdentityStore(context).readPublicPlatformState(), silent)
}

/**
 * A bootstrap the user imported or confirmed: stored as the pending bootstrap of the one sealed
 * record (APP-M12, APP-L20), then enrolled - right away, or after an enrollment that is already
 * running (APP-L14). Called on the main thread.
 */
private fun importPublicBootstrap(context: Context, raw: String) {
    val appContext = context.applicationContext
    PUBLIC_STATE_EXECUTOR.execute {
        val saved = runCatching { savePendingPublicBootstrap(appContext, raw) }
            .onFailure { Log.w(TAG, "saving the bootstrap failed", it) }
            .isSuccess
        MAIN_HANDLER.post {
            if (!saved) {
                PUBLIC_BOOTSTRAP_ERROR = appContext.getString(R.string.public_bootstrap_invalid)
                return@post
            }
            PUBLIC_BOOTSTRAP_IMPORTED = true
            PUBLIC_BOOTSTRAP_ERROR = null
            startOrQueuePublicDeviceEnrollment(appContext)
        }
    }
}

/** Records [raw] as the pending bootstrap in the sealed state (off the main thread). */
private fun savePendingPublicBootstrap(context: Context, raw: String) {
    migrateLegacyPublicBootstrapCopy(context)
    SecureIdentityStore(context).updatePublicPlatformState { withPendingPublicBootstrap(it, raw) }
}

/**
 * Moves the plain SharedPreferences copy older versions kept into the sealed state and deletes it
 * (APP-L20). Cheap when there is nothing to migrate.
 */
private fun migrateLegacyPublicBootstrapCopy(context: Context) {
    val prefs = context.applicationContext.getSharedPreferences(PUBLIC_PLATFORM_PREFS, Context.MODE_PRIVATE)
    val legacy = prefs.getString(KEY_PUBLIC_BOOTSTRAP_RAW, null) ?: return
    if (legacy.isNotBlank()) {
        SecureIdentityStore(context).updatePublicPlatformState { current ->
            migrateLegacyPublicBootstrap(current, legacy) ?: current
        }
    }
    prefs.edit().remove(KEY_PUBLIC_BOOTSTRAP_RAW).commit()
}

/**
 * APP-M13: drops the pending bootstrap (and a legacy copy). Runs [onResult] on the main thread
 * with whether a sealed enrollment remains to fall back to.
 */
private fun discardPendingPublicBootstrap(context: Context, onResult: (Boolean) -> Unit) {
    val appContext = context.applicationContext
    PUBLIC_STATE_EXECUTOR.execute {
        val enrolled = runCatching {
            migrateLegacyPublicBootstrapCopy(appContext)
            SecureIdentityStore(appContext)
                .updatePublicPlatformState(::discardPendingPublicBootstrapState)
                .clientBundleJson.isNotBlank()
        }.onFailure { Log.w(TAG, "discarding the pending bootstrap failed", it) }
            .getOrDefault(false)
        MAIN_HANDLER.post { onResult(enrolled) }
    }
}

/** APP-M14: persists that the orchestrator asked for approval again (off the main thread). */
internal fun persistPublicReauthRequired(context: Context, required: Boolean) {
    val appContext = context.applicationContext
    PUBLIC_STATE_EXECUTOR.execute {
        runCatching {
            SecureIdentityStore(appContext).updatePublicPlatformState { current ->
                // Only an enrolled device can be revoked; never create a state just for the flag.
                if (current.clientBundleJson.isBlank() || current.reauthRequired == required) {
                    current
                } else {
                    current.copy(reauthRequired = required)
                }
            }
        }.onFailure { Log.w(TAG, "persisting the reauth flag failed", it) }
    }
}

/** First restore of the process (APP-L15): legacy migration, restore, then the startup UI. */
private fun startPublicStartupRestore(appContext: Context) {
    PUBLIC_STATE_EXECUTOR.execute {
        val restored = runCatching { restorePublicPlatformState(appContext) }
            .onFailure { Log.w(TAG, "public platform restore crashed", it) }
            .getOrDefault(false)
        val bootstrapRaw = runCatching { publicBootstrapRaw(appContext) }.getOrDefault("")
        MAIN_HANDLER.post {
            PUBLIC_BOOTSTRAP_IMPORTED = restored || bootstrapRaw.isNotBlank()
            if (restored && PUBLIC_REENROLL_NEEDED) {
                // Through the tunnel once it carries traffic, never a direct request (APP-M4).
                requestPublicBackgroundReEnroll(appContext, PublicReEnrollReason.VERSION_REFRESH)
            }
            if (!restored && !TransportRuntime.auth.authorized && !ENROLLMENT_ACTIVE.get()) {
                TransportRuntime.auth = AuthUiState(
                    statusTextRes = if (PUBLIC_BOOTSTRAP_IMPORTED) {
                        R.string.public_bootstrap_imported
                    } else {
                        R.string.public_bootstrap_required
                    },
                )
                if (PUBLIC_BOOTSTRAP_IMPORTED) {
                    startAutomaticPublicEnrollment(appContext, bootstrapRaw)
                }
            }
            PUBLIC_STATE_LOADING = false
        }
    }
}

/**
 * Handles a bootstrap that arrived from outside the app (intent extra, SEND text, deep link).
 * Parsing and the comparison with the stored bootstrap (which needs the Keystore) run on the
 * public-state executor; the decision is applied to UI state on the main thread.
 */
private fun handleExternalBootstrap(context: Context, raw: String) {
    val appContext = context.applicationContext
    PUBLIC_STATE_EXECUTOR.execute {
        val outcome = runCatching {
            val parsed = PublicPlatformConfigParser.parseBootstrap(raw)
            val currentRaw = publicBootstrapRaw(appContext)
            val pinnedUpdatePubkey = runCatching {
                SecureIdentityStore(appContext).readPublicPlatformState().updatePubkeyPin
            }.getOrDefault("")
            val decision = externalBootstrapDecision(currentRaw, parsed, pinnedUpdatePubkey)
            val pending = when (decision) {
                ExternalBootstrapDecision.CONFIRM_NEW ->
                    pendingExternalBootstrap(currentRaw, raw, parsed, replacesExisting = false)
                ExternalBootstrapDecision.CONFIRM_REPLACE ->
                    pendingExternalBootstrap(currentRaw, raw, parsed, replacesExisting = true)
                else -> null
            }
            if (decision == ExternalBootstrapDecision.REFRESH) {
                // Every trusted field (orchestrator, pins, noise key, update key, seed workers)
                // matches the active bootstrap; only the one-time token / expiry changed. It goes
                // into the one sealed record every enrollment reads (APP-M12).
                savePendingPublicBootstrap(appContext, raw)
            }
            decision to pending
        }
        MAIN_HANDLER.post {
            outcome.onSuccess { (decision, pending) ->
                when (decision) {
                    ExternalBootstrapDecision.IGNORE -> PENDING_EXTERNAL_BOOTSTRAP = null
                    ExternalBootstrapDecision.REFRESH -> {
                        PUBLIC_BOOTSTRAP_IMPORTED = true
                        PENDING_EXTERNAL_BOOTSTRAP = null
                        // A fresh token helps a failed enrollment: retry it right away (APP-M12).
                        if (shouldEnrollAfterBootstrapRefresh(TransportRuntime.auth)) {
                            startOrQueuePublicDeviceEnrollment(appContext)
                        }
                    }
                    ExternalBootstrapDecision.CONFIRM_NEW,
                    ExternalBootstrapDecision.CONFIRM_REPLACE,
                    -> PENDING_EXTERNAL_BOOTSTRAP = pending
                }
                PUBLIC_BOOTSTRAP_ERROR = null
            }.onFailure {
                PUBLIC_BOOTSTRAP_ERROR = appContext.getString(R.string.public_bootstrap_invalid)
            }
        }
    }
}

private fun pendingExternalBootstrap(
    currentRaw: String,
    raw: String,
    parsed: PublicBootstrapConfig,
    replacesExisting: Boolean,
): PendingExternalBootstrap {
    // An expired stored bootstrap still names the current server (APP-L12).
    val current = parseBootstrapIgnoringExpiry(currentRaw)
    val changes = externalBootstrapTrustedFieldChanges(current, parsed)
    return PendingExternalBootstrap(
        raw = raw.trim(),
        orchestratorUrl = parsed.orchestratorUrl,
        configPubkeyPin = parsed.configPubkeyPin,
        orchNoisePublic = parsed.orchNoisePublic,
        updatePubkey = parsed.updatePubkey,
        replacesExisting = replacesExisting,
        currentOrchestratorUrl = current?.orchestratorUrl.orEmpty(),
        changes = if (replacesExisting) changes else emptyList(),
        needsKeyConfirmation = externalBootstrapNeedsSecondConfirmation(replacesExisting, changes),
    )
}

/**
 * Starts a user-visible enrollment with the stored (pending) bootstrap, or - when another
 * enrollment is running - queues it to run right after that one (APP-L14).
 */
private fun startOrQueuePublicDeviceEnrollment(context: Context) {
    val appContext = context.applicationContext
    if (!startPublicDeviceEnrollment(appContext)) {
        PUBLIC_ENROLLMENT_QUEUED = true
        Toast.makeText(appContext, R.string.public_bootstrap_enrollment_busy, Toast.LENGTH_LONG).show()
    }
}

/** Runs [action] on the main thread with the stored bootstrap, read off the main thread. */
private fun withPublicBootstrapRaw(context: Context, action: (String) -> Unit) {
    val appContext = context.applicationContext
    PUBLIC_STATE_EXECUTOR.execute {
        val raw = runCatching { publicBootstrapRaw(appContext) }.getOrDefault("")
        MAIN_HANDLER.post { action(raw) }
    }
}

/** Restores the cached public platform state off the main thread; [onResult] runs on main. */
private fun restorePublicPlatformStateAsync(context: Context, onResult: (Boolean) -> Unit) {
    val appContext = context.applicationContext
    PUBLIC_STATE_EXECUTOR.execute {
        val restored = runCatching { restorePublicPlatformState(appContext) }
            .onFailure { Log.w(TAG, "public platform restore crashed", it) }
            .getOrDefault(false)
        MAIN_HANDLER.post { onResult(restored) }
    }
}

internal fun publicBootstrapMatchesActive(currentRaw: String, incoming: PublicBootstrapConfig): Boolean {
    // The stored bootstrap may have expired meanwhile; it still names the platform (APP-L12).
    val current = parseBootstrapIgnoringExpiry(currentRaw) ?: return false
    return publicBootstrapTrustedFieldsMatch(current, incoming)
}

/**
 * Decides how to treat an external (not scanned/typed in the app) bootstrap. Anything that
 * changes a trusted field - including update_pubkey and seed workers - or conflicts with an
 * already pinned update key needs explicit user confirmation, exactly like a new import.
 */
internal fun externalBootstrapDecision(
    currentRaw: String,
    incoming: PublicBootstrapConfig,
    pinnedUpdatePubkey: String = "",
): ExternalBootstrapDecision {
    if (currentRaw.isBlank()) return ExternalBootstrapDecision.CONFIRM_NEW
    if (!publicBootstrapMatchesActive(currentRaw, incoming)) return ExternalBootstrapDecision.CONFIRM_REPLACE
    if (!updatePubkeyCompatibleWithPin(pinnedUpdatePubkey, incoming.updatePubkey)) {
        return ExternalBootstrapDecision.CONFIRM_REPLACE
    }
    val current = parseBootstrapIgnoringExpiry(currentRaw)
    return if (
        current != null &&
        current.bootstrapToken == incoming.bootstrapToken &&
        current.expiresAt == incoming.expiresAt
    ) {
        ExternalBootstrapDecision.IGNORE
    } else {
        ExternalBootstrapDecision.REFRESH
    }
}

internal enum class ExternalBootstrapDecision {
    IGNORE,
    REFRESH,
    CONFIRM_NEW,
    CONFIRM_REPLACE,
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
    val orchNoisePublic: String,
    val updatePubkey: String,
    val replacesExisting: Boolean,
    val currentOrchestratorUrl: String,
    /** Every trusted field the replacement changes (APP-L13). */
    val changes: List<BootstrapFieldChange> = emptyList(),
    /** Pins/keys change: a second confirmation step is required (APP-L13). */
    val needsKeyConfirmation: Boolean = false,
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
    val alarmText = if (exactAlarmsDenied(context, attentionRefreshTick)) {
        context.getString(R.string.permission_summary_exact_alarms_needed)
    } else {
        context.getString(R.string.permission_summary_exact_alarms_ok)
    }
    return "$batteryText · $notificationText · $alarmText"
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
    // Serialized with an enrollment's apply+persist (APP-L15): a restore never applies a state
    // older than one an enrollment has already applied.
    return synchronized(PUBLIC_APPLY_LOCK) { restorePublicPlatformStateLocked(context) }
}

private fun restorePublicPlatformStateLocked(context: Context): Boolean {
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
            persist = null,
        )
        PUBLIC_REENROLL_NEEDED = publicEnrollmentNeedsVersionRefresh(
            enrollVersionCode = stored.enrollVersionCode,
            currentVersionCode = BuildConfig.VERSION_CODE.toLong(),
        )
        true
    }.getOrElse { error ->
        Log.w(TAG, "public platform cached config restore failed", error)
        false
    }
}

/**
 * Enrolls this device with the public platform. [silent] is a background re-enrollment of an
 * already enrolled device (app update, reality_flow_ack, missing AWG profile credentials,
 * confirming a revocation hint): it keeps the current authorized UI state, accepts the stored
 * (possibly expired) bootstrap - the orchestrator does not consume the token of a known device -
 * and reports through [onOutcome] instead of the UI. [viaTunnel] sends the request through the
 * app's SOCKS router, i.e. the running tunnel (APP-M4); otherwise it goes direct. [onFinished] runs
 * on the main thread after the attempt. Returns false when another enrollment is already running.
 */
private fun startPublicDeviceEnrollment(
    context: Context,
    bootstrapRawOverride: String? = null,
    silent: Boolean = false,
    viaTunnel: Boolean = !silent && publicTunnelCarryingTraffic(),
    onOutcome: ((PublicEnrollOutcome) -> Unit)? = null,
    onFinished: (() -> Unit)? = null,
): Boolean {
    if (!DeploymentConfig.IS_PUBLIC_PLATFORM) return false
    if (!ENROLLMENT_ACTIVE.compareAndSet(false, true)) return false
    if (!silent) {
        TransportRuntime.auth = TransportRuntime.auth.copy(
            inProgress = true,
            authorized = false,
            enrollmentRetryAllowed = false,
            statusTextRes = R.string.public_enrollment_status_registering,
            errorTextRes = null,
        )
        PUBLIC_BOOTSTRAP_ERROR = null
    }
    ENROLLMENT_EXECUTOR.execute {
        val mainHandler = Handler(Looper.getMainLooper())
        var outcome: PublicEnrollOutcome = PublicEnrollOutcome.Failed(IllegalStateException("enrollment did not run"))
        try {
            // Resolved here (background) rather than as a default argument on the caller's thread.
            val bootstrapRaw = bootstrapRawOverride ?: publicBootstrapRaw(context, silent)
            val parsed = if (silent) {
                PublicPlatformConfigParser.parseBootstrap(bootstrapRaw, nowMs = 0L)
            } else {
                PublicPlatformConfigParser.parseBootstrap(bootstrapRaw)
            }
            val androidID = Settings.Secure.getString(context.contentResolver, Settings.Secure.ANDROID_ID).orEmpty()
            // APP-L19: the orchestrator keys devices by their identity/noise keys; it only gets a
            // per-platform hint instead of the raw ANDROID_ID.
            val deviceHint = publicDeviceHint(androidID, parsed.configPubkeyPin)
            val store = SecureIdentityStore(context)
            val previous = store.readPublicPlatformState()
            val noiseIdentity = store.getOrCreateIdentity { Transport.generateIdentity() }
            val deviceIdentity = store.getOrCreateDeviceIdentity()
            val awgKeyPair = store.getOrCreatePublicAWGKeyPair { Transport.generateWireGuardKeyPair() }
            val model = deviceModel()
            val nonce = randomNonce()
            val request = JSONObject()
                .put(JSON_PUBLIC_ORCHESTRATOR_URL, parsed.orchestratorUrl)
                .put(JSON_PUBLIC_ORCH_NOISE_PUBLIC, parsed.orchNoisePublic)
                .put(JSON_PUBLIC_BOOTSTRAP_TOKEN, parsed.bootstrapToken)
                .put(JSON_NOISE_PRIVATE_KEY, noiseIdentity.privateKey)
                .put(JSON_NOISE_PUBLIC_KEY, noiseIdentity.publicKey)
                .put(JSON_MODEL, model)
                .put(JSON_IDENTITY_PUBLIC_KEY, deviceIdentity.publicKey)
                .put(JSON_IDENTITY_KEY_TYPE, deviceIdentity.keyType)
                .put(JSON_ENROLLMENT_NONCE, nonce)
                .put(JSON_CLIENT_VERSION, BuildConfig.VERSION_NAME)
                .put(JSON_CLIENT_VERSION_CODE, BuildConfig.VERSION_CODE)
                .put(JSON_CLIENT_CAPABILITIES, JSONArray(PUBLIC_CLIENT_CAPABILITIES))
                .put(JSON_PUBLIC_AWG_PRIVATE_KEY, awgKeyPair.privateKey)
                .put(JSON_PUBLIC_AWG_PUBLIC_KEY, awgKeyPair.publicKey)
                .put(JSON_TIMEOUT_SECONDS, PUBLIC_ENROLL_TIMEOUT_SECONDS)
            if (deviceHint.isNotBlank()) {
                request.put(JSON_DEVICE_ID, deviceHint).put(JSON_ANDROID_ID, deviceHint)
            }
            publicEnrollFlowAck(previous, parsed.configPubkeyPin)?.let { request.put(JSON_PUBLIC_REALITY_FLOW_ACK, it) }
            if (viaTunnel) request.put(JSON_PUBLIC_SOCKS_PROXY, DEFAULT_ROUTER_SOCKS_LISTEN)
            if (parsed.orchTlsSpkiSha256.isNotEmpty()) {
                // APP-L36: the bootstrap pin is for the first enrollment; a re-enrollment accepts
                // the system roots too, so a certificate rotation does not lock devices out.
                request.put(JSON_PUBLIC_ORCH_TLS_SPKI_SHA256, JSONArray(parsed.orchTlsSpkiSha256))
                request.put(JSON_PUBLIC_REENROLL, silent)
            }
            val response = JSONObject(Transport.publicDeviceEnroll(request.toString()))
            if (!response.optBoolean(JSON_OK, false)) {
                throw PublicEnrollmentRejectedException(
                    code = response.optString(JSON_PUBLIC_CODE),
                    authenticated = response.optBoolean(JSON_PUBLIC_REJECTED, false),
                    message = response.optString(JSON_ERROR),
                )
            }
            val clientBundle = response.optJSONObject(JSON_PUBLIC_CLIENT_BUNDLE)
                ?: throw IllegalStateException("missing client bundle")
            val config = PublicPlatformConfigParser.verifyAndParseClientConfig(
                envelopeRaw = clientBundle.toString(),
                expectedPublicKey = parsed.configPubkeyPin,
                // Rollback floor only for the same platform (config key); a confirmed switch starts at 0.
                maxSeenSeq = previous.configSeqFloorFor(parsed.configPubkeyPin),
            )
            // Recomputed atomically against the freshest state in mergeEnrolledPublicPlatformState.
            val updatePubkeyPin = resolveUpdatePubkeyPin(
                signedConfigUpdatePubkey = config.updatePubkey,
                previous = previous,
                bootstrap = parsed,
            )
            val pendingFlow = response.optNullableString(JSON_PUBLIC_REALITY_FLOW_PENDING)
            val stored = StoredPublicPlatformState(
                bootstrapRaw = bootstrapRaw.trim(),
                configPubkeyPin = parsed.configPubkeyPin,
                updatePubkeyPin = updatePubkeyPin,
                maxSeenConfigSeq = maxOf(previous.configSeqFloorFor(parsed.configPubkeyPin), config.seq),
                maxSeenUpdateSeq = previous.updateSeqFloorFor(updatePubkeyPin),
                maxSeenUpdateSeqPin = updatePubkeyPin,
                clientConfigJson = clientBundle.getString(JSON_PUBLIC_CONFIG_JSON),
                clientBundleJson = clientBundle.toString(),
                deviceID = response.optString(JSON_DEVICE_ID).ifBlank { deviceHint },
                realityUUID = response.getString(JSON_PUBLIC_REALITY_UUID),
                internalIP = response.getString(JSON_INTERNAL_IP),
                psk2 = response.getString(JSON_PUBLIC_PSK2),
                serverAWGPublic = response.getString(JSON_PUBLIC_SERVER_AWG_PUBLIC),
                awgPrivateKey = response.optString(JSON_PUBLIC_AWG_PRIVATE_KEY).ifBlank { awgKeyPair.privateKey },
                awgPublicKey = response.optString(JSON_PUBLIC_AWG_PUBLIC_KEY).ifBlank { awgKeyPair.publicKey },
                limitsJson = (config.limits ?: parsed.limits)?.toString().orEmpty(),
                awgProfilesJson = response.optJSONObject(JSON_PUBLIC_AWG_PROFILES)?.toString().orEmpty(),
                // Only the active flow is applied; a pending one waits for its acknowledgement.
                realityFlow = response.optString(JSON_PUBLIC_REALITY_FLOW).trim(),
                realityFlowKnown = response.has(JSON_PUBLIC_REALITY_FLOW),
                enrollVersionCode = BuildConfig.VERSION_CODE.toLong(),
                realityFlowPending = pendingFlow?.trim().orEmpty(),
                realityFlowPendingKnown = pendingFlow != null,
            )
            val enrollStatus = response.optString(JSON_STATUS)
            applyPublicPlatformState(
                context = context.applicationContext,
                store = store,
                stored = stored,
                config = config,
                noiseIdentity = noiseIdentity,
                deviceIdentity = deviceIdentity,
                androidID = androidID,
                model = model,
                persist = { current ->
                    mergeEnrolledPublicPlatformState(
                        current = current,
                        enrolled = stored,
                        configSeq = config.seq,
                        signedConfigUpdatePubkey = config.updatePubkey,
                        bootstrap = parsed,
                    ).copy(
                        // A bootstrap confirmed while this enrollment ran stays pending (APP-L14).
                        pendingBootstrapRaw = pendingPublicBootstrapAfterEnrollment(
                            currentPending = current.pendingBootstrapRaw,
                            usedRaw = bootstrapRaw,
                        ),
                        reauthRequired = publicReauthRequiredAfterEnrollment(current.reauthRequired, enrollStatus),
                    )
                },
            )
            PUBLIC_REENROLL_NEEDED = false
            outcome = PublicEnrollOutcome.Enrolled(
                status = enrollStatus,
                flowPending = publicFlowAckNeeded(stored),
            )
        } catch (error: Throwable) {
            outcome = PublicEnrollOutcome.Failed(error)
            if (silent) {
                PUBLIC_REENROLL_FAILED_AT_MS = SystemClock.elapsedRealtime()
                Log.w(TAG, "public background re-enrollment failed; keeping cached state", error)
            } else {
                Log.w(TAG, "public device enrollment failed", error)
                val policy = publicEnrollmentFailurePolicy(error)
                mainHandler.post {
                    PUBLIC_BOOTSTRAP_ERROR = Telemetry.safeErrorMessage(error)
                }
                postPublicEnrollmentFailure(mainHandler, policy)
            }
        } finally {
            ENROLLMENT_ACTIVE.set(false)
            val finalOutcome = outcome
            mainHandler.post {
                onOutcome?.invoke(finalOutcome)
                onFinished?.invoke()
                // A bootstrap confirmed while this enrollment ran is enrolled now (APP-L14).
                if (PUBLIC_ENROLLMENT_QUEUED && !ENROLLMENT_ACTIVE.get()) {
                    PUBLIC_ENROLLMENT_QUEUED = false
                    startPublicDeviceEnrollment(context)
                }
            }
        }
    }
    return true
}

internal sealed class PublicEnrollOutcome {
    data class Enrolled(val status: String, val flowPending: Boolean) : PublicEnrollOutcome()
    data class Failed(val error: Throwable) : PublicEnrollOutcome()
}

/** Reads an optional string; null when absent or JSON null (an explicit "" stays ""). */
private fun JSONObject.optNullableString(key: String): String? =
    if (!has(key) || isNull(key)) null else optString(key)

/**
 * reality_flow_ack for the next enrollment: the stored reality_flow_pending of the same platform,
 * or null when nothing is pending (X-L13).
 */
internal fun publicEnrollFlowAck(previous: StoredPublicPlatformState, configPubkeyPin: String): String? {
    if (!previous.realityFlowPendingKnown) return null
    if (previous.configPubkeyPin.isNotBlank() && previous.configPubkeyPin != configPubkeyPin) return null
    return previous.realityFlowPending
}

/** A pending flow that differs from the active one still has to be acknowledged. */
internal fun publicFlowAckNeeded(state: StoredPublicPlatformState): Boolean =
    state.realityFlowPendingKnown && !(state.realityFlowKnown && state.realityFlow == state.realityFlowPending)

private fun publicTunnelCarryingTraffic(): Boolean =
    runCatching { TransportRuntime.state.isCarryingTrafficNow() }.getOrDefault(false)

/**
 * Connects with the cached enrollment right away. A re-enrollment the running app version still
 * needs is done in the background through the tunnel once it carries traffic (APP-M4) instead of
 * blocking the connect on a direct request to the orchestrator.
 */
private fun runAfterPublicVersionReEnroll(context: Context, action: () -> Unit) {
    if (PUBLIC_REENROLL_NEEDED) {
        requestPublicBackgroundReEnroll(context, PublicReEnrollReason.VERSION_REFRESH)
    }
    action()
}

internal fun publicEnrollmentNeedsVersionRefresh(enrollVersionCode: Long, currentVersionCode: Long): Boolean =
    enrollVersionCode != currentVersionCode

/**
 * Whether a version re-enrollment attempt is due: it is needed and none failed within
 * [PUBLIC_REENROLL_RETRY_AFTER_MS] (orchestrator unreachable).
 */
internal fun shouldWaitForPublicVersionReEnroll(needed: Boolean, lastFailureAtMs: Long, nowMs: Long): Boolean =
    needed && (lastFailureAtMs <= 0L || nowMs - lastFailureAtMs !in 0 until PUBLIC_REENROLL_RETRY_AFTER_MS)

internal const val PUBLIC_REENROLL_RETRY_AFTER_MS = 10 * 60_000L

/** Background re-enrollment requests, drained through the tunnel (main thread only). */
private object PublicBackgroundReEnroll {
    val reasons: MutableSet<PublicReEnrollReason> = java.util.EnumSet.noneOf(PublicReEnrollReason::class.java)
    val backoff = PublicEnrollmentBackoff()
    val reauthThrottle = PublicReauthConfirmThrottle()
    var checkScheduled = false

    /** Missing AWG profiles a re-enrollment was already attempted for (no retry loop). */
    val attemptedAwgProfiles = mutableSetOf<String>()
}

/**
 * Asks for a silent re-enrollment for [reason]. It runs through the tunnel as soon as one carries
 * traffic, with backoff after failures; see [publicReEnrollPlan].
 */
internal fun requestPublicBackgroundReEnroll(context: Context, reason: PublicReEnrollReason) {
    if (!DeploymentConfig.IS_PUBLIC_PLATFORM) return
    val appContext = context.applicationContext
    MAIN_HANDLER.post {
        val state = PublicBackgroundReEnroll
        if (reason in state.reasons) return@post
        if (reason == PublicReEnrollReason.REAUTH_CONFIRM &&
            !state.reauthThrottle.tryAcquire(SystemClock.elapsedRealtime())
        ) {
            return@post
        }
        state.reasons += reason
        schedulePublicBackgroundReEnroll(appContext, 0L)
    }
}

private fun schedulePublicBackgroundReEnroll(context: Context, delayMs: Long) {
    val state = PublicBackgroundReEnroll
    if (state.checkScheduled) return
    state.checkScheduled = true
    MAIN_HANDLER.postDelayed({
        state.checkScheduled = false
        runPublicBackgroundReEnroll(context)
    }, delayMs.coerceAtLeast(0L))
}

private fun runPublicBackgroundReEnroll(context: Context) {
    val state = PublicBackgroundReEnroll
    val nowMs = SystemClock.elapsedRealtime()
    if (PublicReEnrollReason.VERSION_REFRESH in state.reasons && !PUBLIC_REENROLL_NEEDED) {
        state.reasons -= PublicReEnrollReason.VERSION_REFRESH
    }
    val plan = publicReEnrollPlan(
        reasons = state.reasons,
        tunnelUp = publicTunnelCarryingTraffic(),
        backoffRemainingMs = state.backoff.remainingMs(nowMs),
    )
    when (plan) {
        PublicReEnrollPlan.Idle -> return
        is PublicReEnrollPlan.Wait -> schedulePublicBackgroundReEnroll(context, plan.delayMs)
        is PublicReEnrollPlan.Run -> {
            val running = state.reasons.toSet()
            val started = startPublicDeviceEnrollment(
                context,
                silent = true,
                viaTunnel = plan.viaTunnel,
                onOutcome = { outcome -> onPublicBackgroundReEnrollOutcome(context, running, outcome) },
            )
            if (!started) schedulePublicBackgroundReEnroll(context, PUBLIC_REENROLL_CHECK_INTERVAL_MS)
        }
    }
}

private fun onPublicBackgroundReEnrollOutcome(
    context: Context,
    ran: Set<PublicReEnrollReason>,
    outcome: PublicEnrollOutcome,
) {
    val state = PublicBackgroundReEnroll
    val nowMs = SystemClock.elapsedRealtime()
    when (outcome) {
        is PublicEnrollOutcome.Enrolled -> {
            state.reasons -= ran
            if (outcome.flowPending && PublicReEnrollReason.FLOW_ACK in ran) {
                // Acknowledged but still pending (e.g. the orchestrator rate-limits flow changes):
                // try again later, spaced by the backoff, instead of looping.
                state.backoff.onFailure(nowMs)
            } else {
                state.backoff.onSuccess()
            }
            if (outcome.flowPending) state.reasons += PublicReEnrollReason.FLOW_ACK
            if (ran.contains(PublicReEnrollReason.REAUTH_CONFIRM) &&
                outcome.status.trim().equals(DEVICE_STATUS_PENDING, ignoreCase = true)
            ) {
                applyConfirmedPublicReauth(context, "orchestrator")
            }
        }
        is PublicEnrollOutcome.Failed -> {
            state.backoff.onFailure(nowMs)
            when (authenticatedPublicEnrollmentKind(outcome.error)) {
                PublicEnrollmentFailureKind.PENDING, PublicEnrollmentFailureKind.BLOCKED -> {
                    // The orchestrator itself (inside Noise) says the device is not approved.
                    state.reasons -= PublicReEnrollReason.REAUTH_CONFIRM
                    applyConfirmedPublicReauth(context, "orchestrator")
                }
                PublicEnrollmentFailureKind.TERMINAL -> state.reasons.clear()
                else -> Unit
            }
        }
    }
    schedulePublicBackgroundReEnroll(context, 0L)
}

/**
 * After a config is applied: queue the background re-enrollments it calls for (acknowledge a
 * pending REALITY flow, fetch credentials of AWG profiles the bundle offers).
 */
internal fun requestPublicReEnrollsFor(
    context: Context,
    stored: StoredPublicPlatformState,
    config: PublicClientConfig,
    credentials: PublicPlatformCredentials = stored.toPublicPlatformCredentials(),
) {
    if (publicFlowAckNeeded(stored)) {
        requestPublicBackgroundReEnroll(context, PublicReEnrollReason.FLOW_ACK)
    }
    val missing = PublicPlatformConfigParser.missingAwgProfileCredentials(config, credentials)
    if (missing.isEmpty()) return
    MAIN_HANDLER.post {
        val attempted = PublicBackgroundReEnroll.attemptedAwgProfiles
        if (attempted.containsAll(missing)) return@post
        attempted += missing
        requestPublicBackgroundReEnroll(context, PublicReEnrollReason.AWG_PROFILE_CREDENTIALS)
    }
}

/**
 * Automatic first enrollment on activity start (no explicit user action) is spaced by a backoff,
 * so rotating or reopening the screen does not hammer the orchestrator directly.
 */
private fun startAutomaticPublicEnrollment(context: Context, bootstrapRaw: String) {
    val nowMs = SystemClock.elapsedRealtime()
    if (PUBLIC_AUTO_ENROLL_BACKOFF.remainingMs(nowMs) > 0) {
        TransportRuntime.auth = TransportRuntime.auth.copy(
            inProgress = false,
            enrollmentRetryAllowed = true,
            statusTextRes = R.string.enrollment_status_error,
            errorTextRes = R.string.public_enrollment_error,
        )
        return
    }
    startPublicDeviceEnrollment(context, bootstrapRaw, onOutcome = { outcome ->
        when (outcome) {
            is PublicEnrollOutcome.Enrolled -> PUBLIC_AUTO_ENROLL_BACKOFF.onSuccess()
            is PublicEnrollOutcome.Failed -> PUBLIC_AUTO_ENROLL_BACKOFF.onFailure(SystemClock.elapsedRealtime())
        }
    })
}

private val PUBLIC_AUTO_ENROLL_BACKOFF = PublicEnrollmentBackoff()

private fun postPublicEnrollmentFailure(
    mainHandler: Handler,
    policy: PublicEnrollmentFailurePolicy,
) {
    mainHandler.post {
        TransportRuntime.auth = publicEnrollmentFailureState(TransportRuntime.auth, policy)
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
    // Atomic read-modify-write applied to the stored state after the core accepted the config;
    // null means "restore only" (nothing is written).
    persist: ((StoredPublicPlatformState) -> StoredPublicPlatformState)?,
) {
    val credentials = stored.toPublicPlatformCredentials()
    val slots = PublicPlatformConfigParser.routeSlots(config, stored.deviceID, credentials)
    if (!slots.hasUsableRoute()) {
        throw IllegalStateException("public client config has no usable route")
    }
    val applyRequest = publicCoreApplyRequest(
        stored = stored,
        config = config,
        slots = slots,
        socksListen = DEFAULT_AWG_INTERNAL_SOCKS_LISTEN,
        awgRuSocksListen = DEFAULT_AWG_RU_INTERNAL_SOCKS_LISTEN,
        mtu = DEFAULT_MTU,
    )
    val persisted = synchronized(PUBLIC_APPLY_LOCK) {
        val applyResponse = JSONObject(Transport.applyPublicPlatformConfig(applyRequest.toString()))
        if (!applyResponse.optBoolean(JSON_OK, false)) {
            throw IllegalStateException(applyResponse.optString(JSON_ERROR))
        }
        if (persist != null) store.updatePublicPlatformState(persist) else stored
    }
    requestPublicReEnrollsFor(context, stored, config, credentials)
    val mainHandler = Handler(Looper.getMainLooper())
    val availableChoices = publicAvailableTransportChoices(slots)
    val preferredChoice = runCatching { TransportLifecycleStore.preferredMode(context) }
        .getOrDefault(TransportChoice.AUTO)
    // Compose-backed runtime state is updated on the main thread; posts are FIFO, so anything the
    // caller posts afterwards (e.g. starting the transport) observes these values.
    runOnMainThread(mainHandler) {
        TransportRuntime.publicPlatformConfig = config
        TransportRuntime.publicPlatformRouteSlots = slots
        TransportRuntime.publicReality2EgressIp = slots.reality2ExpectedEgressIp
        TransportRuntime.publicRealityEgressIp = slots.realityExpectedEgressIp
        // APP-M14: keep the user's route; initialise it once, fall back only if it disappeared.
        TransportRuntime.selectedTransport = publicSelectedTransportAfterApply(
            current = TransportRuntime.selectedTransport,
            initialized = PUBLIC_SELECTED_TRANSPORT_INITIALIZED,
            preferred = preferredChoice,
            available = availableChoices,
        )
        PUBLIC_SELECTED_TRANSPORT_INITIALIZED = true
    }
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
        quota = (config.limits ?: stored.limitsJson.toJsonObjectOrNull())?.toQuotaUiState() ?: QuotaUiState(),
    )
    if (persisted.reauthRequired) {
        // APP-M14: the orchestrator said this device needs approval again; a restore or a config
        // apply must not show it as approved. Posted after the base state (FIFO).
        mainHandler.post { TransportRuntime.auth = reauthRequiredAuthState(TransportRuntime.auth) }
        if (persist == null) {
            // Ask the orchestrator (throttled) whether the device has been approved meanwhile.
            requestPublicBackgroundReEnroll(context, PublicReEnrollReason.REAUTH_CONFIRM)
        }
    }
}

private fun runOnMainThread(handler: Handler, action: () -> Unit) {
    if (Looper.myLooper() == Looper.getMainLooper()) {
        action()
    } else {
        handler.post(action)
    }
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
        val connectToken = CONNECT_REQUEST_GATE.begin()
        restorePublicPlatformStateAsync(appContext) { restored ->
            if (restored) {
                // APP-M11: a Cancel/Disconnect while the restore ran voids this request.
                if (!CONNECT_REQUEST_GATE.isCurrent(connectToken)) {
                    Log.i(TAG, "skip deferred transport start after an explicit stop")
                    return@restorePublicPlatformStateAsync
                }
                if (userInitiated) {
                    TRANSPORT_KEEP_ALIVE.set(true)
                    TransportLifecycleStore.rememberActiveTransport(appContext, TransportRuntime.selectedTransport)
                }
                runAfterPublicVersionReEnroll(appContext) { startSelectedTransportIfCurrent(appContext, connectToken) }
            } else {
                startPublicDeviceEnrollment(appContext)
            }
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
    val current = startupAutoconnectSourceState(
        runtimeState = TransportRuntime.state,
        serviceSnapshot = AutoTransportService.latestCarryingUiState(),
    )
    CONNECT_IN_PROGRESS = shouldMarkConnectInProgressOnStartup(current)
    TransportRuntime.state = startupAutoconnectUiState(current)
}

private fun connectSelectedTransport(context: Context) {
    TRANSPORT_KEEP_ALIVE.set(true)
    TransportLifecycleStore.rememberActiveTransport(context.applicationContext, TransportRuntime.selectedTransport)
    val selectedTransport = TransportRuntime.selectedTransport
    val current = TransportRuntime.state
    val requestedRoute = defaultRouteForChoice(selectedTransport)
    val keepExistingCarry = selectedTransport == TransportChoice.AUTO ||
        current.carryingTransport.isBlank() ||
        current.carryingTransport == requestedRoute
    CONNECT_IN_PROGRESS = true
    TransportRuntime.state = current.copy(
        stateTextRes = R.string.state_starting,
        handshakeEstablished = if (keepExistingCarry) current.handshakeEstablished else false,
        tunnelStable = if (keepExistingCarry) current.tunnelStable else false,
        activeTransport = if (keepExistingCarry) {
            current.carryingTransport.ifBlank { current.activeTransport }
        } else {
            requestedRoute
        },
        carryingTransport = if (keepExistingCarry) current.carryingTransport else "",
        socksListen = DEFAULT_ROUTER_SOCKS_LISTEN,
    )
    if (DeploymentConfig.IS_PUBLIC_PLATFORM) {
        val appContext = context.applicationContext
        val connectToken = CONNECT_REQUEST_GATE.begin()
        if (TransportRuntime.auth.authorized) {
            runAfterPublicVersionReEnroll(appContext) { startSelectedTransportIfCurrent(appContext, connectToken) }
        } else {
            restorePublicPlatformStateAsync(appContext) { restored ->
                if (!CONNECT_REQUEST_GATE.isCurrent(connectToken)) {
                    // APP-M11: the user cancelled while the cached state was being restored.
                    Log.i(TAG, "skip deferred connect after an explicit stop")
                } else if (restored) {
                    runAfterPublicVersionReEnroll(appContext) { startSelectedTransportIfCurrent(appContext, connectToken) }
                } else {
                    startPublicDeviceEnrollment(appContext)
                }
            }
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

internal fun statusRouteForUi(state: TransportUiState, selectedTransport: TransportChoice): String =
    state.carryingTransport.ifBlank {
        state.activeTransport.ifBlank { defaultRouteForChoice(selectedTransport) }
    }

internal fun defaultRouteForChoice(choice: TransportChoice): String =
    when (choice) {
        TransportChoice.AUTO -> ""
        TransportChoice.AWG_RU -> TRANSPORT_LABEL_AWG_RU
        TransportChoice.AWG -> TRANSPORT_LABEL_AWG
        TransportChoice.REALITY -> TRANSPORT_LABEL_REALITY
        TransportChoice.REALITY2 -> TRANSPORT_LABEL_REALITY2
    }

internal fun shouldMarkConnectInProgressOnStartup(state: TransportUiState): Boolean =
    state.carryingTransport.isBlank() &&
        !state.handshakeEstablished &&
        !state.tunnelStable

internal fun startupAutoconnectSourceState(
    runtimeState: TransportUiState,
    serviceSnapshot: TransportUiState?,
): TransportUiState =
    serviceSnapshot?.takeIf { it.carryingTransport.isNotBlank() || it.handshakeEstablished }
        ?: runtimeState

internal fun startupAutoconnectUiState(state: TransportUiState): TransportUiState =
    if (shouldMarkConnectInProgressOnStartup(state)) {
        state.copy(
            stateTextRes = R.string.state_starting,
            socksListen = DEFAULT_ROUTER_SOCKS_LISTEN,
        )
    } else {
        state.copy(socksListen = DEFAULT_ROUTER_SOCKS_LISTEN)
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
                state.carryingTransport.isNotBlank() ||
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
    quota: QuotaUiState? = null,
) {
    mainHandler.post {
        val current = TransportRuntime.auth
        val effectiveInternalIP = if (authorized) internalIP.ifBlank { current.internalIP } else internalIP
        val effectiveEndpoint = if (authorized) endpoint.ifBlank { current.endpoint } else endpoint
        val effectiveSOCKS = if (authorized) socksListen.ifBlank { current.provisionedSOCKS } else socksListen
        val effectiveAWGRU = if (authorized) awgRu ?: current.awgRu else awgRu
        val effectiveReality = if (authorized) reality ?: current.reality else reality
        val effectiveReality2 = if (authorized) reality2 ?: current.reality2 else reality2
        val effectiveQuota = if (authorized) quota ?: current.quota else quota ?: QuotaUiState()
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
            quota = effectiveQuota,
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

private fun notifyHttpProxyPreferenceChanged(context: Context) {
    val intent = Intent(context, AutoTransportService::class.java)
        .setAction(AutoTransportService.ACTION_HTTP_PROXY_CHANGED)
    if (Build.VERSION.SDK_INT >= 26) {
        context.startForegroundService(intent)
    } else {
        context.startService(intent)
    }
}

private fun setVpnPreference(
    context: Context,
    enabled: Boolean,
    transition: VpnTransition = VpnTransition.NONE,
) {
    val appContext = context.applicationContext
    TransportLifecycleStore.setVpnEnabled(appContext, enabled)
    TransportRuntime.state = TransportRuntime.state.copy(
        vpnEnabled = BuildConfig.VPN_ENABLED && enabled,
        vpnActive = if (enabled) TransportRuntime.state.vpnActive else false,
        vpnTransition = transition,
    )
    VPN_COMMAND_EXECUTOR.execute {
        notifyVpnConfigPreferenceChanged(appContext)
    }
}

private fun notifyVpnConfigPreferenceChanged(context: Context) {
    if (!BuildConfig.VPN_ENABLED) return
    val intent = Intent(context, AutoTransportService::class.java)
        .setAction(AutoTransportService.ACTION_VPN_CONFIG_CHANGED)
    if (Build.VERSION.SDK_INT >= 26) {
        context.startForegroundService(intent)
    } else {
        context.startService(intent)
    }
}

private fun startVpnModeService(context: Context) {
    val appContext = context.applicationContext
    VPN_COMMAND_EXECUTOR.execute {
        VpnAutoRestore.startVpnService(appContext)
    }
}

private fun stopVpnModeService(context: Context) {
    if (!BuildConfig.VPN_ENABLED) return
    val appContext = context.applicationContext
    VPN_COMMAND_EXECUTOR.execute {
        appContext.startService(vpnModeServiceIntent(appContext, TW_VPN_ACTION_STOP))
    }
}

private fun vpnModeServiceIntent(context: Context, action: String): Intent =
    Intent(action).setClassName(context.packageName, TW_VPN_SERVICE_CLASS)

fun recoverStoredTransportKeys(context: Context) {
    val appContext = context.applicationContext
    if (!TransportLifecycleStore.shouldKeepAlive(appContext)) return
    TransportRuntime.selectedTransport = TransportLifecycleStore.preferredMode(appContext)
    TRANSPORT_KEEP_ALIVE.set(true)
    FORCE_KEY_REQUEST.set(true)
    startDeviceEnrollment(appContext)
}

/**
 * Starts the transport for a connect request issued with [connectToken], unless the user pressed
 * Cancel/Disconnect after it (APP-M11): an explicit stop is never undone by a late start.
 */
private fun startSelectedTransportIfCurrent(context: Context, connectToken: Long) {
    if (!CONNECT_REQUEST_GATE.isCurrent(connectToken)) {
        Log.i(TAG, "skip deferred transport start after an explicit stop")
        return
    }
    startSelectedTransport(context)
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

private fun stopAllTransports(context: Context, keepAlive: Boolean = false) {
    if (!keepAlive) {
        CONNECT_REQUEST_GATE.cancel()
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
    val uriBuilder = Uri.Builder()
        .scheme(TELEGRAM_SCHEME)
        .authority(TELEGRAM_SOCKS_AUTHORITY)
        .appendQueryParameter(TELEGRAM_SERVER_PARAM, host)
        .appendQueryParameter(TELEGRAM_PORT_PARAM, port)
    // When the local proxy requires a password, hand Telegram the front-end credentials too.
    LocalSocksAuth.requiredFrontEndCredentials(context)?.let { credentials ->
        uriBuilder
            .appendQueryParameter(TELEGRAM_USER_PARAM, credentials.username)
            .appendQueryParameter(TELEGRAM_PASS_PARAM, credentials.password)
    }
    val uri = uriBuilder.build()
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

private fun JSONObject.toRealityUiConfig(): RealityUiConfig {
    val network = optString(JSON_REALITY_NETWORK)
    return RealityUiConfig(
        transport = optString(JSON_REALITY_TRANSPORT),
        address = optString(JSON_REALITY_ADDRESS),
        ip = optString(JSON_REALITY_IP),
        port = optInt(JSON_REALITY_PORT, 0),
        uuid = optString(JSON_REALITY_UUID),
        email = optString(JSON_REALITY_EMAIL),
        flow = runtimeRealityFlow(network, optString(JSON_REALITY_FLOW)),
        security = optString(JSON_REALITY_SECURITY),
        network = network,
        serverName = optString(JSON_REALITY_SERVER_NAME),
        publicKey = optString(JSON_REALITY_PUBLIC_KEY),
        shortId = optString(JSON_REALITY_SHORT_ID),
        fingerprint = clampRealityFingerprint(optString(JSON_REALITY_FINGERPRINT)),
        spiderX = optString(JSON_REALITY_SPIDER_X),
        dest = optString(JSON_REALITY_DEST),
        xhttpHost = xhttpString(JSON_REALITY_XHTTP_HOST),
        xhttpPath = xhttpString(JSON_REALITY_XHTTP_PATH),
        xhttpMode = xhttpString(JSON_REALITY_XHTTP_MODE),
        xhttpExtraJson = xhttpObjectString(JSON_REALITY_XHTTP_EXTRA),
    )
}

private fun runtimeRealityFlow(network: String, flow: String): String =
    if (network.equals("xhttp", ignoreCase = true)) "" else flow.trim()

private fun JSONObject.xhttpString(key: String): String {
    val xhttp = optJSONObject(JSON_REALITY_XHTTP)
    return xhttp?.optString(key).orEmpty()
        .ifBlank { optString("xhttp_$key") }
        .ifBlank { optString("xhttp${key.replaceFirstChar { it.uppercaseChar() }}") }
        .trim()
}

private fun JSONObject.xhttpObjectString(key: String): String {
    val xhttp = optJSONObject(JSON_REALITY_XHTTP)
    return xhttp?.optJSONObject(key)?.toString().orEmpty()
        .ifBlank { optJSONObject("xhttp_$key")?.toString().orEmpty() }
        .ifBlank { optJSONObject("xhttp${key.replaceFirstChar { it.uppercaseChar() }}")?.toString().orEmpty() }
        .trim()
}

private fun String.toJsonObjectOrNull(): JSONObject? =
    takeIf { it.isNotBlank() }?.let { raw ->
        runCatching { JSONObject(raw) }.getOrNull()
    }

internal fun JSONObject.toQuotaUiState(): QuotaUiState {
    val limit = optLong(JSON_QUOTA_TRAFFIC_BYTES, optLong(JSON_QUOTA_LIMIT_BYTES, 0L)).coerceAtLeast(0L)
    val used = if (has(JSON_QUOTA_USED_BYTES)) {
        optLong(JSON_QUOTA_USED_BYTES, 0L).coerceAtLeast(0L)
    } else {
        null
    }
    val remaining = if (has(JSON_QUOTA_REMAINING_BYTES)) {
        optLong(JSON_QUOTA_REMAINING_BYTES, 0L).coerceAtLeast(0L)
    } else {
        used?.let { (limit - it).coerceAtLeast(0L) }
    }
    return QuotaUiState(
        limitBytes = limit,
        usedBytes = used,
        remainingBytes = remaining,
        rateLimit = optString(JSON_QUOTA_RATE_LIMIT),
        expiresAt = optString(JSON_EXPIRES_AT),
    )
}

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

/** Serializes secure-store reads, restore and external-bootstrap handling off the main thread. */
private val PUBLIC_STATE_EXECUTOR = Executors.newSingleThreadExecutor()
// Lazy: MainActivityKt is loaded by JVM unit tests, where android.os.Looper is only a stub.
private val MAIN_HANDLER by lazy { Handler(Looper.getMainLooper()) }
private val ENROLLMENT_ACTIVE = AtomicBoolean(false)

/** Serializes the core apply + persist of a restore and of an enrollment (APP-L15). */
private val PUBLIC_APPLY_LOCK = Any()

/** The public startup restore runs once per process, not on every activity recreation (APP-L15). */
private val PUBLIC_STARTUP_RESTORE_REQUESTED = AtomicBoolean(false)

/** A user enrollment requested while another one ran; started when that one ends (APP-L14). */
private var PUBLIC_ENROLLMENT_QUEUED = false

/** The route selection was initialised from the remembered mode (APP-M14; main thread only). */
private var PUBLIC_SELECTED_TRANSPORT_INITIALIZED = false

/** Explicit Cancel/Disconnect voids connect requests still in flight (APP-M11). */
private val CONNECT_REQUEST_GATE = ConnectRequestGate()

/** Set when the cached enrollment was made by another app version (see runAfterPublicVersionReEnroll). */
@Volatile
private var PUBLIC_REENROLL_NEEDED = false

@Volatile
private var PUBLIC_REENROLL_FAILED_AT_MS = 0L
private val FORCE_KEY_REQUEST = AtomicBoolean(false)
private val TRANSPORT_KEEP_ALIVE = AtomicBoolean(false)
private val STARTUP_AUTOCONNECT_REQUESTED = AtomicBoolean(false)
private var CONNECT_IN_PROGRESS by mutableStateOf(false)
private var SHOW_SETTINGS_SCREEN by mutableStateOf(false)
private var PUBLIC_BOOTSTRAP_IMPORTED by mutableStateOf(false)
private var PUBLIC_STATE_LOADING by mutableStateOf(DeploymentConfig.IS_PUBLIC_PLATFORM)
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
/** Legacy plain copy of the bootstrap; only read to migrate it into the sealed state (APP-L20). */
private const val KEY_PUBLIC_BOOTSTRAP_RAW = "bootstrap_raw"
private const val UI_PREFS = "main_ui"
private const val KEY_NOTIFICATION_PERMISSION_REQUESTED = "notification_permission_requested"
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
private const val TELEGRAM_USER_PARAM = "user"
private const val TELEGRAM_PASS_PARAM = "pass"
private const val TW_VPN_SERVICE_CLASS = "pro.trafficwrapper.TwVpnService"
private const val TW_VPN_ACTION_STOP = "pro.trafficwrapper.action.VPN_STOP"
private val VPN_COMMAND_EXECUTOR = Executors.newSingleThreadExecutor()

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
private const val JSON_CLIENT_VERSION_CODE = "client_version_code"
private const val JSON_CLIENT_CAPABILITIES = "client_capabilities"
private const val JSON_PUBLIC_AWG_PROFILES = "awg_profiles"
private const val JSON_PUBLIC_REALITY_FLOW = "reality_flow"
private const val JSON_PUBLIC_REALITY_FLOW_PENDING = "reality_flow_pending"
private const val JSON_PUBLIC_REALITY_FLOW_ACK = "reality_flow_ack"
private const val JSON_PUBLIC_SOCKS_PROXY = "socks_proxy"
private const val JSON_PUBLIC_ORCH_TLS_SPKI_SHA256 = "orch_tls_spki_sha256"
private const val JSON_PUBLIC_REENROLL = "reenroll"
private const val JSON_PUBLIC_CODE = "code"
private const val JSON_PUBLIC_REJECTED = "rejected"
private const val JSON_REQUEST_KEYS = "request_keys"
private const val JSON_SOCKS_LISTEN = "socks_listen"
private const val JSON_AWG_RU_SOCKS_LISTEN = "awg_ru_socks_listen"
private const val JSON_MTU = "mtu"
private const val JSON_INTERNAL_IP = "internal_ip"
private const val JSON_ENDPOINT = "endpoint"
private const val JSON_SERVER_PUBLIC_KEY = "server_public_key"
private const val JSON_AWG_RU = "awg_ru"
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
private const val JSON_REALITY_XHTTP = "xhttp"
private const val JSON_REALITY_XHTTP_HOST = "host"
private const val JSON_REALITY_XHTTP_PATH = "path"
private const val JSON_REALITY_XHTTP_MODE = "mode"
private const val JSON_REALITY_XHTTP_EXTRA = "extra"
private const val JSON_LIMITS = "limits"
private const val JSON_QUOTA_TRAFFIC_BYTES = "traffic_quota_bytes"
private const val JSON_QUOTA_LIMIT_BYTES = "limit_bytes"
private const val JSON_QUOTA_USED_BYTES = "used_bytes"
private const val JSON_QUOTA_REMAINING_BYTES = "remaining_bytes"
private const val JSON_QUOTA_RATE_LIMIT = "rate_limit"
private const val JSON_EXPIRES_AT = "expires_at"
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
