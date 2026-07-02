package pro.trafficwrapper

import android.content.Context
import android.util.Log
import org.json.JSONArray
import java.io.File

class UpdateRepository(private val context: Context) {
    private val verifier = UpdateVerifier(context)

    fun check(
        auth: AuthUiState,
        socksListen: String,
        allowProvisioningFallback: Boolean = false,
        activeTransportOverride: String? = null,
    ): UpdateCheckOutcome {
        val directEnabled = TransportLifecycleStore.directUpdateFallbackEnabled(context)
        val tunnelViable = auth.authorized && socksListen.isNotBlank()
        if (!tunnelViable && !directEnabled) {
            return UpdateCheckOutcome(status = UpdateCheckStatus.ERROR, errorTextRes = R.string.update_error_tunnel_required)
        }
        return try {
            val verified = fetchFirstVerifiedBundle(socksListen, tunnelViable, directEnabled)
            when (val decision = verified.decision) {
                is ManifestDecision.Latest -> UpdateCheckOutcome(
                    status = UpdateCheckStatus.LATEST,
                    manifest = decision.manifest,
                    source = verified.bundle.source,
                    baseUrl = verified.bundle.baseUrl,
                )

                is ManifestDecision.Available -> UpdateCheckOutcome(
                    status = UpdateCheckStatus.AVAILABLE,
                    manifest = decision.manifest,
                    source = verified.bundle.source,
                    baseUrl = verified.bundle.baseUrl,
                    totalBytes = decision.manifest.apkSize,
                )
            }
        } catch (error: UpdateVerificationException) {
            Log.w(TAG, "public update check rejected: ${context.getString(error.textRes)}")
            UpdateCheckOutcome(status = UpdateCheckStatus.ERROR, errorTextRes = error.textRes)
        } catch (error: Throwable) {
            Log.w(TAG, "public update check failed", error)
            UpdateCheckOutcome(status = UpdateCheckStatus.ERROR, errorTextRes = R.string.update_error_network)
        }
    }

    fun downloadAndVerify(
        auth: AuthUiState,
        socksListen: String,
        allowProvisioningFallback: Boolean = false,
        activeTransportOverride: String? = null,
        onProgress: (downloadedBytes: Long, totalBytes: Long) -> Unit = { _, _ -> },
    ): UpdateCheckOutcome {
        val directEnabled = TransportLifecycleStore.directUpdateFallbackEnabled(context)
        val tunnelViable = auth.authorized && socksListen.isNotBlank()
        if (!tunnelViable && !directEnabled) {
            return UpdateCheckOutcome(status = UpdateCheckStatus.ERROR, errorTextRes = R.string.update_error_tunnel_required)
        }
        return try {
            var lastError: Throwable? = null
            var degradedOutcome: UpdateCheckOutcome? = null
            for (endpoint in updateEndpoints(socksListen, tunnelViable, directEnabled)) {
                val verified = runCatching { fetchVerifiedBundle(endpoint) }
                    .onFailure {
                        lastError = it
                        Log.w(TAG, "public update manifest failed via ${endpoint.baseUrl}", it)
                    }
                    .getOrNull() ?: continue
                when (val decision = verified.decision) {
                    is ManifestDecision.Latest -> return UpdateCheckOutcome(
                        status = UpdateCheckStatus.LATEST,
                        manifest = decision.manifest,
                        source = verified.bundle.source,
                        baseUrl = verified.bundle.baseUrl,
                    )

                    is ManifestDecision.Available -> {
                        val apk = try {
                            UpdateDownloader(verified.bundle.socksListen, verified.bundle.baseUrl, verified.bundle.source)
                                .downloadApk(decision.manifest, updateCacheDir(), onProgress)
                        } catch (error: UpdateVerificationException) {
                            lastError = error
                            Log.w(TAG, "public update APK download failed via ${verified.bundle.baseUrl}", error)
                            if (
                                error.textRes == R.string.update_error_download &&
                                decision.manifest.requiresInstalledUpdate()
                            ) {
                                degradedOutcome = mandatoryDegradedOutcome(
                                    verified.bundle,
                                    decision.manifest,
                                    verified.bundle.baseUrl,
                                )
                            }
                            continue
                        } catch (error: Throwable) {
                            lastError = error
                            Log.w(TAG, "public update APK download failed via ${verified.bundle.baseUrl}", error)
                            if (decision.manifest.requiresInstalledUpdate()) {
                                degradedOutcome = mandatoryDegradedOutcome(
                                    verified.bundle,
                                    decision.manifest,
                                    verified.bundle.baseUrl,
                                )
                            }
                            continue
                        }
                        verifier.verifyApk(apk, decision.manifest)
                        return UpdateCheckOutcome(
                            status = UpdateCheckStatus.AVAILABLE,
                            manifest = decision.manifest,
                            source = verified.bundle.source,
                            baseUrl = verified.bundle.baseUrl,
                            apkFile = apk,
                            downloadedBytes = apk.length(),
                            totalBytes = decision.manifest.apkSize,
                        )
                    }
                }
            }
            degradedOutcome ?: throw (lastError ?: UpdateVerificationException(R.string.update_error_network))
        } catch (error: UpdateVerificationException) {
            Log.w(TAG, "public update download rejected: ${context.getString(error.textRes)}")
            UpdateCheckOutcome(status = UpdateCheckStatus.ERROR, errorTextRes = error.textRes)
        } catch (error: Throwable) {
            Log.w(TAG, "public update download failed", error)
            UpdateCheckOutcome(status = UpdateCheckStatus.ERROR, errorTextRes = R.string.update_error_network)
        }
    }

    private fun fetchFirstVerifiedBundle(
        socksListen: String,
        tunnelViable: Boolean,
        directEnabled: Boolean,
    ): VerifiedManifestBundle {
        var lastError: Throwable? = null
        for (endpoint in updateEndpoints(socksListen, tunnelViable, directEnabled)) {
            val result = runCatching { fetchVerifiedBundle(endpoint) }
            result.getOrNull()?.let { return it }
            result.exceptionOrNull()?.let { lastError = it }
        }
        throw lastError ?: UpdateVerificationException(R.string.update_error_network)
    }

    private fun fetchVerifiedBundle(endpoint: UpdateEndpoint): VerifiedManifestBundle {
        val bundle = UpdateDownloader(endpoint.socksListen, endpoint.baseUrl, endpoint.source).fetchManifestBundle()
        return VerifiedManifestBundle(bundle, verifier.verifyManifest(bundle)).also {
            Log.i(TAG, "public update manifest verified via ${endpoint.baseUrl}")
        }
    }

    private fun updateEndpoints(
        socksListen: String,
        tunnelViable: Boolean,
        directEnabled: Boolean,
    ): List<UpdateEndpoint> {
        val urls = linkedSetOf<String>()
        if (tunnelViable) {
            return publicUpdateEndpoints(
                routeParams = TransportRuntime.publicPlatformRouteSlots.orderedRoutes.map { it.route.params },
                socksListen = socksListen,
                tunnelViable = true,
                directEnabled = directEnabled,
            ).map { UpdateEndpoint(it.baseUrl, it.socksListen, it.source) }
        }
        if (!directEnabled) return emptyList()
        return publicUpdateEndpoints(
            routeParams = TransportRuntime.publicPlatformRouteSlots.orderedRoutes.map { it.route.params },
            socksListen = socksListen,
            tunnelViable = false,
            directEnabled = true,
        ).map { UpdateEndpoint(it.baseUrl, it.socksListen, it.source) }
    }

    private fun updateCacheDir(): File =
        File(context.cacheDir, "updates").apply { mkdirs() }

    private fun mandatoryDegradedOutcome(
        bundle: ManifestBundle,
        manifest: UpdateManifest,
        baseUrl: String,
    ): UpdateCheckOutcome =
        UpdateCheckOutcome(
            status = UpdateCheckStatus.ERROR,
            manifest = manifest,
            source = bundle.source,
            baseUrl = baseUrl,
            mandatoryDegraded = true,
            errorTextRes = R.string.update_error_mandatory_degraded,
        )

    private data class UpdateEndpoint(
        val baseUrl: String,
        val socksListen: String,
        val source: UpdateSource = UpdateSource.PLATFORM,
    )

    private data class VerifiedManifestBundle(
        val bundle: ManifestBundle,
        val decision: ManifestDecision,
    )

    private companion object {
        private const val TAG = "TWPublicUpdate"
    }
}

internal data class PublicUpdateEndpointCandidate(
    val baseUrl: String,
    val socksListen: String,
    val source: UpdateSource = UpdateSource.PLATFORM,
)

internal fun publicUpdateEndpoints(
    routeParams: Iterable<org.json.JSONObject>,
    socksListen: String,
    tunnelViable: Boolean,
    directEnabled: Boolean,
): List<PublicUpdateEndpointCandidate> {
    if (tunnelViable) {
        val urls = linkedSetOf<String>()
        routeParams.forEach { params ->
            val url = params.optString("config_url").trim()
            if (url.isNotBlank()) urls += url.trimEnd('/')
        }
        if (urls.isEmpty()) urls += PUBLIC_PLATFORM_UPDATE_BASE_URL
        return urls.map {
            PublicUpdateEndpointCandidate(
                baseUrl = it,
                socksListen = socksListen.ifBlank { UPDATE_ROUTER_SOCKS_LISTEN },
            )
        }
    }
    if (!directEnabled) return emptyList()
    return publicDirectUpdateBaseUrls(routeParams).map {
        PublicUpdateEndpointCandidate(it, "", UpdateSource.DIRECT)
    }
}

internal fun publicDirectUpdateBaseUrls(routeParams: Iterable<org.json.JSONObject>): List<String> {
    val urls = linkedSetOf<String>()
    routeParams.forEach { params ->
        collectUrlArray(params.optJSONArray("direct_update_urls"), urls)
        collectUrlArray(params.optJSONArray("fallback_urls"), urls)
        val single = params.optString("direct_update_url").trim()
        if (single.isNotBlank()) urls += single
    }
    return urls
        .map { it.trim().trimEnd('/') }
        .filter { it.startsWith("https://", ignoreCase = true) }
}

private fun collectUrlArray(array: JSONArray?, out: MutableSet<String>) {
    if (array == null) return
    for (index in 0 until array.length()) {
        val value = array.optString(index).trim()
        if (value.isNotBlank()) out += value
    }
}
