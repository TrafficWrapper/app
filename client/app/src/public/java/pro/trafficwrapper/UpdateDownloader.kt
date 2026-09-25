package pro.trafficwrapper

import android.util.Log
import java.io.Closeable
import java.io.File
import java.io.FileOutputStream
import java.io.InputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URI
import okhttp3.OkHttpClient
import okhttp3.Request

private val UPDATE_CACHE_FILE_PATTERN = Regex("""^app-release-(\d+)\.apk(\.part|\.etag)?$""")

/**
 * APP-L32: files of the update cache that can be deleted. APKs and partial downloads of versions
 * that are already installed (<= [installedVersionCode]) are useless; partial downloads (.part /
 * .etag) of any version other than the one being downloaded ([targetVersionCode]) are superseded.
 */
internal fun staleUpdateCacheFileNames(
    names: Collection<String>,
    installedVersionCode: Long,
    targetVersionCode: Long? = null,
): List<String> =
    names.filter { name ->
        val match = UPDATE_CACHE_FILE_PATTERN.matchEntire(name) ?: return@filter false
        val versionCode = match.groupValues[1].toLongOrNull() ?: return@filter false
        val partial = match.groupValues[2].isNotEmpty()
        versionCode <= installedVersionCode ||
            (partial && targetVersionCode != null && versionCode != targetVersionCode)
    }

internal fun pruneUpdateCache(dir: File, installedVersionCode: Long, targetVersionCode: Long? = null) {
    val names = dir.list()?.toList() ?: return
    staleUpdateCacheFileNames(names, installedVersionCode, targetVersionCode).forEach { name ->
        if (!File(dir, name).delete()) {
            Log.w("TWPublicUpdate", "public update cache cleanup could not delete $name")
        }
    }
}

/**
 * APP-L33: a partial download is keyed by the APK identity pinned by the signed manifest
 * (sha256 + size), not by the URL or ETag of the worker that served it, so failover to another
 * worker resumes instead of starting over. The final SHA-256 check still guards the bytes.
 */
internal fun updatePartialMetadataText(sha256: String, apkSize: Long): String =
    "sha256=${sha256.trim().lowercase()}\nsize=$apkSize\n"

internal fun updatePartialMetadataMatches(metadataText: String?, sha256: String, apkSize: Long): Boolean {
    if (metadataText.isNullOrBlank() || sha256.isBlank()) return false
    val values = metadataText.lines().mapNotNull { line ->
        val separator = line.indexOf('=')
        if (separator <= 0) null else line.substring(0, separator) to line.substring(separator + 1).trim()
    }.toMap()
    return values["sha256"]?.equals(sha256.trim(), ignoreCase = true) == true &&
        values["size"]?.toLongOrNull() == apkSize
}

/**
 * APP-L31: a SHA-256 mismatch of a complete download is deterministic for this endpoint (it
 * serves different bytes than the signed manifest pins), so retrying it only re-downloads the
 * full APK; the caller moves on to the next endpoint instead.
 */
internal fun updateDownloadErrorIsTerminal(error: Throwable): Boolean =
    error is UpdateVerificationException && error.textRes == R.string.update_error_apk_hash

class UpdateDownloader(
    private val socksListen: String,
    private val baseUrl: String = UPDATE_AWG_BASE_URL,
    private val source: UpdateSource = UpdateSource.PLATFORM,
) {
    fun fetchManifestBundle(): ManifestBundle {
        val manifest = fetchString(updateUrl("update-manifest.json"))
        val minisig = fetchString(updateUrl("update-manifest.json.minisig"))
        return ManifestBundle(manifest, minisig, source, baseUrl, socksListen)
    }

    fun downloadApk(
        manifest: UpdateManifest,
        outputDir: File,
        onProgress: (downloadedBytes: Long, totalBytes: Long) -> Unit = { _, _ -> },
    ): File {
        outputDir.mkdirs()
        runCatching { pruneUpdateCache(outputDir, BuildConfig.VERSION_CODE.toLong(), manifest.versionCode) }
        val finalFile = File(outputDir, "app-release-${manifest.versionCode}.apk")
        val partFile = File(outputDir, finalFile.name + ".part")
        val etagFile = File(outputDir, finalFile.name + ".etag")
        if (manifest.apkSize <= 0 || manifest.apkSize > UPDATE_APK_MAX_BYTES) {
            throw UpdateVerificationException(R.string.update_error_download)
        }
        if (finalFile.exists()) {
            // Reuse a cached APK only if it is byte-identical to what the verified manifest pins.
            if (finalFile.length() == manifest.apkSize && fileSha256Matches(finalFile, manifest.sha256)) {
                onProgress(finalFile.length(), manifest.apkSize)
                return finalFile
            }
            finalFile.delete()
        }

        val apkUrl = apkDownloadUrl(manifest)
        var lastError: Throwable? = null
        for (attempt in 0 until MAX_DOWNLOAD_ATTEMPTS) {
            try {
                preparePartial(partFile, etagFile, manifest)
                etagFile.writeText(updatePartialMetadataText(manifest.sha256, manifest.apkSize))
                val resumeFrom = partFile.takeIf { it.exists() }?.length() ?: 0L
                onProgress(resumeFrom, manifest.apkSize)
                if (resumeFrom == manifest.apkSize) {
                    return finalizePartial(partFile, finalFile, etagFile, manifest, onProgress)
                }
                downloadRange(apkUrl, partFile, resumeFrom, manifest, onProgress)
                if (partFile.length() == manifest.apkSize) {
                    return finalizePartial(partFile, finalFile, etagFile, manifest, onProgress)
                }
                throw UpdateVerificationException(R.string.update_error_download)
            } catch (error: Throwable) {
                lastError = error
                if (updateDownloadErrorIsTerminal(error)) throw error
                if (attempt == MAX_DOWNLOAD_ATTEMPTS - 1) break
                sleepBeforeRetry(attempt)
            }
        }
        val verificationError = lastError as? UpdateVerificationException
        if (verificationError != null) {
            throw verificationError
        }
        throw UpdateVerificationException(R.string.update_error_download)
    }

    private fun downloadRange(
        apkUrl: String,
        partFile: File,
        resumeFrom: Long,
        manifest: UpdateManifest,
        onProgress: (downloadedBytes: Long, totalBytes: Long) -> Unit,
    ) {
        val headers = if (resumeFrom > 0) {
            mapOf("Range" to "bytes=$resumeFrom-")
        } else {
            emptyMap()
        }
        val expectedBodyBytes = manifest.apkSize - resumeFrom
        openHttp(apkUrl, "GET", headers, manifest.apkSize).use { response ->
            if (resumeFrom > 0 && response.code == HTTP_RANGE_NOT_SATISFIABLE) {
                if (partFile.length() == manifest.apkSize) return
                partFile.delete()
                throw UpdateVerificationException(R.string.update_error_download)
            }
            val append = resumeFrom > 0 && response.code == HTTP_PARTIAL
            if (!response.isSuccessful || (resumeFrom > 0 && !append) || (resumeFrom == 0L && response.code != HTTP_OK)) {
                if (response.code == HTTP_OK) {
                    partFile.delete()
                }
                throw UpdateVerificationException(R.string.update_error_download)
            }
            if (append && !updateContentRangeMatches(response.headers["content-range"], resumeFrom, manifest.apkSize)) {
                partFile.delete()
                throw UpdateVerificationException(R.string.update_error_download)
            }
            // Never let the partial file grow beyond the size pinned by the verified manifest.
            FileOutputStream(partFile, append).use { out ->
                UpdateMaxBytesInputStream(response.input, expectedBodyBytes).use { input ->
                    val buffer = ByteArray(DOWNLOAD_BUFFER_BYTES)
                    while (true) {
                        val read = input.read(buffer)
                        if (read < 0) break
                        out.write(buffer, 0, read)
                        onProgress(partFile.length(), manifest.apkSize)
                    }
                }
            }
        }
    }

    private fun finalizePartial(
        partFile: File,
        finalFile: File,
        etagFile: File,
        manifest: UpdateManifest,
        onProgress: (downloadedBytes: Long, totalBytes: Long) -> Unit,
    ): File {
        if (partFile.length() != manifest.apkSize) {
            throw UpdateVerificationException(R.string.update_error_download)
        }
        if (!fileSha256Matches(partFile, manifest.sha256)) {
            Log.w(TAG, "public update APK hash mismatch after download; discarding partial file")
            partFile.delete()
            etagFile.delete()
            throw UpdateVerificationException(R.string.update_error_apk_hash)
        }
        finalFile.delete()
        if (!partFile.renameTo(finalFile)) {
            partFile.delete()
            etagFile.delete()
            throw UpdateVerificationException(R.string.update_error_download)
        }
        etagFile.delete()
        onProgress(finalFile.length(), manifest.apkSize)
        return finalFile
    }

    private fun preparePartial(
        partFile: File,
        metadataFile: File,
        manifest: UpdateManifest,
    ) {
        if (!partFile.exists()) return
        val metadata = if (metadataFile.exists()) runCatching { metadataFile.readText() }.getOrNull() else null
        if (
            partFile.length() > manifest.apkSize ||
            !updatePartialMetadataMatches(metadata, manifest.sha256, manifest.apkSize)
        ) {
            partFile.delete()
            metadataFile.delete()
        }
    }

    private fun sleepBeforeRetry(attempt: Int) {
        try {
            Thread.sleep(RETRY_DELAYS_MS[attempt.coerceAtMost(RETRY_DELAYS_MS.lastIndex)])
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
            throw UpdateVerificationException(R.string.update_error_download)
        }
    }

    private fun fetchString(url: String): String {
        openHttp(url, "GET", maxBodyBytes = UPDATE_MANIFEST_MAX_BYTES).use { response ->
            if (!response.isSuccessful) {
                throw UpdateVerificationException(R.string.update_error_download)
            }
            return readUpdateBodyLimited(response.input, UPDATE_MANIFEST_MAX_BYTES).toString(Charsets.UTF_8)
        }
    }

    private fun fileSha256Matches(file: File, expectedSha256: String): Boolean =
        expectedSha256.isNotBlank() &&
            runCatching { file.inputStream().use { updateSha256HexOfStream(it) } }
                .getOrNull()
                ?.equals(expectedSha256.trim(), ignoreCase = true) == true

    private fun updateUrl(fileName: String): String =
        baseUrl.trimEnd('/') + "/" + fileName

    private fun apkDownloadUrl(manifest: UpdateManifest): String {
        val apkName = manifest.apkUrl.substringAfterLast('/').ifBlank {
            "app-public-${manifest.versionCode}.apk"
        }
        return updateApkDownloadUrl(baseUrl, apkName, manifest.versionCode)
    }

    private data class HttpResponse(
        val code: Int,
        val headers: Map<String, String>,
        val input: InputStream,
        val socket: Socket? = null,
        val response: Closeable? = null,
    ) : Closeable {
        val isSuccessful: Boolean
            get() = code in 200..299

        override fun close() {
            runCatching { input.close() }
            runCatching { response?.close() }
            runCatching { socket?.close() }
        }
    }

    private companion object {
        private const val HTTP_OK = 200
        private const val HTTP_PARTIAL = 206
        private const val HTTP_RANGE_NOT_SATISFIABLE = 416
        private const val DOWNLOAD_BUFFER_BYTES = 256 * 1024
        private const val MAX_DOWNLOAD_ATTEMPTS = 8
        private val RETRY_DELAYS_MS = longArrayOf(750L, 1500L, 3000L, 5000L, 8000L, 13000L, 21000L)

        private const val TAG = "TWPublicUpdate"

        private const val DEFAULT_SOCKS_HOST = "127.0.0.1"
        private const val DEFAULT_SOCKS_PORT = "18080"
        private val directClient = OkHttpClient.Builder()
            .followRedirects(false)
            .followSslRedirects(false)
            .build()
    }

    private fun openHttp(
        url: String,
        method: String,
        headers: Map<String, String> = emptyMap(),
        maxBodyBytes: Long,
    ): HttpResponse {
        if (source == UpdateSource.DIRECT) {
            return openDirectHttps(url, method, headers, maxBodyBytes)
        }
        val uri = URI(url)
        if ((uri.scheme ?: "").lowercase() != "http") {
            throw UpdateVerificationException(R.string.update_error_download)
        }
        val host = uri.host ?: throw UpdateVerificationException(R.string.update_error_download)
        val port = if (uri.port > 0) uri.port else 80
        val rawPath = uri.rawPath?.ifBlank { "/" } ?: "/"
        val query = uri.rawQuery?.let { "?$it" }.orEmpty()
        val socket = openSocks5Socket(host, port)
        try {
            val request = buildString {
                append(method).append(' ').append(rawPath).append(query).append(" HTTP/1.1\r\n")
                append("Host: ").append(host)
                if (uri.port > 0) append(':').append(port)
                append("\r\nConnection: close\r\nAccept: application/json,application/octet-stream,*/*\r\n")
                headers.forEach { (name, value) -> append(name).append(": ").append(value).append("\r\n") }
                append("\r\n")
            }
            socket.getOutputStream().write(request.toByteArray(Charsets.US_ASCII))
            socket.getOutputStream().flush()
            val input = socket.getInputStream().buffered(DOWNLOAD_BUFFER_BYTES)
            val head = parseUpdateHttpHead(readUpdateHttpHead(input))
            // Error bodies are never consumed, so only successful responses get the caller's limit.
            val bodyLimit = if (head.code in 200..299) maxBodyBytes else UPDATE_MANIFEST_MAX_BYTES
            val body = updateHttpBodyStream(input, method, head, bodyLimit)
            return HttpResponse(head.code, head.headers, body, socket)
        } catch (error: Throwable) {
            runCatching { socket.close() }
            throw error
        }
    }

    private fun openDirectHttps(
        url: String,
        method: String,
        headers: Map<String, String>,
        maxBodyBytes: Long,
    ): HttpResponse {
        val uri = URI(url)
        if ((uri.scheme ?: "").lowercase() != "https") {
            throw UpdateVerificationException(R.string.update_error_download)
        }
        val request = Request.Builder()
            .url(url)
            .method(method, null)
            .also { builder ->
                headers.forEach { (name, value) -> builder.header(name, value) }
            }
            .build()
        val response = directClient.newCall(request).execute()
        // OkHttp already enforces framing (chunked / Content-Length, truncation = error); we only
        // add the size ceiling here.
        val declaredLength = response.body.contentLength()
        if (response.isSuccessful && !method.equals("HEAD", ignoreCase = true) && declaredLength > maxBodyBytes) {
            response.close()
            throw UpdateHttpException("body of $declaredLength bytes exceeds limit $maxBodyBytes")
        }
        val input = UpdateMaxBytesInputStream(response.body.byteStream(), maxOf(maxBodyBytes, 0L))
        return HttpResponse(
            code = response.code,
            headers = response.headers.toMultimap().mapValues { it.value.joinToString(",") },
            input = input,
            response = response,
        )
    }

    private fun openSocks5Socket(targetHost: String, targetPort: Int): Socket {
        val proxyHost = socksListen.substringBeforeLast(":", DEFAULT_SOCKS_HOST).ifBlank { DEFAULT_SOCKS_HOST }
        val proxyPort = socksListen.substringAfterLast(":", DEFAULT_SOCKS_PORT).toIntOrNull()
            ?: DEFAULT_SOCKS_PORT.toInt()
        val socket = Socket()
        try {
            socket.soTimeout = 90_000
            socket.connect(InetSocketAddress(proxyHost, proxyPort), 15_000)
            // Loopback SOCKS listeners require the in-process credentials (RFC 1929).
            socks5Connect(
                input = socket.getInputStream(),
                output = socket.getOutputStream(),
                host = targetHost,
                port = targetPort,
                credentials = LocalSocksAuth.internal,
            )
            return socket
        } catch (error: Throwable) {
            runCatching { socket.close() }
            throw error
        }
    }
}
