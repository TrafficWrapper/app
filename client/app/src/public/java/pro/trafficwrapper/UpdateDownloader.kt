package pro.trafficwrapper

import java.io.Closeable
import java.io.EOFException
import java.io.File
import java.io.FileOutputStream
import java.io.InputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URI

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
        val finalFile = File(outputDir, "app-release-${manifest.versionCode}.apk")
        val partFile = File(outputDir, finalFile.name + ".part")
        val etagFile = File(outputDir, finalFile.name + ".etag")
        if (finalFile.exists() && finalFile.length() == manifest.apkSize) {
            onProgress(finalFile.length(), manifest.apkSize)
            return finalFile
        }

        val apkUrl = apkDownloadUrl(manifest)
        var lastError: Throwable? = null
        for (attempt in 0 until MAX_DOWNLOAD_ATTEMPTS) {
            try {
                val head = head(apkUrl)
                preparePartial(partFile, etagFile, manifest, apkUrl, head.etag)
                writePartialMetadata(etagFile, manifest, apkUrl, head.etag)
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
        openHttp(apkUrl, "GET", headers).use { response ->
            if (resumeFrom > 0 && response.code == HTTP_RANGE_NOT_SATISFIABLE) {
                if (partFile.length() == manifest.apkSize) return
                partFile.delete()
                throw UpdateVerificationException(R.string.update_error_download)
            }
            val append = resumeFrom > 0 && response.code == HTTP_PARTIAL
            if (!response.isSuccessful || (resumeFrom > 0 && !append)) {
                if (response.code == HTTP_OK) {
                    partFile.delete()
                }
                throw UpdateVerificationException(R.string.update_error_download)
            }
            FileOutputStream(partFile, append).use { out ->
                response.input.use { input ->
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
        finalFile.delete()
        if (!partFile.renameTo(finalFile)) {
            partFile.delete()
            etagFile.delete()
            throw UpdateVerificationException(R.string.update_error_download)
        }
        onProgress(finalFile.length(), manifest.apkSize)
        return finalFile
    }

    private fun preparePartial(
        partFile: File,
        metadataFile: File,
        manifest: UpdateManifest,
        apkUrl: String,
        etag: String?,
    ) {
        if (!partFile.exists()) return
        if (
            partFile.length() > manifest.apkSize ||
            !partialMetadataMatches(metadataFile, manifest, apkUrl, etag)
        ) {
            partFile.delete()
            metadataFile.delete()
        }
    }

    private fun partialMetadataMatches(
        metadataFile: File,
        manifest: UpdateManifest,
        apkUrl: String,
        etag: String?,
    ): Boolean {
        val metadata = readPartialMetadata(metadataFile) ?: return false
        if (metadata.legacyEtagOnly) {
            return etag != null && metadata.etag == etag
        }
        return metadata.apkUrl == apkUrl &&
            metadata.sha256.equals(manifest.sha256, ignoreCase = true) &&
            metadata.apkSize == manifest.apkSize &&
            (etag == null || metadata.etag == etag)
    }

    private fun readPartialMetadata(metadataFile: File): PartialMetadata? {
        if (!metadataFile.exists()) return null
        val lines = runCatching { metadataFile.readLines() }.getOrNull() ?: return null
        if (lines.size == 1 && !lines[0].contains("=")) {
            return PartialMetadata(etag = lines[0], legacyEtagOnly = true)
        }
        val values = lines.mapNotNull { line ->
            val separator = line.indexOf('=')
            if (separator <= 0) {
                null
            } else {
                line.substring(0, separator) to line.substring(separator + 1)
            }
        }.toMap()
        return PartialMetadata(
            apkUrl = values["url"],
            sha256 = values["sha256"],
            apkSize = values["size"]?.toLongOrNull(),
            etag = values["etag"]?.ifBlank { null },
        )
    }

    private fun writePartialMetadata(
        metadataFile: File,
        manifest: UpdateManifest,
        apkUrl: String,
        etag: String?,
    ) {
        metadataFile.writeText(
            buildString {
                append("url=").append(apkUrl).append('\n')
                append("sha256=").append(manifest.sha256).append('\n')
                append("size=").append(manifest.apkSize).append('\n')
                append("etag=").append(etag.orEmpty()).append('\n')
            },
        )
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
        openHttp(url, "GET").use { response ->
            if (!response.isSuccessful) {
                throw UpdateVerificationException(R.string.update_error_download)
            }
            return response.input.readBytes().toString(Charsets.UTF_8)
        }
    }

    private fun head(url: String): HeadMetadata {
        openHttp(url, "HEAD").use { response ->
            if (!response.isSuccessful) {
                throw UpdateVerificationException(R.string.update_error_download)
            }
            return HeadMetadata(response.headers["etag"])
        }
    }

    private fun updateUrl(fileName: String): String =
        baseUrl.trimEnd('/') + "/" + fileName

    private fun apkDownloadUrl(manifest: UpdateManifest): String {
        val apkName = manifest.apkUrl.substringAfterLast('/').ifBlank {
            "app-public-${manifest.versionCode}.apk"
        }
        return updateApkDownloadUrl(baseUrl, apkName, manifest.versionCode)
    }

    private data class HeadMetadata(val etag: String?)

    private data class HttpResponse(
        val code: Int,
        val headers: Map<String, String>,
        val input: InputStream,
        val socket: Socket,
    ) : Closeable {
        val isSuccessful: Boolean
            get() = code in 200..299

        override fun close() {
            runCatching { input.close() }
            runCatching { socket.close() }
        }
    }

    private data class PartialMetadata(
        val apkUrl: String? = null,
        val sha256: String? = null,
        val apkSize: Long? = null,
        val etag: String? = null,
        val legacyEtagOnly: Boolean = false,
    )

    private companion object {
        private const val HTTP_OK = 200
        private const val HTTP_PARTIAL = 206
        private const val HTTP_RANGE_NOT_SATISFIABLE = 416
        private const val DOWNLOAD_BUFFER_BYTES = 256 * 1024
        private const val MAX_DOWNLOAD_ATTEMPTS = 8
        private val RETRY_DELAYS_MS = longArrayOf(750L, 1500L, 3000L, 5000L, 8000L, 13000L, 21000L)

        private const val HTTP_HEADER_LIMIT_BYTES = 64 * 1024
        private const val SOCKS_VERSION = 0x05
        private const val SOCKS_NO_AUTH = 0x00
        private const val SOCKS_CONNECT = 0x01
        private const val SOCKS_ATYP_DOMAIN = 0x03
        private const val SOCKS_OK = 0x00

        private const val DEFAULT_SOCKS_HOST = "127.0.0.1"
        private const val DEFAULT_SOCKS_PORT = "18080"
    }

    private fun openHttp(
        url: String,
        method: String,
        headers: Map<String, String> = emptyMap(),
    ): HttpResponse {
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
            val input = socket.getInputStream()
            val rawHeader = readHttpHeader(input)
            val lines = rawHeader.lineSequence().filter { it.isNotBlank() }.toList()
            val statusLine = lines.firstOrNull().orEmpty()
            val code = statusLine.split(' ').getOrNull(1)?.toIntOrNull()
                ?: throw UpdateVerificationException(R.string.update_error_download)
            val responseHeaders = lines.drop(1).mapNotNull { line ->
                val index = line.indexOf(':')
                if (index <= 0) null else line.substring(0, index).lowercase() to line.substring(index + 1).trim()
            }.toMap()
            return HttpResponse(code, responseHeaders, input, socket)
        } catch (error: Throwable) {
            runCatching { socket.close() }
            throw error
        }
    }

    private fun openSocks5Socket(targetHost: String, targetPort: Int): Socket {
        val proxyHost = socksListen.substringBefore(":", DEFAULT_SOCKS_HOST).ifBlank { DEFAULT_SOCKS_HOST }
        val proxyPort = socksListen.substringAfterLast(":", DEFAULT_SOCKS_PORT).toIntOrNull()
            ?: DEFAULT_SOCKS_PORT.toInt()
        val socket = Socket()
        try {
            socket.soTimeout = 90_000
            socket.connect(InetSocketAddress(proxyHost, proxyPort), 15_000)
            val input = socket.getInputStream()
            val output = socket.getOutputStream()
            output.write(byteArrayOf(SOCKS_VERSION.toByte(), 0x01, SOCKS_NO_AUTH.toByte()))
            output.flush()
            if (readByte(input) != SOCKS_VERSION || readByte(input) != SOCKS_NO_AUTH) {
                throw UpdateVerificationException(R.string.update_error_download)
            }
            val hostBytes = targetHost.toByteArray(Charsets.UTF_8)
            if (hostBytes.size > 255) {
                throw UpdateVerificationException(R.string.update_error_download)
            }
            output.write(byteArrayOf(SOCKS_VERSION.toByte(), SOCKS_CONNECT.toByte(), 0x00, SOCKS_ATYP_DOMAIN.toByte(), hostBytes.size.toByte()))
            output.write(hostBytes)
            output.write(byteArrayOf(((targetPort ushr 8) and 0xff).toByte(), (targetPort and 0xff).toByte()))
            output.flush()
            if (readByte(input) != SOCKS_VERSION) {
                throw UpdateVerificationException(R.string.update_error_download)
            }
            val reply = readByte(input)
            readByte(input)
            val atyp = readByte(input)
            if (reply != SOCKS_OK) {
                throw UpdateVerificationException(R.string.update_error_download)
            }
            val bindLength = when (atyp) {
                0x01 -> 4
                0x03 -> readByte(input)
                0x04 -> 16
                else -> throw UpdateVerificationException(R.string.update_error_download)
            }
            readFully(input, bindLength + 2)
            return socket
        } catch (error: Throwable) {
            runCatching { socket.close() }
            throw error
        }
    }

    private fun readHttpHeader(input: InputStream): String {
        val bytes = ArrayList<Byte>(1024)
        var state = 0
        while (bytes.size < HTTP_HEADER_LIMIT_BYTES) {
            val value = input.read()
            if (value < 0) throw EOFException("unexpected EOF while reading HTTP header")
            bytes += value.toByte()
            state = when (state) {
                0 -> if (value == '\r'.code) 1 else 0
                1 -> if (value == '\n'.code) 2 else 0
                2 -> if (value == '\r'.code) 3 else 0
                3 -> if (value == '\n'.code) return bytes.toByteArray().toString(Charsets.ISO_8859_1) else 0
                else -> 0
            }
        }
        throw UpdateVerificationException(R.string.update_error_download)
    }

    private fun readByte(input: InputStream): Int {
        val value = input.read()
        if (value < 0) throw EOFException("unexpected EOF")
        return value
    }

    private fun readFully(input: InputStream, length: Int) {
        var remaining = length
        val buffer = ByteArray(256)
        while (remaining > 0) {
            val read = input.read(buffer, 0, minOf(buffer.size, remaining))
            if (read < 0) throw EOFException("unexpected EOF")
            remaining -= read
        }
    }
}
