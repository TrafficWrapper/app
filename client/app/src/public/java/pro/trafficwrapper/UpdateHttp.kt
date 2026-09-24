package pro.trafficwrapper

import java.io.EOFException
import java.io.FilterInputStream
import java.io.IOException
import java.io.InputStream
import java.security.MessageDigest

/** Maximum size of a signed manifest / signature fetched by the updater. */
internal const val UPDATE_MANIFEST_MAX_BYTES = 1L * 1024 * 1024

/** Hard ceiling for an update APK, independent of what the (signed) manifest claims. */
internal const val UPDATE_APK_MAX_BYTES = 300L * 1024 * 1024

internal const val UPDATE_HTTP_HEADER_LIMIT_BYTES = 64 * 1024

internal class UpdateHttpException(message: String) : IOException(message)

internal data class UpdateHttpHead(
    val code: Int,
    /** Header names are lower-cased; repeated headers are joined with ", ". */
    val headers: Map<String, String>,
)

/** Reads bytes up to and including the terminating CRLFCRLF of an HTTP/1.x response head. */
internal fun readUpdateHttpHead(input: InputStream, limitBytes: Int = UPDATE_HTTP_HEADER_LIMIT_BYTES): String {
    val bytes = java.io.ByteArrayOutputStream(1024)
    var state = 0
    while (bytes.size() < limitBytes) {
        val value = input.read()
        if (value < 0) throw EOFException("unexpected EOF while reading HTTP header")
        bytes.write(value)
        state = when {
            state == 0 && value == '\r'.code -> 1
            state == 1 && value == '\n'.code -> 2
            state == 2 && value == '\r'.code -> 3
            state == 3 && value == '\n'.code -> return bytes.toString(Charsets.ISO_8859_1.name())
            value == '\r'.code -> 1
            else -> 0
        }
    }
    throw UpdateHttpException("HTTP header exceeds $limitBytes bytes")
}

internal fun parseUpdateHttpHead(raw: String): UpdateHttpHead {
    val lines = raw.split("\r\n").filter { it.isNotEmpty() }
    val statusLine = lines.firstOrNull() ?: throw UpdateHttpException("empty HTTP response")
    val parts = statusLine.split(' ', limit = 3)
    if (parts.size < 2 || !parts[0].startsWith("HTTP/1.")) {
        throw UpdateHttpException("malformed HTTP status line")
    }
    val code = parts[1].takeIf { it.length == 3 }?.toIntOrNull()
        ?: throw UpdateHttpException("malformed HTTP status code")
    val headers = linkedMapOf<String, String>()
    lines.drop(1).forEach { line ->
        val index = line.indexOf(':')
        if (index <= 0) throw UpdateHttpException("malformed HTTP header line")
        val name = line.substring(0, index).trim().lowercase()
        val value = line.substring(index + 1).trim()
        headers[name] = headers[name]?.let { "$it, $value" } ?: value
    }
    return UpdateHttpHead(code, headers)
}

/**
 * Returns a stream that yields exactly the response body, honoring `Transfer-Encoding: chunked`
 * and `Content-Length` (a truncated body raises EOFException instead of being treated as complete),
 * and refusing bodies larger than [maxBytes].
 */
internal fun updateHttpBodyStream(
    input: InputStream,
    method: String,
    head: UpdateHttpHead,
    maxBytes: Long,
): InputStream {
    if (method.equals("HEAD", ignoreCase = true) || head.code in 100..199 || head.code == 204 || head.code == 304) {
        return UpdateFixedLengthInputStream(input, 0)
    }
    val transferEncoding = head.headers["transfer-encoding"]?.trim()?.lowercase().orEmpty()
    if (transferEncoding.isNotEmpty()) {
        val codings = transferEncoding.split(',').map { it.trim() }.filter { it.isNotEmpty() }
        if (codings != listOf("chunked")) {
            throw UpdateHttpException("unsupported transfer-encoding: $transferEncoding")
        }
        return UpdateChunkedInputStream(input, maxBytes)
    }
    val contentLengthRaw = head.headers["content-length"]
    if (contentLengthRaw != null) {
        val values = contentLengthRaw.split(',').map { it.trim() }.toSet()
        val length = values.singleOrNull()?.takeIf { v -> v.isNotEmpty() && v.all { it in '0'..'9' } }?.toLongOrNull()
            ?: throw UpdateHttpException("invalid content-length")
        if (length > maxBytes) throw UpdateHttpException("body of $length bytes exceeds limit $maxBytes")
        return UpdateFixedLengthInputStream(input, length)
    }
    // No framing: body is delimited by connection close (we always send Connection: close).
    return UpdateMaxBytesInputStream(input, maxBytes)
}

/** Reads the whole stream into memory, failing when it exceeds [maxBytes]. */
internal fun readUpdateBodyLimited(input: InputStream, maxBytes: Long): ByteArray {
    val out = java.io.ByteArrayOutputStream()
    val buffer = ByteArray(8 * 1024)
    var total = 0L
    while (true) {
        val read = input.read(buffer)
        if (read < 0) break
        total += read
        if (total > maxBytes) throw UpdateHttpException("body exceeds limit $maxBytes")
        out.write(buffer, 0, read)
    }
    return out.toByteArray()
}

internal fun updateSha256Hex(bytes: ByteArray): String = updateHexLower(MessageDigest.getInstance("SHA-256").digest(bytes))

internal fun updateSha256HexOfStream(input: InputStream): String {
    val digest = MessageDigest.getInstance("SHA-256")
    val buffer = ByteArray(64 * 1024)
    while (true) {
        val read = input.read(buffer)
        if (read < 0) break
        digest.update(buffer, 0, read)
    }
    return updateHexLower(digest.digest())
}

internal fun updateHexLower(bytes: ByteArray): String =
    bytes.joinToString("") { "%02x".format(it.toInt() and 0xff) }

/** Exactly [length] bytes; EOF before that is an error (truncated body). */
internal class UpdateFixedLengthInputStream(input: InputStream, length: Long) : FilterInputStream(input) {
    private var remaining = length

    override fun read(): Int {
        if (remaining <= 0) return -1
        val value = `in`.read()
        if (value < 0) throw EOFException("body truncated: $remaining bytes missing")
        remaining--
        return value
    }

    override fun read(b: ByteArray, off: Int, len: Int): Int {
        if (len == 0) return 0
        if (remaining <= 0) return -1
        val read = `in`.read(b, off, minOf(len.toLong(), remaining).toInt())
        if (read < 0) throw EOFException("body truncated: $remaining bytes missing")
        remaining -= read
        return read
    }

    override fun skip(n: Long): Long = 0

    override fun available(): Int = minOf(`in`.available().toLong(), remaining).toInt()

    override fun markSupported(): Boolean = false
}

/** Passes the stream through but fails once more than [maxBytes] bytes have been read. */
internal class UpdateMaxBytesInputStream(input: InputStream, private val maxBytes: Long) : FilterInputStream(input) {
    private var total = 0L

    override fun read(): Int {
        val value = `in`.read()
        if (value >= 0) account(1)
        return value
    }

    override fun read(b: ByteArray, off: Int, len: Int): Int {
        val read = `in`.read(b, off, len)
        if (read > 0) account(read.toLong())
        return read
    }

    override fun skip(n: Long): Long = 0

    override fun markSupported(): Boolean = false

    private fun account(count: Long) {
        total += count
        if (total > maxBytes) throw UpdateHttpException("body exceeds limit $maxBytes")
    }
}

/** RFC 9112 chunked transfer decoding (chunk extensions and trailers are skipped). */
internal class UpdateChunkedInputStream(input: InputStream, private val maxBytes: Long) : FilterInputStream(input) {
    private var chunkRemaining = 0L
    private var total = 0L
    private var finished = false
    private var started = false

    override fun read(): Int {
        val one = ByteArray(1)
        val read = read(one, 0, 1)
        return if (read <= 0) -1 else one[0].toInt() and 0xff
    }

    override fun read(b: ByteArray, off: Int, len: Int): Int {
        if (len == 0) return 0
        if (finished) return -1
        if (chunkRemaining == 0L) {
            if (started) expectCrlf()
            started = true
            chunkRemaining = readChunkSize()
            if (chunkRemaining == 0L) {
                skipTrailers()
                finished = true
                return -1
            }
            if (total + chunkRemaining > maxBytes) throw UpdateHttpException("body exceeds limit $maxBytes")
        }
        val read = `in`.read(b, off, minOf(len.toLong(), chunkRemaining).toInt())
        if (read < 0) throw EOFException("chunked body truncated")
        chunkRemaining -= read
        total += read
        return read
    }

    override fun skip(n: Long): Long = 0

    override fun available(): Int = 0

    override fun markSupported(): Boolean = false

    private fun readChunkSize(): Long {
        val line = readLine()
        val sizeText = line.substringBefore(';').trim()
        if (sizeText.isEmpty() || sizeText.length > 15 || !sizeText.all { it.isHexDigitChar() }) {
            throw UpdateHttpException("malformed chunk size")
        }
        return sizeText.toLong(16)
    }

    private fun skipTrailers() {
        while (readLine().isNotEmpty()) {
            // trailer fields are ignored
        }
    }

    private fun expectCrlf() {
        if (readLine().isNotEmpty()) throw UpdateHttpException("missing CRLF after chunk")
    }

    private fun readLine(): String {
        val builder = StringBuilder()
        while (true) {
            val value = `in`.read()
            if (value < 0) throw EOFException("chunked body truncated")
            if (value == '\r'.code) {
                val next = `in`.read()
                if (next != '\n'.code) throw UpdateHttpException("malformed chunk line ending")
                return builder.toString()
            }
            builder.append(value.toChar())
            if (builder.length > CHUNK_LINE_LIMIT) throw UpdateHttpException("chunk line too long")
        }
    }

    private fun Char.isHexDigitChar(): Boolean = this in '0'..'9' || this in 'a'..'f' || this in 'A'..'F'

    private companion object {
        private const val CHUNK_LINE_LIMIT = 4096
    }
}

/**
 * Validates a `Content-Range: bytes <start>-<end>/<total>` header of a 206 response against the
 * requested resume offset and the expected total size (from the signed manifest).
 */
internal fun updateContentRangeMatches(value: String?, expectedStart: Long, expectedTotal: Long): Boolean {
    if (value == null) return false
    val trimmed = value.trim()
    if (!trimmed.startsWith("bytes ", ignoreCase = true)) return false
    val spec = trimmed.substring("bytes ".length).trim()
    val range = spec.substringBefore('/')
    val total = spec.substringAfter('/', "")
    val start = range.substringBefore('-').trim().toLongOrNull() ?: return false
    val end = range.substringAfter('-', "").trim().toLongOrNull() ?: return false
    if (start != expectedStart || end < start || end >= expectedTotal) return false
    return total == "*" || total.trim().toLongOrNull() == expectedTotal
}
