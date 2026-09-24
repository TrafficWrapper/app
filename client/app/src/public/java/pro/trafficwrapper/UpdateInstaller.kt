package pro.trafficwrapper

import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageInstaller
import android.net.Uri
import android.os.Build
import android.provider.Settings
import android.util.Log
import androidx.annotation.StringRes
import java.io.File
import java.io.InputStream
import java.io.OutputStream
import java.security.MessageDigest
import java.util.concurrent.ConcurrentHashMap

data class InstallStartResult(
    val started: Boolean,
    @StringRes val textRes: Int,
    val needsPermission: Boolean = false,
)

/**
 * In-process registry of APKs that passed [UpdateVerifier.verifyApk], keyed by canonical path,
 * holding the SHA-256 pinned by the verified manifest. The installer re-hashes the bytes it
 * streams into the PackageInstaller session and refuses anything that does not match, closing
 * the window between verification and installation (the file is re-read from disk).
 */
internal object VerifiedUpdateApks {
    private val expected = ConcurrentHashMap<String, String>()

    fun register(apk: File, sha256: String) {
        expected[key(apk)] = sha256.trim().lowercase()
    }

    fun expectedSha256(apkPath: String): String? = expected[key(File(apkPath))]

    private fun key(file: File): String = runCatching { file.canonicalPath }.getOrDefault(file.absolutePath)
}

internal class ApkHashMismatchException(message: String) : Exception(message)

/**
 * Copies [input] to [output] while hashing, and returns the lowercase hex SHA-256 of the bytes
 * written. Throws [ApkHashMismatchException] when the size or the hash differ from the expected
 * values (checked before the caller commits anything).
 */
internal fun copyAndVerifySha256(
    input: InputStream,
    output: OutputStream,
    expectedSha256: String,
    expectedSize: Long,
): String {
    val digest = MessageDigest.getInstance("SHA-256")
    val buffer = ByteArray(64 * 1024)
    var total = 0L
    while (true) {
        val read = input.read(buffer)
        if (read < 0) break
        total += read
        if (total > expectedSize) throw ApkHashMismatchException("apk grew beyond verified size")
        digest.update(buffer, 0, read)
        output.write(buffer, 0, read)
    }
    if (total != expectedSize) throw ApkHashMismatchException("apk size changed after verification")
    val actual = digest.digest().joinToString("") { "%02x".format(it.toInt() and 0xff) }
    if (expectedSha256.isBlank() || !actual.equals(expectedSha256.trim(), ignoreCase = true)) {
        throw ApkHashMismatchException("apk hash changed after verification")
    }
    return actual
}

class UpdateInstaller(private val context: Context) {
    fun canRequestInstalls(): Boolean =
        Build.VERSION.SDK_INT < 26 || context.packageManager.canRequestPackageInstalls()

    fun openInstallSettings() {
        if (Build.VERSION.SDK_INT >= 26) {
            val intent = Intent(
                Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES,
                Uri.parse("package:${context.packageName}"),
            ).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            context.startActivity(intent)
        }
    }

    fun install(
        apkPath: String,
        expectedSha256: String? = VerifiedUpdateApks.expectedSha256(apkPath),
    ): InstallStartResult {
        if (!canRequestInstalls()) {
            return InstallStartResult(
                started = false,
                textRes = R.string.update_install_permission_required,
                needsPermission = true,
            )
        }
        val apk = File(apkPath)
        if (!apk.isFile || apk.length() <= 0) {
            return InstallStartResult(started = false, textRes = R.string.update_install_missing_apk)
        }
        if (expectedSha256.isNullOrBlank()) {
            // Nothing verified this file in the current process: refuse rather than trust the disk.
            Log.w(TAG, "update install refused: no verified hash for $apkPath")
            return InstallStartResult(started = false, textRes = R.string.update_install_missing_apk)
        }
        val apkSize = apk.length()

        val installer = context.packageManager.packageInstaller
        val params = PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL)
            .apply {
                setAppPackageName(context.packageName)
                setSize(apkSize)
                if (Build.VERSION.SDK_INT >= 31) {
                    setRequireUserAction(PackageInstaller.SessionParams.USER_ACTION_REQUIRED)
                }
                requestUpdateOwnershipIfAllowed(this, context)
            }

        var sessionId = 0
        var session: PackageInstaller.Session? = null
        return try {
            sessionId = installer.createSession(params)
            session = installer.openSession(sessionId)
            val openedSession = session
            apk.inputStream().use { input ->
                openedSession.openWrite(APK_STREAM_NAME, 0, apkSize).use { output ->
                    copyAndVerifySha256(input, output, expectedSha256, apkSize)
                    openedSession.fsync(output)
                }
            }
            val callback = Intent(context, UpdateInstallReceiver::class.java)
                .setAction(UpdateInstallReceiver.ACTION_INSTALL_RESULT)
                .setPackage(context.packageName)
            val flags = PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_MUTABLE
            val sender = PendingIntent.getBroadcast(context, sessionId, callback, flags).intentSender
            session.commit(sender)
            session.close()
            session = null
            InstallStartResult(started = true, textRes = R.string.update_install_started)
        } catch (error: Throwable) {
            if (error is ApkHashMismatchException) {
                Log.w(TAG, "update install aborted: ${error.message}")
                apk.delete()
            }
            runCatching { session?.abandon() }
            if (session == null && sessionId != 0) {
                runCatching { installer.abandonSession(sessionId) }
            }
            InstallStartResult(started = false, textRes = R.string.update_install_failed)
        } finally {
            runCatching { session?.close() }
        }
    }

    private fun requestUpdateOwnershipIfAllowed(
        params: PackageInstaller.SessionParams,
        context: Context,
    ) {
        if (Build.VERSION.SDK_INT < 34) return
        if (context.checkSelfPermission(ENFORCE_UPDATE_OWNERSHIP) != android.content.pm.PackageManager.PERMISSION_GRANTED) {
            return
        }
        runCatching {
            params.javaClass
                .getMethod("setRequestUpdateOwnership", Boolean::class.javaPrimitiveType)
                .invoke(params, true)
        }
    }

    private companion object {
        private const val TAG = "TWPublicUpdate"
        private const val APK_STREAM_NAME = "base.apk"
        private const val ENFORCE_UPDATE_OWNERSHIP = "android.permission.ENFORCE_UPDATE_OWNERSHIP"
    }
}
