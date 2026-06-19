package pro.trafficwrapper

import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageInstaller
import android.net.Uri
import android.os.Build
import android.provider.Settings
import androidx.annotation.StringRes
import java.io.File

data class InstallStartResult(
    val started: Boolean,
    @StringRes val textRes: Int,
    val needsPermission: Boolean = false,
)

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

    fun install(apkPath: String): InstallStartResult {
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

        val installer = context.packageManager.packageInstaller
        val params = PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL)
            .apply {
                setAppPackageName(context.packageName)
                setSize(apk.length())
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
            apk.inputStream().use { input ->
                session.openWrite(APK_STREAM_NAME, 0, apk.length()).use { output ->
                    input.copyTo(output, DEFAULT_BUFFER_SIZE)
                    session.fsync(output)
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
        } catch (_: Throwable) {
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
        private const val APK_STREAM_NAME = "base.apk"
        private const val ENFORCE_UPDATE_OWNERSHIP = "android.permission.ENFORCE_UPDATE_OWNERSHIP"
    }
}
