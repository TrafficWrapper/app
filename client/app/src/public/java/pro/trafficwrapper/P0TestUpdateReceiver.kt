package pro.trafficwrapper

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log
import androidx.work.ExistingWorkPolicy
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.OutOfQuotaPolicy
import androidx.work.WorkManager

// P0-TEST TEMPORARY: exported device trigger for UpdateCheckWorker FGS empirical testing.
class P0TestUpdateReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent?) {
        if (intent?.action != ACTION_TEST_UPDATE_NOW) return
        val appContext = context.applicationContext
        // P0-TEST TEMPORARY: force every auto-download network gate on for the FGS probe.
        TransportLifecycleStore.setAutoDownloadUpdatesEnabled(appContext, true)
        TransportLifecycleStore.setAutoDownloadWifiEnabled(appContext, true)
        TransportLifecycleStore.setAutoDownloadMobileEnabled(appContext, true)
        val request = OneTimeWorkRequestBuilder<UpdateCheckWorker>()
            .setExpedited(OutOfQuotaPolicy.RUN_AS_NON_EXPEDITED_WORK_REQUEST)
            .build()
        WorkManager.getInstance(appContext).enqueueUniqueWork(
            TEST_WORK_NAME,
            ExistingWorkPolicy.REPLACE,
            request,
        )
        Log.i(LOG_TAG, "P0-TEST TEMPORARY: enqueued immediate update check id=${request.id}")
    }

    private companion object {
        private const val ACTION_TEST_UPDATE_NOW = "pro.trafficwrapper.TEST_UPDATE_NOW"
        private const val TEST_WORK_NAME = "trafficwrapper-p0-test-update-now"
        private const val LOG_TAG = "TWPublicUpdate"
    }
}
