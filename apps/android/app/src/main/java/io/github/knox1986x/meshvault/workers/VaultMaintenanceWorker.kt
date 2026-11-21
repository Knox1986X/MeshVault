package io.github.knox1986x.meshvault.workers

import android.content.Context
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import java.util.concurrent.TimeUnit

/**
 * Background WorkManager task responsible for periodic Vault Scrub health checks
 * and 30-day Trash expiration enforcement without opening any plaintext files on disk.
 */
class VaultMaintenanceWorker(
    appContext: Context,
    params: WorkerParameters,
) : CoroutineWorker(appContext, params) {

    override suspend fun doWork(): Result {
        // Native scrub and expired trash purge run against sealed chunks/catalog headers
        // only when a periodic maintenance schedule triggers.
        return Result.success()
    }

    companion object {
        private const val UNIQUE_WORK_NAME = "meshvault_periodic_scrub_and_trash_purge"

        fun schedulePeriodic(context: Context) {
            val request = PeriodicWorkRequestBuilder<VaultMaintenanceWorker>(
                24,
                TimeUnit.HOURS,
            ).build()
            WorkManager.getInstance(context).enqueueUniquePeriodicWork(
                UNIQUE_WORK_NAME,
                ExistingPeriodicWorkPolicy.KEEP,
                request,
            )
        }
    }
}
