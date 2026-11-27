package com.meshvault.data.sync.dropbox

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.ExistingWorkPolicy
import androidx.work.NetworkType
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.Result
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import com.meshvault.crypto.BlindIndex
import com.meshvault.crypto.VaultSessionKeys
import com.meshvault.crypto.wipe
import com.meshvault.data.db.EncryptedVaultRepositoryImpl
import com.meshvault.data.db.HardwareKeystoreManager
import com.meshvault.data.media.EncryptedMediaFileStore
import com.meshvault.domain.model.MediaItem
import com.meshvault.domain.model.SyncItemStatus
import com.meshvault.domain.model.VaultFolder
import com.meshvault.domain.repository.DropboxQuotaInfo
import com.meshvault.domain.repository.DropboxSyncGateway
import com.meshvault.domain.repository.DropboxSyncPhase
import com.meshvault.domain.sync.DropboxSyncMerger
import com.meshvault.domain.sync.SyncDeltaBatch
import com.meshvault.domain.sync.VaultSyncManifest
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.io.IOException
import java.util.concurrent.TimeUnit

/**
 * Двигатель E2EE-синхронизации MeshVault с обезличенным облаком Dropbox (`/MeshVault/`).
 *
 * Конвейер дельта-синхронизации:
 *  1. Выгрузка локального CRDT-манифеста и накопленных локальных операций;
 *  2. Загрузка облачного снапшота `snapshots/manifest.mvenc` + дельта-журнала из каталога `oplog` (файлы `.mvop`);
 *  3. Детерминированное слияние (LWW + Tombstones, [DropboxSyncMerger]);
 *  4. Выгрузка недостающих зашифрованных blob-ов `.mvbin` и превью `.mvthumb` (>8 МБ — докачка сессиями по 4 МБ);
 *  5. Удаление из облака blob-ов, помеченных Tombstone-ами (`purgeCloudBlob`);
 *  6. Компактирование: перезапись снапшота манифеста и удаление применённых `.mvop`;
 *  7. Вытеснение оригиналов папок «Экономия места (On-Demand)» при превышении лимита зашифрованного LRU-кэша.
 */
class DropboxSyncEngine(
    private val context: Context,
    private val session: VaultSessionKeys,
    private val repository: EncryptedVaultRepositoryImpl,
    private val fileStore: EncryptedMediaFileStore,
    private val authManager: DropboxPkceAuthManager,
    private val httpApi: DropboxHttpApiClient,
    private val keystoreManager: HardwareKeystoreManager,
) : DropboxSyncGateway {

    private val syncMutex = Mutex()

    override val isConnectedFlow: StateFlow<Boolean> = authManager.isAuthenticatedFlow

    private val _syncPhaseFlow = MutableStateFlow<DropboxSyncPhase>(DropboxSyncPhase.Idle)
    override val syncPhaseFlow: StateFlow<DropboxSyncPhase> = _syncPhaseFlow

    private val _quotaFlow = MutableStateFlow<DropboxQuotaInfo?>(null)
    override val quotaFlow: StateFlow<DropboxQuotaInfo?> = _quotaFlow

    // ---------- Публичные операции жизненного цикла хранилища ----------

    /**
     * Выгружает `vault_header.json` (параметры KDF + зашифрованный конверт VMK, без пользовательских данных),
     * чтобы хранилище можно было восстановить на новом смартфоне одним мастер-паролем.
     */
    suspend fun uploadVaultHeaderBackupIfPossible(): Boolean = withContext(Dispatchers.IO) {
        if (!authManager.isAuthenticatedFlow.value) return@withContext false
        val raw = keystoreManager.readVaultHeaderRaw() ?: return@withContext false
        runCatching {
            httpApi.uploadSmallBytes(DropboxHttpApiClient.HEADER_PATH, raw.toByteArray(Charsets.UTF_8))
        }.isSuccess
    }

    /**
     * Восстановление на новом устройстве: если локального `vault_header.json` нет —
     * скачивает его из Dropbox. Пользователь далее вводит мастер-пароль на обычном экране разблокировки.
     */
    suspend fun restoreVaultHeaderFromCloudIfMissing(): Boolean = withContext(Dispatchers.IO) {
        if (keystoreManager.hasVaultHeader()) return@withContext true
        if (!authManager.isAuthenticatedFlow.value) return@withContext false
        val bytes = runCatching { httpApi.downloadBytesOrNull(DropboxHttpApiClient.HEADER_PATH) }
            .getOrNull() ?: return@withContext false
        runCatching {
            keystoreManager.saveVaultHeaderRaw(String(bytes, Charsets.UTF_8))
            true
        }.getOrDefault(false)
    }

    // ---------- DropboxSyncGateway ----------

    override suspend fun triggerDeltaSync(wifiOnly: Boolean) {
        syncMutex.withLock {
            runDeltaSyncLocked(wifiOnly)
        }
    }

    override suspend fun ensureMediaBlobAvailableLocally(
        item: MediaItem,
        onProgress: (Float) -> Unit,
    ): Boolean = withContext(Dispatchers.IO) {
        if (session.isLocked) return@withContext false

        if (item.localBlobPresent && fileStore.hasLocalBlob(session.contour, item.id)) {
            repository.upsertMedia(item.copy(lastAccessedAtMs = System.currentTimeMillis()))
            onProgress(1f)
            return@withContext true
        }

        if (!authManager.isAuthenticatedFlow.value) return@withContext false

        val cloudPath = session.withMacKey { kMac ->
            cloudBlobPath(kMac, item.id)
        }
        val targetFile = fileStore.blobFile(session.contour, item.id)
        val ok = runCatching { httpApi.downloadToFile(cloudPath, targetFile, onProgress) }
            .getOrDefault(false)
        if (!ok) return@withContext false

        repository.upsertMedia(
            item.copy(
                localBlobPresent = true,
                syncStatus = SyncItemStatus.SYNCED_DROPBOX,
                lastAccessedAtMs = System.currentTimeMillis(),
                updatedAtMs = System.currentTimeMillis(),
            ),
        )
        enforceOnDemandQuotaIfNeeded()
        true
    }

    override suspend fun refreshSpaceUsage() {
        if (!authManager.isAuthenticatedFlow.value) {
            _quotaFlow.value = null
            return
        }
        runCatching { httpApi.getSpaceUsage() }
            .onSuccess { _quotaFlow.value = it }
    }

    override suspend fun disconnectAndWipeTokens() {
        authManager.disconnectAndWipe()
        _quotaFlow.value = null
        _syncPhaseFlow.value = DropboxSyncPhase.Idle
    }

    // ---------- Конвейер синхронизации ----------

    private suspend fun runDeltaSyncLocked(wifiOnly: Boolean) {
        if (session.isLocked) {
            _syncPhaseFlow.value = DropboxSyncPhase.Error("Хранилище заблокировано — разблокируйте MeshVault")
            return
        }
        if (!authManager.isAuthenticatedFlow.value) {
            _syncPhaseFlow.value = DropboxSyncPhase.Error("Dropbox не подключён")
            return
        }
        if (wifiOnly && !isOnUnmeteredNetwork()) {
            _syncPhaseFlow.value = DropboxSyncPhase.Error("Ожидание Wi‑Fi-сети для синхронизации (отключите «Только по Wi‑Fi» в настройках)")
            return
        }

        val syncStartedAt = System.currentTimeMillis()
        var transferredBytes = 0L

        try {
            // 1. Локальное состояние
            _syncPhaseFlow.value = DropboxSyncPhase.Running("Чтение локальных изменений…", 0, 1)
            val (localManifest, localBatch, pendingOpIds) = repository.exportLocalSyncBundle()

            // 2. Облачный снапшот манифеста
            _syncPhaseFlow.value = DropboxSyncPhase.Running("Загрузка снимка из Dropbox…", 0, 1)
            val remoteManifest: VaultSyncManifest? = runCatching {
                httpApi.downloadBytesOrNull(DropboxHttpApiClient.MANIFEST_PATH)?.let { bytes ->
                    runCatching { DropboxSyncMerger.decryptManifest(session, bytes) }
                        .onFailure { bytes.wipe() }
                        .getOrNull()
                }
            }.getOrNull()

            // 3. Дельта-журнал oplog
            _syncPhaseFlow.value = DropboxSyncPhase.Running("Чтение журнала операций…", 0, 1)
            val remoteOplogNames = runCatching {
                httpApi.listFileNamesInFolder(DropboxHttpApiClient.OPLOG_DIR)
            }.getOrDefault(emptyList())
                .filter { it.endsWith(".mvop", ignoreCase = true) }

            val remoteBatches = mutableListOf<SyncDeltaBatch>()
            for (name in remoteOplogNames) {
                val batchId = name.removeSuffix(".mvop").removeSuffix(".MVOP")
                val bytes = runCatching { httpApi.downloadBytesOrNull("${DropboxHttpApiClient.OPLOG_DIR}/$name") }
                    .getOrNull() ?: continue
                val batch = runCatching { DropboxSyncMerger.decryptDeltaBatch(session, batchId, bytes) }
                    .getOrNull() // дельты чужого контура/битые файлы просто пропускаем
                bytes.wipe()
                if (batch != null) remoteBatches += batch
            }

            // 4. Детерминированное CRDT-слияние (локальная дельта тоже участвует в порядке HLC)
            _syncPhaseFlow.value = DropboxSyncPhase.Running("Слияние изменений (CRDT)…", 0, 1)
            val allBatches = buildList {
                addAll(remoteBatches)
                localBatch?.let { add(it) }
            }
            val merged = DropboxSyncMerger.merge(
                localManifest = localManifest,
                remoteManifest = remoteManifest,
                deltaBatches = allBatches,
                nowEpochMs = System.currentTimeMillis(),
            )
            repository.applyMergedManifest(merged.mergedManifest, acknowledgedOpIds = pendingOpIds)

            val remoteOpCount = remoteBatches.sumOf { it.operations.size }

            // 5. Выгрузка локальной дельты
            localBatch?.let { batch ->
                _syncPhaseFlow.value = DropboxSyncPhase.Running("Выгрузка дельты (${batch.operations.size} оп.)…", 0, 1)
                val encrypted = DropboxSyncMerger.encryptDeltaBatch(session, batch)
                try {
                    httpApi.uploadSmallBytes(
                        "${DropboxHttpApiClient.OPLOG_DIR}/${batch.batchId}.mvop",
                        encrypted,
                    )
                    transferredBytes += encrypted.size
                } finally {
                    encrypted.wipe()
                }
            }

            // 6. Выгрузка недостающих blob-ов и превью
            val allMedia = repository.mediaFlow.first()
            val folders = repository.foldersFlow.first()
            val uploads = allMedia.filter { item ->
                (item.syncStatus == SyncItemStatus.LOCAL_ONLY || item.syncStatus == SyncItemStatus.QUEUED) &&
                    item.localBlobPresent &&
                    fileStore.hasLocalBlob(session.contour, item.id)
            }

            _syncPhaseFlow.value = DropboxSyncPhase.Running("Выгрузка зашифрованных файлов…", 0, uploads.size)
            var uploaded = 0
            for (item in uploads) {
                if (session.isLocked) break
                try {
                    val (blobPath, thumbPath) = session.withMacKey { kMac ->
                        cloudBlobPath(kMac, item.id) to cloudThumbPath(kMac, item.id)
                    }

                    val thumbFile = fileStore.thumbFile(session.contour, item.id)
                    if (thumbFile.exists()) {
                        httpApi.uploadSmallBytes(thumbPath, thumbFile.readBytes())
                    }

                    val blobFile = fileStore.blobFile(session.contour, item.id)
                    httpApi.uploadFileResumable(blobPath, blobFile) { sent, total ->
                        _syncPhaseFlow.value = DropboxSyncPhase.Running(
                            stepRu = "Выгрузка ${item.displayName}",
                            completedItems = uploaded,
                            totalItems = uploads.size,
                            transferredBytes = transferredBytes + sent,
                        )
                    }
                    transferredBytes += blobFile.length()

                    repository.upsertMedia(
                        item.copy(
                            syncStatus = SyncItemStatus.SYNCED_DROPBOX,
                            updatedAtMs = System.currentTimeMillis(),
                        ),
                    )
                    uploaded++
                    _syncPhaseFlow.value = DropboxSyncPhase.Running(
                        stepRu = "Выгрузка зашифрованных файлов…",
                        completedItems = uploaded,
                        totalItems = uploads.size,
                        transferredBytes = transferredBytes,
                    )
                } catch (net: IOException) {
                    // Сеть оборвалась — оставляем item в статусе QUEUED для повторной попытки
                    repository.upsertMedia(item.copy(syncStatus = SyncItemStatus.QUEUED))
                    throw net
                } catch (_: Throwable) {
                    repository.upsertMedia(item.copy(syncStatus = SyncItemStatus.QUEUED))
                }
            }

            // 7. Удаление облачных blob-ов, помеченных Tombstones
            for (purgedMediaId in merged.mediaIdsToPurgeInCloud) {
                val (blobPath, thumbPath) = session.withMacKey { kMac ->
                    cloudBlobPath(kMac, purgedMediaId) to cloudThumbPath(kMac, purgedMediaId)
                }
                runCatching { httpApi.deletePathIfExists(blobPath) }
                runCatching { httpApi.deletePathIfExists(thumbPath) }
            }

            // 8. Компактирование снапшота: манифест перезаписывается, применённые .mvop удаляются
            _syncPhaseFlow.value = DropboxSyncPhase.Running("Компактирование журнала изменений…", uploads.size, uploads.size + 1)
            val manifestBytes = DropboxSyncMerger.encryptManifest(session, merged.mergedManifest)
            try {
                httpApi.uploadSmallBytes(DropboxHttpApiClient.MANIFEST_PATH, manifestBytes)
            } finally {
                manifestBytes.wipe()
            }
            val compactedWallMs = merged.mergedManifest.compactedUpToHlc?.wallTimeMs ?: syncStartedAt
            for (name in remoteOplogNames) {
                val wallMs = name.substringBefore('_').toLongOrNull()
                if (wallMs == null || wallMs <= compactedWallMs) {
                    runCatching { httpApi.deletePathIfExists("${DropboxHttpApiClient.OPLOG_DIR}/$name") }
                }
            }

            // 9. Резервная копия vault_header.json для восстановления на новом устройстве
            uploadVaultHeaderBackupIfPossible()

            // 10. Лимит зашифрованного LRU-кэша On-Demand папок
            enforceOnDemandQuotaIfNeeded(folders = folders)

            refreshSpaceUsage()

            _syncPhaseFlow.value = DropboxSyncPhase.Completed(
                lastSyncedAtMs = System.currentTimeMillis(),
                uploadedDeltas = localBatch?.operations?.size ?: 0,
                downloadedItems = remoteOpCount,
            )
        } catch (e: IOException) {
            _syncPhaseFlow.value = DropboxSyncPhase.Error("Сеть недоступна или Dropbox ответил ошибкой: ${e.message ?: "unknown"}")
        } catch (e: Throwable) {
            _syncPhaseFlow.value = DropboxSyncPhase.Error("Ошибка синхронизации: ${e.message ?: "неизвестная ошибка"}")
        }
    }

    /**
     * Возвращает идентификаторы вытесненных из локального LRU-кэша On-Demand оригиналов.
     */
    private suspend fun enforceOnDemandQuotaIfNeeded(
        folders: List<VaultFolder>? = null,
    ): Set<String> {
        val settings = keystoreManager.settingsFlow.value
        val maxCacheBytes = settings.onDemandCacheLimitMb.toLong() * 1024L * 1024L
        val folderList = folders ?: repository.foldersFlow.first()
        val mediaList = repository.mediaFlow.first()
        val evicted = fileStore.enforceOnDemandSpaceSaverQuota(
            contour = session.contour,
            allFolders = folderList,
            allMedia = mediaList,
            maxCacheBytes = maxCacheBytes,
        )
        val evictedIds = mutableSetOf<String>()
        for (item in evicted) {
            repository.upsertMedia(item)
            evictedIds += item.id
        }
        return evictedIds
    }

    private fun isOnUnmeteredNetwork(): Boolean {
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
            ?: return false
        val network = cm.activeNetwork ?: return false
        val caps = cm.getNetworkCapabilities(network) ?: return false
        return caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED)
    }

    private fun cloudBlobPath(kMac: ByteArray, mediaId: String): String {
        val prefix = BlindIndex.cloudShardPrefix(kMac, mediaId)
        return "${DropboxHttpApiClient.BLOBS_DIR}/$prefix/$mediaId.mvbin"
    }

    private fun cloudThumbPath(kMac: ByteArray, mediaId: String): String {
        val prefix = BlindIndex.cloudShardPrefix(kMac, mediaId)
        return "${DropboxHttpApiClient.THUMBS_DIR}/$prefix/$mediaId.mvthumb"
    }
}

/**
 * Ручная регистрация активного замыкания синхронизации (без Hilt): приложение при старте сессии
 * назначает [activeRunner], после чего WorkManager может поднимать фоновую дельта-синхронизацию.
 */
object DropboxSyncWorkRegistry {
    @Volatile
    var activeRunner: (suspend () -> Unit)? = null

    fun enqueueOneTimeSync(context: Context) {
        val request = OneTimeWorkRequestBuilder<DropboxDeltaSyncWorker>()
            .setConstraints(
                Constraints.Builder()
                    .setRequiredNetworkType(NetworkType.CONNECTED)
                    .build(),
            )
            .build()
        WorkManager.getInstance(context).enqueueUniqueWork(
            UNIQUE_ONE_TIME,
            ExistingWorkPolicy.REPLACE,
            request,
        )
    }

    fun ensurePeriodicSyncScheduled(context: Context) {
        val request = PeriodicWorkRequestBuilder<DropboxDeltaSyncWorker>(6, TimeUnit.HOURS)
            .setConstraints(
                Constraints.Builder()
                    .setRequiredNetworkType(NetworkType.CONNECTED)
                    .build(),
            )
            .build()
        WorkManager.getInstance(context).enqueueUniquePeriodicWork(
            UNIQUE_PERIODIC,
            ExistingPeriodicWorkPolicy.KEEP,
            request,
        )
    }

    fun cancelAll(context: Context) {
        val wm = WorkManager.getInstance(context)
        wm.cancelUniqueWork(UNIQUE_ONE_TIME)
        wm.cancelUniqueWork(UNIQUE_PERIODIC)
    }

    private const val UNIQUE_ONE_TIME = "meshvault_dropbox_delta_sync_once"
    private const val UNIQUE_PERIODIC = "meshvault_dropbox_delta_sync_periodic"
}

/**
 * Фоновая дельта-синхронизация с Dropbox (раз в 6 часов + по требованию).
 * Выполняется только при разблокированном хранилище — ключевую сессию предоставляет приложение.
 */
class DropboxDeltaSyncWorker(
    appContext: Context,
    workerParams: WorkerParameters,
) : CoroutineWorker(appContext, workerParams) {

    override suspend fun doWork(): Result = withContext(Dispatchers.IO) {
        val runner = DropboxSyncWorkRegistry.activeRunner
        if (runner == null) {
            // Хранилище заблокировано или не открыто — повторять не имеет смысла до следующего цикла
            return@withContext Result.success()
        }
        return@withContext try {
            runner()
            Result.success()
        } catch (_: IOException) {
            if (runAttemptCount < MAX_ATTEMPTS) Result.retry() else Result.failure()
        } catch (_: Throwable) {
            Result.failure()
        }
    }

    private companion object {
        const val MAX_ATTEMPTS = 3
    }
}
