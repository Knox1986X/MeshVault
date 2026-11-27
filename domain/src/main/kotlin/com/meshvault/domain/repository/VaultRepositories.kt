package com.meshvault.domain.repository

import com.meshvault.domain.model.MediaItem
import com.meshvault.domain.model.SecretEntry
import com.meshvault.domain.model.StoragePolicy
import com.meshvault.domain.model.VaultFolder
import com.meshvault.domain.model.VaultNote
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.serialization.Serializable

@Serializable
enum class AutoLockTimeout(val delayMillis: Long, val labelRu: String) {
    IMMEDIATE(0L, "Мгновенно"),
    SEC_30(30_000L, "30 секунд"),
    MIN_1(60_000L, "1 минута"),
    MIN_5(300_000L, "5 минут"),
}

@Serializable
enum class PerformanceProfile(
    val labelRu: String,
    val descriptionRu: String,
    val thumbMemoryCacheMb: Int,
    val maxDecodeDimensionPx: Int,
    val parallelDecodeWorkers: Int,
) {
    AUTO(
        labelRu = "Авто",
        descriptionRu = "Сбалансированный кэш миниатюр и потоков декодирования под объём ОЗУ смартфона",
        thumbMemoryCacheMb = 48,
        maxDecodeDimensionPx = 3072,
        parallelDecodeWorkers = 4,
    ),
    RAM_SAVER(
        labelRu = "Экономия ОЗУ",
        descriptionRu = "Компактный пул битмапов для бюджетных устройств и больших папок",
        thumbMemoryCacheMb = 20,
        maxDecodeDimensionPx = 2048,
        parallelDecodeWorkers = 2,
    ),
    MAX_REFERENCE_QUALITY(
        labelRu = "Максимум качества референсов",
        descriptionRu = "Увеличенный LruCache и полное разрешение для глубокого зума 16×",
        thumbMemoryCacheMb = 96,
        maxDecodeDimensionPx = 6144,
        parallelDecodeWorkers = 6,
    ),
}

@Serializable
data class AppSecuritySettings(
    val flagSecureEnabled: Boolean = true,
    val biometricUnlockEnabled: Boolean = false,
    val shakeToPanicLockEnabled: Boolean = true,
    val autoLockTimeout: AutoLockTimeout = AutoLockTimeout.SEC_30,
    val clipboardAutoClearSeconds: Int = 25,
    val syncWifiOnly: Boolean = true,
    val onDemandCacheLimitMb: Int = 2048, // 2 ГБ по умолчанию
    val performanceProfile: PerformanceProfile = PerformanceProfile.AUTO,
)

@Serializable
data class DropboxQuotaInfo(
    val usedBytes: Long,
    val allocatedBytes: Long,
    val accountDisplayName: String = "",
) {
    val usedFraction: Float
        get() = if (allocatedBytes > 0L) {
            (usedBytes.toDouble() / allocatedBytes.toDouble()).toFloat().coerceIn(0f, 1f)
        } else {
            0f
        }
}

sealed interface DropboxSyncPhase {
    data object Idle : DropboxSyncPhase
    data class Running(
        val stepRu: String,
        val completedItems: Int,
        val totalItems: Int,
        val transferredBytes: Long = 0L,
    ) : DropboxSyncPhase
    data class Completed(val lastSyncedAtMs: Long, val uploadedDeltas: Int, val downloadedItems: Int) : DropboxSyncPhase
    data class Error(val messageRu: String) : DropboxSyncPhase
}

interface VaultDataRepository {
    val foldersFlow: Flow<List<VaultFolder>>
    val mediaFlow: Flow<List<MediaItem>>
    val secretsFlow: Flow<List<SecretEntry>>
    val notesFlow: Flow<List<VaultNote>>

    suspend fun upsertFolder(folder: VaultFolder)
    suspend fun updateFolderPolicy(folderId: String, policy: StoragePolicy)
    suspend fun deleteFolderCascade(folderId: String)

    suspend fun upsertMedia(item: MediaItem)
    suspend fun moveMediaItems(mediaIds: Set<String>, targetFolderId: String?)
    suspend fun copyMediaItems(mediaIds: Set<String>, targetFolderId: String?)
    suspend fun deleteMediaItems(mediaIds: Set<String>, purgeFromCloud: Boolean)

    suspend fun upsertSecret(entry: SecretEntry)
    suspend fun deleteSecret(secretId: String)

    suspend fun upsertNote(note: VaultNote)
    suspend fun deleteNote(noteId: String)
}

interface DropboxSyncGateway {
    val isConnectedFlow: StateFlow<Boolean>
    val syncPhaseFlow: StateFlow<DropboxSyncPhase>
    val quotaFlow: StateFlow<DropboxQuotaInfo?>

    suspend fun triggerDeltaSync(wifiOnly: Boolean)
    suspend fun ensureMediaBlobAvailableLocally(item: MediaItem, onProgress: (Float) -> Unit = {}): Boolean
    suspend fun refreshSpaceUsage()
    suspend fun disconnectAndWipeTokens()
}
