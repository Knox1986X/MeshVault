package com.meshvault.domain.sync

import com.meshvault.crypto.VaultCryptoEngine
import com.meshvault.crypto.VaultSessionKeys
import com.meshvault.domain.model.MediaItem
import com.meshvault.domain.model.SecretEntry
import com.meshvault.domain.model.VaultFolder
import com.meshvault.domain.model.VaultNote
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlin.math.max

/**
 * Гибридные логические часы (Hybrid Logical Clock) для строгого полного порядка операций CRDT
 * между несколькими устройствами даже при рассинхроне системного времени смартфона.
 */
@Serializable
data class HlcTimestamp(
    val wallTimeMs: Long,
    val counter: Int,
    val nodeId: String,
) : Comparable<HlcTimestamp> {

    override fun compareTo(other: HlcTimestamp): Int {
        val c1 = wallTimeMs.compareTo(other.wallTimeMs)
        if (c1 != 0) return c1
        val c2 = counter.compareTo(other.counter)
        if (c2 != 0) return c2
        return nodeId.compareTo(other.nodeId)
    }

    fun toFileSafeKey(): String = "%015d_%05d_%s".format(wallTimeMs, counter, nodeId.take(12))

    companion object {
        fun initial(nodeId: String): HlcTimestamp = HlcTimestamp(0L, 0, nodeId)
    }
}

class HlcClock(
    private val nodeId: String,
    initial: HlcTimestamp = HlcTimestamp.initial(nodeId),
) {
    private var last: HlcTimestamp = initial

    @Synchronized
    fun nextTick(nowMs: Long = System.currentTimeMillis()): HlcTimestamp {
        val nextWall = max(nowMs, last.wallTimeMs)
        val nextCounter = if (nextWall == last.wallTimeMs) last.counter + 1 else 0
        last = HlcTimestamp(nextWall, nextCounter, nodeId)
        return last
    }

    @Synchronized
    fun observeRemote(remote: HlcTimestamp, nowMs: Long = System.currentTimeMillis()): HlcTimestamp {
        val nextWall = max(nowMs, max(last.wallTimeMs, remote.wallTimeMs))
        val nextCounter = when {
            nextWall == last.wallTimeMs && nextWall == remote.wallTimeMs ->
                max(last.counter, remote.counter) + 1
            nextWall == last.wallTimeMs -> last.counter + 1
            nextWall == remote.wallTimeMs -> remote.counter + 1
            else -> 0
        }
        last = HlcTimestamp(nextWall, nextCounter, nodeId)
        return last
    }
}

@Serializable
enum class SyncEntityKind {
    FOLDER,
    MEDIA,
    SECRET,
    NOTE,
}

@Serializable
data class VersionedEntity<T>(
    val hlc: HlcTimestamp,
    val entity: T,
)

@Serializable
data class SyncTombstone(
    val kind: SyncEntityKind,
    val entityId: String,
    val deletedAtHlc: HlcTimestamp,
    val purgeCloudBlob: Boolean = false,
)

@Serializable
sealed interface SyncDeltaOp {
    val hlc: HlcTimestamp

    @Serializable
    data class UpsertFolder(override val hlc: HlcTimestamp, val folder: VaultFolder) : SyncDeltaOp

    @Serializable
    data class UpsertMedia(override val hlc: HlcTimestamp, val media: MediaItem) : SyncDeltaOp

    @Serializable
    data class UpsertSecret(override val hlc: HlcTimestamp, val secret: SecretEntry) : SyncDeltaOp

    @Serializable
    data class UpsertNote(override val hlc: HlcTimestamp, val note: VaultNote) : SyncDeltaOp

    @Serializable
    data class DeleteEntity(
        override val hlc: HlcTimestamp,
        val kind: SyncEntityKind,
        val entityId: String,
        val purgeCloudBlob: Boolean = true,
    ) : SyncDeltaOp
}

@Serializable
data class SyncDeltaBatch(
    val batchId: String,
    val deviceNodeId: String,
    val createdAtHlc: HlcTimestamp,
    val operations: List<SyncDeltaOp>,
)

@Serializable
data class VaultSyncManifest(
    val schemaVersion: Int = 2,
    val compactedUpToHlc: HlcTimestamp? = null,
    val folders: Map<String, VersionedEntity<VaultFolder>> = emptyMap(),
    val media: Map<String, VersionedEntity<MediaItem>> = emptyMap(),
    val secrets: Map<String, VersionedEntity<SecretEntry>> = emptyMap(),
    val notes: Map<String, VersionedEntity<VaultNote>> = emptyMap(),
    val tombstones: Map<String, SyncTombstone> = emptyMap(), // key = "${kind.name}:$entityId"
)

data class MergedSyncState(
    val mergedManifest: VaultSyncManifest,
    val mediaIdsToPurgeInCloud: Set<String>,
    val appliedOpCount: Int,
)

/**
 * CRDT-движок слияния манифестов и дельта-журнала oplog (Last-Write-Wins Element-Set + Tombstones).
 * Обеспечивает коммутативность, ассоциативность и идемпотентность синхронизации через Dropbox:
 *  - Изменение одного пароля или переименование папки отправляет крошечный `.mvop` (1–2 КБ);
 *  - Tombstones гарантируют, что удалённые дубликаты или пароли не «воскреснут» со второго телефона.
 */
object DropboxSyncMerger {
    private const val TOMBSTONE_RETENTION_MS = 90L * 86_400_000L // 90 суток хранения надгробий

    private val syncJson = Json {
        ignoreUnknownKeys = true
        encodeDefaults = true
        classDiscriminator = "_opType"
    }

    fun tombstoneKey(kind: SyncEntityKind, entityId: String): String = "${kind.name}:$entityId"

    fun merge(
        localManifest: VaultSyncManifest,
        remoteManifest: VaultSyncManifest?,
        deltaBatches: List<SyncDeltaBatch>,
        nowEpochMs: Long = System.currentTimeMillis(),
        tombstoneRetentionMs: Long = TOMBSTONE_RETENTION_MS,
    ): MergedSyncState {
        val folders = LinkedHashMap(localManifest.folders)
        val media = LinkedHashMap(localManifest.media)
        val secrets = LinkedHashMap(localManifest.secrets)
        val notes = LinkedHashMap(localManifest.notes)
        val tombstones = LinkedHashMap(localManifest.tombstones)
        val purgeMediaIds = LinkedHashSet<String>()

        var maxHlc: HlcTimestamp? = localManifest.compactedUpToHlc

        fun bumpMaxHlc(candidate: HlcTimestamp?) {
            if (candidate != null && (maxHlc == null || candidate > maxHlc!!)) {
                maxHlc = candidate
            }
        }

        // 1. Слияние двух снапшотов манифестов (локальный + облачный)
        if (remoteManifest != null) {
            bumpMaxHlc(remoteManifest.compactedUpToHlc)
            for ((k, remoteTomb) in remoteManifest.tombstones) {
                val existing = tombstones[k]
                if (existing == null || remoteTomb.deletedAtHlc > existing.deletedAtHlc) {
                    tombstones[k] = remoteTomb
                }
            }
            mergeMapInto(folders, remoteManifest.folders, SyncEntityKind.FOLDER, tombstones)
            mergeMapInto(media, remoteManifest.media, SyncEntityKind.MEDIA, tombstones)
            mergeMapInto(secrets, remoteManifest.secrets, SyncEntityKind.SECRET, tombstones)
            mergeMapInto(notes, remoteManifest.notes, SyncEntityKind.NOTE, tombstones)
        }

        // Применяем уже известные надгробия к локальным картам на случай более свежего удаления из remoteManifest
        enforceTombstonesOnMap(folders, SyncEntityKind.FOLDER, tombstones, purgeMediaIds)
        enforceTombstonesOnMap(media, SyncEntityKind.MEDIA, tombstones, purgeMediaIds)
        enforceTombstonesOnMap(secrets, SyncEntityKind.SECRET, tombstones, purgeMediaIds)
        enforceTombstonesOnMap(notes, SyncEntityKind.NOTE, tombstones, purgeMediaIds)

        // 2. Накатываем операции из дельта-журналов oplog в детерминированном порядке HLC
        val allOps = deltaBatches
            .flatMap { it.operations }
            .sortedBy { it.hlc }

        for (op in allOps) {
            bumpMaxHlc(op.hlc)
            when (op) {
                is SyncDeltaOp.UpsertFolder -> applyUpsert(
                    map = folders,
                    kind = SyncEntityKind.FOLDER,
                    id = op.folder.id,
                    hlc = op.hlc,
                    entity = op.folder,
                    tombstones = tombstones,
                )
                is SyncDeltaOp.UpsertMedia -> applyUpsert(
                    map = media,
                    kind = SyncEntityKind.MEDIA,
                    id = op.media.id,
                    hlc = op.hlc,
                    entity = op.media,
                    tombstones = tombstones,
                )
                is SyncDeltaOp.UpsertSecret -> applyUpsert(
                    map = secrets,
                    kind = SyncEntityKind.SECRET,
                    id = op.secret.id,
                    hlc = op.hlc,
                    entity = op.secret,
                    tombstones = tombstones,
                )
                is SyncDeltaOp.UpsertNote -> applyUpsert(
                    map = notes,
                    kind = SyncEntityKind.NOTE,
                    id = op.note.id,
                    hlc = op.hlc,
                    entity = op.note,
                    tombstones = tombstones,
                )
                is SyncDeltaOp.DeleteEntity -> {
                    val tKey = tombstoneKey(op.kind, op.entityId)
                    val prevTomb = tombstones[tKey]
                    val nextTomb = SyncTombstone(
                        kind = op.kind,
                        entityId = op.entityId,
                        deletedAtHlc = if (prevTomb != null && prevTomb.deletedAtHlc > op.hlc) {
                            prevTomb.deletedAtHlc
                        } else {
                            op.hlc
                        },
                        purgeCloudBlob = op.purgeCloudBlob || (prevTomb?.purgeCloudBlob == true),
                    )
                    tombstones[tKey] = nextTomb

                    when (op.kind) {
                        SyncEntityKind.FOLDER -> removeIfNotNewer(folders, op.entityId, nextTomb.deletedAtHlc)
                        SyncEntityKind.MEDIA -> {
                            val removed = removeIfNotNewer(media, op.entityId, nextTomb.deletedAtHlc)
                            if ((removed || op.entityId !in media) && nextTomb.purgeCloudBlob) {
                                purgeMediaIds += op.entityId
                            }
                        }
                        SyncEntityKind.SECRET -> removeIfNotNewer(secrets, op.entityId, nextTomb.deletedAtHlc)
                        SyncEntityKind.NOTE -> removeIfNotNewer(notes, op.entityId, nextTomb.deletedAtHlc)
                    }
                }
            }
        }

        // 3. Очистка устаревших Tombstones старше горизонта хранения
        val tombCutoffMs = nowEpochMs - tombstoneRetentionMs
        val prunedTombstones = tombstones.filterValues { it.deletedAtHlc.wallTimeMs >= tombCutoffMs }

        for (tomb in prunedTombstones.values) {
            if (tomb.kind == SyncEntityKind.MEDIA && tomb.purgeCloudBlob && tomb.entityId !in media) {
                purgeMediaIds += tomb.entityId
            }
        }

        val merged = VaultSyncManifest(
            schemaVersion = 2,
            compactedUpToHlc = maxHlc,
            folders = folders,
            media = media,
            secrets = secrets,
            notes = notes,
            tombstones = prunedTombstones,
        )

        return MergedSyncState(
            mergedManifest = merged,
            mediaIdsToPurgeInCloud = purgeMediaIds,
            appliedOpCount = allOps.size,
        )
    }

    fun encryptManifest(session: VaultSessionKeys, manifest: VaultSyncManifest): ByteArray {
        val raw = syncJson.encodeToString(manifest).toByteArray(Charsets.UTF_8)
        return VaultCryptoEngine.encryptMeta(session, "dropbox:manifest:v2", raw)
    }

    fun decryptManifest(session: VaultSessionKeys, encrypted: ByteArray): VaultSyncManifest {
        val plain = VaultCryptoEngine.decryptMeta(session, "dropbox:manifest:v2", encrypted)
        return syncJson.decodeFromString(String(plain, Charsets.UTF_8))
    }

    fun encryptDeltaBatch(session: VaultSessionKeys, batch: SyncDeltaBatch): ByteArray {
        val raw = syncJson.encodeToString(batch).toByteArray(Charsets.UTF_8)
        return VaultCryptoEngine.encryptMeta(session, "dropbox:oplog:${batch.batchId}", raw)
    }

    fun decryptDeltaBatch(session: VaultSessionKeys, batchId: String, encrypted: ByteArray): SyncDeltaBatch {
        val plain = VaultCryptoEngine.decryptMeta(session, "dropbox:oplog:$batchId", encrypted)
        return syncJson.decodeFromString(String(plain, Charsets.UTF_8))
    }

    private fun <T> mergeMapInto(
        target: MutableMap<String, VersionedEntity<T>>,
        incoming: Map<String, VersionedEntity<T>>,
        kind: SyncEntityKind,
        tombstones: MutableMap<String, SyncTombstone>,
    ) {
        for ((id, candidate) in incoming) {
            applyUpsert(target, kind, id, candidate.hlc, candidate.entity, tombstones)
        }
    }

    private fun <T> applyUpsert(
        map: MutableMap<String, VersionedEntity<T>>,
        kind: SyncEntityKind,
        id: String,
        hlc: HlcTimestamp,
        entity: T,
        tombstones: MutableMap<String, SyncTombstone>,
    ) {
        val tKey = tombstoneKey(kind, id)
        val tomb = tombstones[tKey]
        // Надгробие выигрывает, если его HLC >= HLC записи
        if (tomb != null && tomb.deletedAtHlc >= hlc) {
            map.remove(id)
            return
        }
        // Если пришёл строго более новый Upsert после удаления — надгробие снимается
        if (tomb != null && hlc > tomb.deletedAtHlc) {
            tombstones.remove(tKey)
        }
        val current = map[id]
        if (current == null || hlc > current.hlc) {
            map[id] = VersionedEntity(hlc = hlc, entity = entity)
        }
    }

    private fun <T> enforceTombstonesOnMap(
        map: MutableMap<String, VersionedEntity<T>>,
        kind: SyncEntityKind,
        tombstones: Map<String, SyncTombstone>,
        purgeMediaIds: MutableSet<String>,
    ) {
        val iterator = map.entries.iterator()
        while (iterator.hasNext()) {
            val (id, versioned) = iterator.next()
            val tomb = tombstones[tombstoneKey(kind, id)]
            if (tomb != null && tomb.deletedAtHlc >= versioned.hlc) {
                iterator.remove()
                if (kind == SyncEntityKind.MEDIA && tomb.purgeCloudBlob) {
                    purgeMediaIds += id
                }
            }
        }
    }

    private fun <T> removeIfNotNewer(
        map: MutableMap<String, VersionedEntity<T>>,
        id: String,
        deletedAt: HlcTimestamp,
    ): Boolean {
        val existing = map[id] ?: return false
        if (deletedAt >= existing.hlc) {
            map.remove(id)
            return true
        }
        return false
    }
}
