package com.meshvault.data.db

import androidx.room.withTransaction
import com.meshvault.crypto.VaultCryptoEngine
import com.meshvault.crypto.VaultSessionKeys
import com.meshvault.domain.model.FolderTreeNavigator
import com.meshvault.domain.model.MediaItem
import com.meshvault.domain.model.SecretEntry
import com.meshvault.domain.model.StoragePolicy
import com.meshvault.domain.model.SyncItemStatus
import com.meshvault.domain.model.VaultFolder
import com.meshvault.domain.model.VaultNote
import com.meshvault.domain.repository.VaultDataRepository
import com.meshvault.domain.sync.DropboxSyncMerger
import com.meshvault.domain.sync.HlcClock
import com.meshvault.domain.sync.HlcTimestamp
import com.meshvault.domain.sync.SyncDeltaBatch
import com.meshvault.domain.sync.SyncDeltaOp
import com.meshvault.domain.sync.SyncEntityKind
import com.meshvault.domain.sync.SyncTombstone
import com.meshvault.domain.sync.VaultSyncManifest
import com.meshvault.domain.sync.VersionedEntity
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.withContext
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.util.UUID

class EncryptedVaultRepositoryImpl(
    private val database: MeshVaultDatabase,
    private val session: VaultSessionKeys,
    private val deviceNodeId: String,
    private val onDeleteLocalMediaFiles: suspend (mediaId: String) -> Unit = {},
    private val onCloneLocalMediaFiles: suspend (sourceId: String, newId: String) -> Unit = { _, _ -> },
) : VaultDataRepository {

    private val dao: MeshVaultDao = database.vaultDao()
    private val hlcClock = HlcClock(deviceNodeId)

    private val json = Json {
        ignoreUnknownKeys = true
        encodeDefaults = true
        classDiscriminator = "_type"
    }

    override val foldersFlow: Flow<List<VaultFolder>> = dao.observeFolders()
        .map { rows ->
            if (session.isLocked) emptyList()
            else rows.mapNotNull { decodeFolderOrNull(it) }
                .sortedWith(compareByDescending<VaultFolder> { it.isPinned }.thenBy { it.name.lowercase() })
        }
        .flowOn(Dispatchers.Default)

    override val mediaFlow: Flow<List<MediaItem>> = dao.observeMedia()
        .map { rows ->
            if (session.isLocked) emptyList()
            else rows.mapNotNull { decodeMediaOrNull(it) }
                .sortedByDescending { it.createdAtMs }
        }
        .flowOn(Dispatchers.Default)

    override val secretsFlow: Flow<List<SecretEntry>> = dao.observeSecrets()
        .map { rows ->
            if (session.isLocked) emptyList()
            else rows.mapNotNull { decodeSecretOrNull(it) }
                .sortedWith(compareByDescending<SecretEntry> { it.isFavorite }.thenBy { it.title.lowercase() })
        }
        .flowOn(Dispatchers.Default)

    override val notesFlow: Flow<List<VaultNote>> = dao.observeNotes()
        .map { rows ->
            if (session.isLocked) emptyList()
            else rows.mapNotNull { decodeNoteOrNull(it) }
                .sortedWith(compareByDescending<VaultNote> { it.isPinned }.thenByDescending { it.updatedAtMs })
        }
        .flowOn(Dispatchers.Default)

    override suspend fun upsertFolder(folder: VaultFolder) = withContext(Dispatchers.IO) {
        val hlc = hlcClock.nextTick()
        val record = encodeFolder(folder, hlc)
        val op = SyncDeltaOp.UpsertFolder(hlc, folder)
        database.withTransaction {
            dao.upsertFolder(record)
            enqueueDeltaOp(op)
        }
    }

    override suspend fun updateFolderPolicy(folderId: String, policy: StoragePolicy) = withContext(Dispatchers.IO) {
        val all = dao.getAllFolders().mapNotNull(::decodeFolderOrNull)
        val target = all.find { it.id == folderId } ?: return@withContext
        val updated = target.copy(storagePolicy = policy, updatedAtMs = System.currentTimeMillis())
        upsertFolder(updated)
    }

    override suspend fun deleteFolderCascade(folderId: String) = withContext(Dispatchers.IO) {
        val allFolders = dao.getAllFolders().mapNotNull(::decodeFolderOrNull)
        val affectedFolderIds = FolderTreeNavigator.descendantFolderIdsInclusive(allFolders, folderId)
        val allMedia = dao.getAllMedia().mapNotNull(::decodeMediaOrNull)
        val affectedMediaIds = allMedia.filter { it.folderId in affectedFolderIds }.map { it.id }.toSet()

        if (affectedMediaIds.isNotEmpty()) {
            deleteMediaItems(affectedMediaIds, purgeFromCloud = true)
        }

        database.withTransaction {
            for (fId in affectedFolderIds) {
                val hlc = hlcClock.nextTick()
                dao.deleteFolderById(fId)
                dao.upsertTombstone(
                    EncryptedTombstoneRecord(
                        tombKey = DropboxSyncMerger.tombstoneKey(SyncEntityKind.FOLDER, fId),
                        kind = SyncEntityKind.FOLDER.name,
                        entityId = fId,
                        hlcWallMs = hlc.wallTimeMs,
                        hlcCounter = hlc.counter,
                        hlcNode = hlc.nodeId,
                        purgeCloudBlob = false,
                    ),
                )
                enqueueDeltaOp(SyncDeltaOp.DeleteEntity(hlc, SyncEntityKind.FOLDER, fId, purgeCloudBlob = false))
            }
        }
    }

    override suspend fun upsertMedia(item: MediaItem) = withContext(Dispatchers.IO) {
        val hlc = hlcClock.nextTick()
        val record = encodeMedia(item, hlc)
        val op = SyncDeltaOp.UpsertMedia(hlc, item)
        database.withTransaction {
            dao.upsertMedia(record)
            enqueueDeltaOp(op)
        }
    }

    override suspend fun moveMediaItems(mediaIds: Set<String>, targetFolderId: String?) = withContext(Dispatchers.IO) {
        if (mediaIds.isEmpty()) return@withContext
        val now = System.currentTimeMillis()
        val existing = dao.getAllMedia().mapNotNull(::decodeMediaOrNull).filter { it.id in mediaIds }
        database.withTransaction {
            for (item in existing) {
                val moved = item.copy(
                    folderId = targetFolderId,
                    syncStatus = if (item.syncStatus == SyncItemStatus.SYNCED_DROPBOX) {
                        SyncItemStatus.QUEUED
                    } else {
                        item.syncStatus
                    },
                    updatedAtMs = now,
                )
                val hlc = hlcClock.nextTick(now)
                dao.upsertMedia(encodeMedia(moved, hlc))
                enqueueDeltaOp(SyncDeltaOp.UpsertMedia(hlc, moved))
            }
        }
    }

    override suspend fun copyMediaItems(mediaIds: Set<String>, targetFolderId: String?) = withContext(Dispatchers.IO) {
        if (mediaIds.isEmpty()) return@withContext
        val now = System.currentTimeMillis()
        val existing = dao.getAllMedia().mapNotNull(::decodeMediaOrNull).filter { it.id in mediaIds }
        for (item in existing) {
            val newId = UUID.randomUUID().toString()
            onCloneLocalMediaFiles(item.id, newId)
            val cloned = item.copy(
                id = newId,
                folderId = targetFolderId,
                syncStatus = SyncItemStatus.QUEUED,
                createdAtMs = now,
                updatedAtMs = now,
            )
            upsertMedia(cloned)
        }
    }

    override suspend fun deleteMediaItems(mediaIds: Set<String>, purgeFromCloud: Boolean) =
        withContext(Dispatchers.IO) {
            if (mediaIds.isEmpty()) return@withContext
            database.withTransaction {
                dao.deleteMediaByIds(mediaIds.toList())
                for (id in mediaIds) {
                    val hlc = hlcClock.nextTick()
                    dao.upsertTombstone(
                        EncryptedTombstoneRecord(
                            tombKey = DropboxSyncMerger.tombstoneKey(SyncEntityKind.MEDIA, id),
                            kind = SyncEntityKind.MEDIA.name,
                            entityId = id,
                            hlcWallMs = hlc.wallTimeMs,
                            hlcCounter = hlc.counter,
                            hlcNode = hlc.nodeId,
                            purgeCloudBlob = purgeFromCloud,
                        ),
                    )
                    enqueueDeltaOp(
                        SyncDeltaOp.DeleteEntity(
                            hlc = hlc,
                            kind = SyncEntityKind.MEDIA,
                            entityId = id,
                            purgeCloudBlob = purgeFromCloud,
                        ),
                    )
                }
            }
            for (id in mediaIds) {
                onDeleteLocalMediaFiles(id)
            }
        }

    override suspend fun upsertSecret(entry: SecretEntry) = withContext(Dispatchers.IO) {
        val hlc = hlcClock.nextTick()
        val record = encodeSecret(entry, hlc)
        val op = SyncDeltaOp.UpsertSecret(hlc, entry)
        database.withTransaction {
            dao.upsertSecret(record)
            enqueueDeltaOp(op)
        }
    }

    override suspend fun deleteSecret(secretId: String) = withContext(Dispatchers.IO) {
        val hlc = hlcClock.nextTick()
        database.withTransaction {
            dao.deleteSecretById(secretId)
            dao.upsertTombstone(
                EncryptedTombstoneRecord(
                    tombKey = DropboxSyncMerger.tombstoneKey(SyncEntityKind.SECRET, secretId),
                    kind = SyncEntityKind.SECRET.name,
                    entityId = secretId,
                    hlcWallMs = hlc.wallTimeMs,
                    hlcCounter = hlc.counter,
                    hlcNode = hlc.nodeId,
                    purgeCloudBlob = false,
                ),
            )
            enqueueDeltaOp(SyncDeltaOp.DeleteEntity(hlc, SyncEntityKind.SECRET, secretId, purgeCloudBlob = false))
        }
    }

    override suspend fun upsertNote(note: VaultNote) = withContext(Dispatchers.IO) {
        val hlc = hlcClock.nextTick()
        val record = encodeNote(note, hlc)
        val op = SyncDeltaOp.UpsertNote(hlc, note)
        database.withTransaction {
            dao.upsertNote(record)
            enqueueDeltaOp(op)
        }
    }

    override suspend fun deleteNote(noteId: String) = withContext(Dispatchers.IO) {
        val hlc = hlcClock.nextTick()
        database.withTransaction {
            dao.deleteNoteById(noteId)
            dao.upsertTombstone(
                EncryptedTombstoneRecord(
                    tombKey = DropboxSyncMerger.tombstoneKey(SyncEntityKind.NOTE, noteId),
                    kind = SyncEntityKind.NOTE.name,
                    entityId = noteId,
                    hlcWallMs = hlc.wallTimeMs,
                    hlcCounter = hlc.counter,
                    hlcNode = hlc.nodeId,
                    purgeCloudBlob = false,
                ),
            )
            enqueueDeltaOp(SyncDeltaOp.DeleteEntity(hlc, SyncEntityKind.NOTE, noteId, purgeCloudBlob = false))
        }
    }

    /**
     * Выгружает локальный CRDT-манифест и накопленные локальные дельта-операции для синхронизации с Dropbox.
     */
    suspend fun exportLocalSyncBundle(): Triple<VaultSyncManifest, SyncDeltaBatch?, List<String>> =
        withContext(Dispatchers.IO) {
            val foldersMap = dao.getAllFolders().mapNotNull { rec ->
                val f = decodeFolderOrNull(rec) ?: return@mapNotNull null
                f.id to VersionedEntity(HlcTimestamp(rec.hlcWallMs, rec.hlcCounter, rec.hlcNode), f)
            }.toMap()

            val mediaMap = dao.getAllMedia().mapNotNull { rec ->
                val m = decodeMediaOrNull(rec) ?: return@mapNotNull null
                m.id to VersionedEntity(HlcTimestamp(rec.hlcWallMs, rec.hlcCounter, rec.hlcNode), m)
            }.toMap()

            val secretsMap = dao.getAllSecrets().mapNotNull { rec ->
                val s = decodeSecretOrNull(rec) ?: return@mapNotNull null
                s.id to VersionedEntity(HlcTimestamp(rec.hlcWallMs, rec.hlcCounter, rec.hlcNode), s)
            }.toMap()

            val notesMap = dao.getAllNotes().mapNotNull { rec ->
                val n = decodeNoteOrNull(rec) ?: return@mapNotNull null
                n.id to VersionedEntity(HlcTimestamp(rec.hlcWallMs, rec.hlcCounter, rec.hlcNode), n)
            }.toMap()

            val tombsMap = dao.getAllTombstones().associate { rec ->
                rec.tombKey to SyncTombstone(
                    kind = SyncEntityKind.valueOf(rec.kind),
                    entityId = rec.entityId,
                    deletedAtHlc = HlcTimestamp(rec.hlcWallMs, rec.hlcCounter, rec.hlcNode),
                    purgeCloudBlob = rec.purgeCloudBlob,
                )
            }

            val pendingRows = dao.getPendingSyncOps()
            val decodedOps = pendingRows.mapNotNull { row ->
                runCatching {
                    val plain = VaultCryptoEngine.decryptMetaString(session, "pending_op:${row.opId}", row.ciphertext)
                    json.decodeFromString<SyncDeltaOp>(plain)
                }.getOrNull()
            }

            val batch = if (decodedOps.isNotEmpty()) {
                val batchHlc = hlcClock.nextTick()
                SyncDeltaBatch(
                    batchId = "${batchHlc.toFileSafeKey()}_${UUID.randomUUID().toString().take(6)}",
                    deviceNodeId = deviceNodeId,
                    createdAtHlc = batchHlc,
                    operations = decodedOps,
                )
            } else {
                null
            }

            val manifest = VaultSyncManifest(
                schemaVersion = 2,
                folders = foldersMap,
                media = mediaMap,
                secrets = secretsMap,
                notes = notesMap,
                tombstones = tombsMap,
            )

            Triple(manifest, batch, pendingRows.map { it.opId })
        }

    /**
     * Атомарно записывает результат CRDT-слияния в SQLCipher БД и удаляет подтверждённые локальные дельты.
     */
    suspend fun applyMergedManifest(
        merged: VaultSyncManifest,
        acknowledgedOpIds: List<String>,
    ) = withContext(Dispatchers.IO) {
        merged.compactedUpToHlc?.let { hlcClock.observeRemote(it) }

        val folderRecords = merged.folders.values.map { encodeFolder(it.entity, it.hlc) }
        val mediaRecords = merged.media.values.map { encodeMedia(it.entity, it.hlc) }
        val secretRecords = merged.secrets.values.map { encodeSecret(it.entity, it.hlc) }
        val noteRecords = merged.notes.values.map { encodeNote(it.entity, it.hlc) }
        val tombRecords = merged.tombstones.map { (key, t) ->
            EncryptedTombstoneRecord(
                tombKey = key,
                kind = t.kind.name,
                entityId = t.entityId,
                hlcWallMs = t.deletedAtHlc.wallTimeMs,
                hlcCounter = t.deletedAtHlc.counter,
                hlcNode = t.deletedAtHlc.nodeId,
                purgeCloudBlob = t.purgeCloudBlob,
            )
        }

        database.withTransaction {
            dao.clearFolders()
            dao.upsertFolders(folderRecords)

            dao.clearMedia()
            dao.upsertMediaList(mediaRecords)

            dao.clearSecrets()
            dao.upsertSecrets(secretRecords)

            dao.clearNotes()
            dao.upsertNotes(noteRecords)

            dao.clearTombstones()
            dao.upsertTombstones(tombRecords)

            if (acknowledgedOpIds.isNotEmpty()) {
                dao.deletePendingSyncOps(acknowledgedOpIds)
            }
        }
    }

    private suspend fun enqueueDeltaOp(op: SyncDeltaOp) {
        val opId = UUID.randomUUID().toString()
        val raw = json.encodeToString<SyncDeltaOp>(op)
        val encrypted = VaultCryptoEngine.encryptMetaString(session, "pending_op:$opId", raw)
        dao.insertPendingSyncOp(
            PendingSyncOpRecord(
                opId = opId,
                hlcKey = op.hlc.toFileSafeKey(),
                ciphertext = encrypted,
                createdAtMs = op.hlc.wallTimeMs,
            ),
        )
    }

    private fun encodeFolder(folder: VaultFolder, hlc: HlcTimestamp): EncryptedFolderRecord {
        val ct = VaultCryptoEngine.encryptMetaString(session, "folder:${folder.id}", json.encodeToString(folder))
        return EncryptedFolderRecord(folder.id, ct, hlc.wallTimeMs, hlc.counter, hlc.nodeId)
    }

    private fun decodeFolderOrNull(rec: EncryptedFolderRecord): VaultFolder? = runCatching {
        val plain = VaultCryptoEngine.decryptMetaString(session, "folder:${rec.id}", rec.ciphertext)
        json.decodeFromString<VaultFolder>(plain)
    }.getOrNull()

    private fun encodeMedia(item: MediaItem, hlc: HlcTimestamp): EncryptedMediaRecord {
        val ct = VaultCryptoEngine.encryptMetaString(session, "media:${item.id}", json.encodeToString(item))
        return EncryptedMediaRecord(
            id = item.id,
            blindBlake3Hmac = item.cryptoBlake3BlindHex,
            ciphertext = ct,
            hlcWallMs = hlc.wallTimeMs,
            hlcCounter = hlc.counter,
            hlcNode = hlc.nodeId,
        )
    }

    private fun decodeMediaOrNull(rec: EncryptedMediaRecord): MediaItem? = runCatching {
        val plain = VaultCryptoEngine.decryptMetaString(session, "media:${rec.id}", rec.ciphertext)
        json.decodeFromString<MediaItem>(plain)
    }.getOrNull()

    private fun encodeSecret(entry: SecretEntry, hlc: HlcTimestamp): EncryptedSecretRecord {
        val ct = VaultCryptoEngine.encryptMetaString(session, "secret:${entry.id}", json.encodeToString(entry))
        return EncryptedSecretRecord(entry.id, ct, hlc.wallTimeMs, hlc.counter, hlc.nodeId)
    }

    private fun decodeSecretOrNull(rec: EncryptedSecretRecord): SecretEntry? = runCatching {
        val plain = VaultCryptoEngine.decryptMetaString(session, "secret:${rec.id}", rec.ciphertext)
        json.decodeFromString<SecretEntry>(plain)
    }.getOrNull()

    private fun encodeNote(note: VaultNote, hlc: HlcTimestamp): EncryptedNoteRecord {
        val ct = VaultCryptoEngine.encryptMetaString(session, "note:${note.id}", json.encodeToString(note))
        return EncryptedNoteRecord(note.id, ct, hlc.wallTimeMs, hlc.counter, hlc.nodeId)
    }

    private fun decodeNoteOrNull(rec: EncryptedNoteRecord): VaultNote? = runCatching {
        val plain = VaultCryptoEngine.decryptMetaString(session, "note:${rec.id}", rec.ciphertext)
        json.decodeFromString<VaultNote>(plain)
    }.getOrNull()
}
