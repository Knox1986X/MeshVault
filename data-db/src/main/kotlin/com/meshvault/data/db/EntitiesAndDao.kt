package com.meshvault.data.db

import androidx.room.ColumnInfo
import androidx.room.Dao
import androidx.room.Entity
import androidx.room.Index
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.PrimaryKey
import androidx.room.Query
import kotlinx.coroutines.flow.Flow

@Entity(tableName = "enc_folders")
class EncryptedFolderRecord(
    @PrimaryKey
    @ColumnInfo(name = "id")
    val id: String,
    @ColumnInfo(name = "ciphertext", typeAffinity = ColumnInfo.BLOB)
    val ciphertext: ByteArray,
    @ColumnInfo(name = "hlc_wall_ms")
    val hlcWallMs: Long,
    @ColumnInfo(name = "hlc_counter")
    val hlcCounter: Int,
    @ColumnInfo(name = "hlc_node")
    val hlcNode: String,
)

@Entity(
    tableName = "enc_media",
    indices = [Index(value = ["blind_blake3_hmac"], unique = false)],
)
class EncryptedMediaRecord(
    @PrimaryKey
    @ColumnInfo(name = "id")
    val id: String,
    @ColumnInfo(name = "blind_blake3_hmac")
    val blindBlake3Hmac: String,
    @ColumnInfo(name = "ciphertext", typeAffinity = ColumnInfo.BLOB)
    val ciphertext: ByteArray,
    @ColumnInfo(name = "hlc_wall_ms")
    val hlcWallMs: Long,
    @ColumnInfo(name = "hlc_counter")
    val hlcCounter: Int,
    @ColumnInfo(name = "hlc_node")
    val hlcNode: String,
)

@Entity(tableName = "enc_secrets")
class EncryptedSecretRecord(
    @PrimaryKey
    @ColumnInfo(name = "id")
    val id: String,
    @ColumnInfo(name = "ciphertext", typeAffinity = ColumnInfo.BLOB)
    val ciphertext: ByteArray,
    @ColumnInfo(name = "hlc_wall_ms")
    val hlcWallMs: Long,
    @ColumnInfo(name = "hlc_counter")
    val hlcCounter: Int,
    @ColumnInfo(name = "hlc_node")
    val hlcNode: String,
)

@Entity(tableName = "enc_notes")
class EncryptedNoteRecord(
    @PrimaryKey
    @ColumnInfo(name = "id")
    val id: String,
    @ColumnInfo(name = "ciphertext", typeAffinity = ColumnInfo.BLOB)
    val ciphertext: ByteArray,
    @ColumnInfo(name = "hlc_wall_ms")
    val hlcWallMs: Long,
    @ColumnInfo(name = "hlc_counter")
    val hlcCounter: Int,
    @ColumnInfo(name = "hlc_node")
    val hlcNode: String,
)

@Entity(tableName = "enc_tombstones")
class EncryptedTombstoneRecord(
    @PrimaryKey
    @ColumnInfo(name = "tomb_key")
    val tombKey: String,
    @ColumnInfo(name = "kind")
    val kind: String,
    @ColumnInfo(name = "entity_id")
    val entityId: String,
    @ColumnInfo(name = "hlc_wall_ms")
    val hlcWallMs: Long,
    @ColumnInfo(name = "hlc_counter")
    val hlcCounter: Int,
    @ColumnInfo(name = "hlc_node")
    val hlcNode: String,
    @ColumnInfo(name = "purge_cloud_blob")
    val purgeCloudBlob: Boolean,
)

@Entity(tableName = "pending_sync_ops")
class PendingSyncOpRecord(
    @PrimaryKey
    @ColumnInfo(name = "op_id")
    val opId: String,
    @ColumnInfo(name = "hlc_key")
    val hlcKey: String,
    @ColumnInfo(name = "ciphertext", typeAffinity = ColumnInfo.BLOB)
    val ciphertext: ByteArray,
    @ColumnInfo(name = "created_at_ms")
    val createdAtMs: Long,
)

@Dao
interface MeshVaultDao {
    @Query("SELECT * FROM enc_folders")
    fun observeFolders(): Flow<List<EncryptedFolderRecord>>

    @Query("SELECT * FROM enc_folders")
    suspend fun getAllFolders(): List<EncryptedFolderRecord>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertFolder(record: EncryptedFolderRecord)

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertFolders(records: List<EncryptedFolderRecord>)

    @Query("DELETE FROM enc_folders WHERE id = :id")
    suspend fun deleteFolderById(id: String)

    @Query("DELETE FROM enc_folders")
    suspend fun clearFolders()

    @Query("SELECT * FROM enc_media")
    fun observeMedia(): Flow<List<EncryptedMediaRecord>>

    @Query("SELECT * FROM enc_media")
    suspend fun getAllMedia(): List<EncryptedMediaRecord>

    @Query("SELECT * FROM enc_media WHERE id = :id LIMIT 1")
    suspend fun getMediaById(id: String): EncryptedMediaRecord?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertMedia(record: EncryptedMediaRecord)

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertMediaList(records: List<EncryptedMediaRecord>)

    @Query("DELETE FROM enc_media WHERE id IN (:ids)")
    suspend fun deleteMediaByIds(ids: List<String>)

    @Query("DELETE FROM enc_media")
    suspend fun clearMedia()

    @Query("SELECT * FROM enc_secrets")
    fun observeSecrets(): Flow<List<EncryptedSecretRecord>>

    @Query("SELECT * FROM enc_secrets")
    suspend fun getAllSecrets(): List<EncryptedSecretRecord>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertSecret(record: EncryptedSecretRecord)

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertSecrets(records: List<EncryptedSecretRecord>)

    @Query("DELETE FROM enc_secrets WHERE id = :id")
    suspend fun deleteSecretById(id: String)

    @Query("DELETE FROM enc_secrets")
    suspend fun clearSecrets()

    @Query("SELECT * FROM enc_notes")
    fun observeNotes(): Flow<List<EncryptedNoteRecord>>

    @Query("SELECT * FROM enc_notes")
    suspend fun getAllNotes(): List<EncryptedNoteRecord>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertNote(record: EncryptedNoteRecord)

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertNotes(records: List<EncryptedNoteRecord>)

    @Query("DELETE FROM enc_notes WHERE id = :id")
    suspend fun deleteNoteById(id: String)

    @Query("DELETE FROM enc_notes")
    suspend fun clearNotes()

    @Query("SELECT * FROM enc_tombstones")
    suspend fun getAllTombstones(): List<EncryptedTombstoneRecord>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertTombstone(record: EncryptedTombstoneRecord)

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertTombstones(records: List<EncryptedTombstoneRecord>)

    @Query("DELETE FROM enc_tombstones")
    suspend fun clearTombstones()

    @Query("SELECT * FROM pending_sync_ops ORDER BY hlc_key ASC")
    suspend fun getPendingSyncOps(): List<PendingSyncOpRecord>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertPendingSyncOp(record: PendingSyncOpRecord)

    @Query("DELETE FROM pending_sync_ops WHERE op_id IN (:opIds)")
    suspend fun deletePendingSyncOps(opIds: List<String>)
}
