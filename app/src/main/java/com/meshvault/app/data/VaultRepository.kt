package com.meshvault.app.data

import android.content.Context
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.media.MediaMetadataRetriever
import android.net.Uri
import android.provider.OpenableColumns
import com.meshvault.app.crypto.CryptoManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.io.ByteArrayOutputStream
import java.io.File
import java.util.UUID
import javax.crypto.SecretKey

class VaultRepository(private val context: Context) {

    private val json = Json {
        ignoreUnknownKeys = true
        encodeDefaults = true
    }

    private val mutex = Mutex()
    private var activeKey: SecretKey? = null

    private val vaultFile: File
        get() = File(context.filesDir, "vault.enc")

    private val mediaDir: File
        get() = File(context.filesDir, "vault_media").apply { mkdirs() }

    private val thumbDir: File
        get() = File(context.filesDir, "vault_thumbs").apply { mkdirs() }

    private val previewCacheDir: File
        get() = File(context.cacheDir, "decrypted_preview").apply { mkdirs() }

    private val _isUnlocked = MutableStateFlow(false)
    val isUnlocked: StateFlow<Boolean> = _isUnlocked.asStateFlow()

    private val _database = MutableStateFlow(VaultDatabase())
    val database: StateFlow<VaultDatabase> = _database.asStateFlow()

    fun isInitialized(): Boolean = CryptoManager.isVaultInitialized(context)

    suspend fun createVault(masterPassword: CharArray) = withContext(Dispatchers.IO) {
        mutex.withLock {
            val key = CryptoManager.initializeVault(context, masterPassword)
            activeKey = key
            val emptyDb = VaultDatabase()
            saveDatabaseInternal(emptyDb, key)
            _database.value = emptyDb
            _isUnlocked.value = true
        }
    }

    suspend fun unlockWithPassword(masterPassword: CharArray): Boolean = withContext(Dispatchers.IO) {
        mutex.withLock {
            val key = CryptoManager.verifyAndDeriveKey(context, masterPassword) ?: return@withContext false
            loadDatabaseWithKey(key)
            true
        }
    }

    suspend fun unlockWithBiometrics(): Boolean = withContext(Dispatchers.IO) {
        mutex.withLock {
            val key = CryptoManager.getBiometricKey(context) ?: return@withContext false
            loadDatabaseWithKey(key)
            true
        }
    }

    private fun loadDatabaseWithKey(key: SecretKey) {
        activeKey = key
        val db = if (vaultFile.exists()) {
            val encrypted = vaultFile.readBytes()
            val plain = CryptoManager.decryptBytes(encrypted, key)
            json.decodeFromString<VaultDatabase>(plain.toString(Charsets.UTF_8))
        } else {
            VaultDatabase()
        }
        _database.value = db
        _isUnlocked.value = true
    }

    fun lock() {
        activeKey = null
        _database.value = VaultDatabase()
        _isUnlocked.value = false
        clearPreviewCache()
    }

    fun enableBiometrics(enabled: Boolean) {
        CryptoManager.setBiometricEnabled(context, enabled, activeKey)
    }

    fun clearPreviewCache() {
        previewCacheDir.listFiles()?.forEach { it.delete() }
    }

    suspend fun upsertVaultItem(item: VaultItem) = withContext(Dispatchers.IO) {
        mutex.withLock {
            val key = activeKey ?: return@withLock
            val current = _database.value
            val updatedList = current.items.toMutableList()
            val existingIdx = updatedList.indexOfFirst { it.id == item.id }
            val stamped = item.copy(updatedAt = System.currentTimeMillis())
            if (existingIdx >= 0) {
                updatedList[existingIdx] = stamped
            } else {
                updatedList.add(0, stamped)
            }
            val newDb = current.copy(items = updatedList)
            saveDatabaseInternal(newDb, key)
            _database.value = newDb
        }
    }

    suspend fun deleteVaultItem(itemId: String) = withContext(Dispatchers.IO) {
        mutex.withLock {
            val key = activeKey ?: return@withLock
            val current = _database.value
            val newDb = current.copy(items = current.items.filterNot { it.id == itemId })
            saveDatabaseInternal(newDb, key)
            _database.value = newDb
        }
    }

    suspend fun importMedia(uris: List<Uri>, album: String = "Основное") = withContext(Dispatchers.IO) {
        val key = activeKey ?: return@withContext
        val imported = mutableListOf<GalleryMediaItem>()

        for (uri in uris) {
            try {
                val resolver = context.contentResolver
                val mimeType = resolver.getType(uri) ?: "image/jpeg"
                val isVideo = mimeType.startsWith("video/")
                val mediaType = if (isVideo) MediaType.VIDEO else MediaType.IMAGE
                val displayName = queryDisplayName(uri) ?: "media_${System.currentTimeMillis()}"
                val id = UUID.randomUUID().toString()

                val encryptedFile = File(mediaDir, "$id.enc")
                resolver.openInputStream(uri)?.use { input ->
                    encryptedFile.outputStream().use { output ->
                        CryptoManager.encryptStream(input, output, key)
                    }
                } ?: continue

                var width = 0
                var height = 0
                var durationMs = 0L
                var thumbBitmap: Bitmap? = null

                if (isVideo) {
                    val retriever = MediaMetadataRetriever()
                    try {
                        retriever.setDataSource(context, uri)
                        width = retriever.extractMetadata(MediaMetadataRetriever.METADATA_KEY_VIDEO_WIDTH)?.toIntOrNull() ?: 0
                        height = retriever.extractMetadata(MediaMetadataRetriever.METADATA_KEY_VIDEO_HEIGHT)?.toIntOrNull() ?: 0
                        durationMs = retriever.extractMetadata(MediaMetadataRetriever.METADATA_KEY_DURATION)?.toLongOrNull() ?: 0L
                        thumbBitmap = retriever.getFrameAtTime(0)
                    } finally {
                        retriever.release()
                    }
                } else {
                    resolver.openInputStream(uri)?.use { stream ->
                        val options = BitmapFactory.Options().apply { inJustDecodeBounds = true }
                        BitmapFactory.decodeStream(stream, null, options)
                        width = options.outWidth
                        height = options.outHeight
                    }
                    resolver.openInputStream(uri)?.use { stream ->
                        val sampleSize = calculateInSampleSize(width, height, 400, 400)
                        val options = BitmapFactory.Options().apply { inSampleSize = sampleSize }
                        thumbBitmap = BitmapFactory.decodeStream(stream, null, options)
                    }
                }

                if (thumbBitmap != null) {
                    val scaled = scaleBitmapCenterCrop(thumbBitmap!!, 360)
                    val baos = ByteArrayOutputStream()
                    scaled.compress(Bitmap.CompressFormat.JPEG, 82, baos)
                    val encThumb = CryptoManager.encryptBytes(baos.toByteArray(), key)
                    File(thumbDir, "$id.thumb.enc").writeBytes(encThumb)
                    if (scaled !== thumbBitmap) scaled.recycle()
                    thumbBitmap?.recycle()
                }

                imported.add(
                    GalleryMediaItem(
                        id = id,
                        displayName = displayName,
                        mimeType = mimeType,
                        mediaType = mediaType,
                        album = album,
                        sizeBytes = encryptedFile.length(),
                        width = width,
                        height = height,
                        durationMs = durationMs
                    )
                )
            } catch (_: Exception) {
                // Пропускаем повреждённый или недоступный файл
            }
        }

        if (imported.isNotEmpty()) {
            mutex.withLock {
                val current = _database.value
                val newDb = current.copy(mediaItems = imported + current.mediaItems)
                saveDatabaseInternal(newDb, key)
                _database.value = newDb
            }
        }
    }

    suspend fun decryptThumbnail(mediaId: String): ByteArray? = withContext(Dispatchers.IO) {
        val key = activeKey ?: return@withContext null
        val thumbFile = File(thumbDir, "$mediaId.thumb.enc")
        if (!thumbFile.exists()) return@withContext null
        return@withContext try {
            CryptoManager.decryptBytes(thumbFile.readBytes(), key)
        } catch (_: Exception) {
            null
        }
    }

    suspend fun decryptMediaToTempFile(item: GalleryMediaItem): File? = withContext(Dispatchers.IO) {
        val key = activeKey ?: return@withContext null
        val encFile = File(mediaDir, "${item.id}.enc")
        if (!encFile.exists()) return@withContext null

        val ext = when {
            item.mimeType.contains("png") -> "png"
            item.mimeType.contains("webp") -> "webp"
            item.mimeType.contains("mp4") -> "mp4"
            item.mimeType.contains("mkv") -> "mkv"
            item.mediaType == MediaType.VIDEO -> "mp4"
            else -> "jpg"
        }
        val outFile = File(previewCacheDir, "${item.id}.$ext")
        if (outFile.exists() && outFile.length() > 0) return@withContext outFile

        return@withContext try {
            encFile.inputStream().use { input ->
                outFile.outputStream().use { output ->
                    CryptoManager.decryptToStream(input, output, key)
                }
            }
            outFile
        } catch (_: Exception) {
            outFile.delete()
            null
        }
    }

    suspend fun toggleMediaFavorite(mediaId: String) = withContext(Dispatchers.IO) {
        mutex.withLock {
            val key = activeKey ?: return@withLock
            val current = _database.value
            val updated = current.mediaItems.map {
                if (it.id == mediaId) it.copy(isFavorite = !it.isFavorite) else it
            }
            val newDb = current.copy(mediaItems = updated)
            saveDatabaseInternal(newDb, key)
            _database.value = newDb
        }
    }

    suspend fun deleteMediaItems(ids: Set<String>) = withContext(Dispatchers.IO) {
        mutex.withLock {
            val key = activeKey ?: return@withLock
            ids.forEach { id ->
                File(mediaDir, "$id.enc").delete()
                File(thumbDir, "$id.thumb.enc").delete()
                previewCacheDir.listFiles { _, name -> name.startsWith(id) }?.forEach { it.delete() }
            }
            val current = _database.value
            val newDb = current.copy(mediaItems = current.mediaItems.filterNot { it.id in ids })
            saveDatabaseInternal(newDb, key)
            _database.value = newDb
        }
    }

    private fun saveDatabaseInternal(db: VaultDatabase, key: SecretKey) {
        val raw = json.encodeToString(db).toByteArray(Charsets.UTF_8)
        val encrypted = CryptoManager.encryptBytes(raw, key)
        vaultFile.writeBytes(encrypted)
    }

    private fun queryDisplayName(uri: Uri): String? {
        context.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { cursor ->
            if (cursor.moveToFirst()) {
                val idx = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                if (idx >= 0) return cursor.getString(idx)
            }
        }
        return null
    }

    private fun calculateInSampleSize(width: Int, height: Int, reqWidth: Int, reqHeight: Int): Int {
        var inSampleSize = 1
        if (height > reqHeight || width > reqWidth) {
            val halfHeight = height / 2
            val halfWidth = width / 2
            while (halfHeight / inSampleSize >= reqHeight && halfWidth / inSampleSize >= reqWidth) {
                inSampleSize *= 2
            }
        }
        return inSampleSize
    }

    private fun scaleBitmapCenterCrop(src: Bitmap, size: Int): Bitmap {
        val minDim = minOf(src.width, src.height)
        val x = (src.width - minDim) / 2
        val y = (src.height - minDim) / 2
        val square = Bitmap.createBitmap(src, x, y, minDim, minDim)
        val scaled = Bitmap.createScaledBitmap(square, size, size, true)
        if (square !== src && square !== scaled) square.recycle()
        return scaled
    }
}
