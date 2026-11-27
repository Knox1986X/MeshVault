package com.meshvault.data.media

import android.content.Context
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.util.LruCache
import com.meshvault.crypto.MvchStreamCipher
import com.meshvault.crypto.VaultContour
import com.meshvault.crypto.VaultCryptoEngine
import com.meshvault.crypto.VaultSessionKeys
import com.meshvault.crypto.wipe
import com.meshvault.domain.media.BlurHashCodec
import com.meshvault.domain.model.MediaItem
import com.meshvault.domain.model.StoragePolicy
import com.meshvault.domain.model.SyncItemStatus
import com.meshvault.domain.model.VaultFolder
import com.meshvault.domain.repository.PerformanceProfile
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.withContext
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.nio.channels.FileChannel
import java.nio.file.StandardOpenOption
import kotlin.math.max

/**
 * Управляет зашифрованными файлами `.mvbin` и `.mvthumb` на диске, LruCache битмапов в ОЗУ
 * и квотой селективного офлайн-кэша (On-Demand Space Saver).
 */
class EncryptedMediaFileStore(
    private val context: Context,
    private var profile: PerformanceProfile = PerformanceProfile.AUTO,
) {
    @Volatile
    private var decodeSemaphore = Semaphore(profile.parallelDecodeWorkers)

    @Volatile
    private var bitmapCache: LruCache<String, Bitmap> = createBitmapLruCache(profile.thumbMemoryCacheMb)

    fun applyPerformanceProfile(newProfile: PerformanceProfile) {
        if (newProfile == profile) return
        profile = newProfile
        decodeSemaphore = Semaphore(newProfile.parallelDecodeWorkers)
        synchronized(this) {
            bitmapCache.resize(newProfile.thumbMemoryCacheMb * 1024 * 1024)
        }
    }

    /**
     * Мгновенная анти-форензик очистка кэша расшифрованных превью в ОЗУ при Panic Lock.
     */
    fun panicWipeMemoryCache() {
        synchronized(this) {
            bitmapCache.evictAll()
        }
    }

    fun blobFile(contour: VaultContour, mediaId: String): File =
        File(File(contourDir(contour), "blobs"), "$mediaId.mvbin").also { it.parentFile?.mkdirs() }

    fun thumbFile(contour: VaultContour, mediaId: String): File =
        File(File(contourDir(contour), "thumbs"), "$mediaId.mvthumb").also { it.parentFile?.mkdirs() }

    fun hasLocalBlob(contour: VaultContour, mediaId: String): Boolean {
        val f = blobFile(contour, mediaId)
        return f.exists() && f.length() > MvchStreamCipher.HEADER_BYTES
    }

    fun deleteMediaFiles(contour: VaultContour, mediaId: String) {
        synchronized(this) {
            bitmapCache.remove("thumb:$mediaId")
            bitmapCache.remove("full:$mediaId")
        }
        overwriteHeaderAndDelete(blobFile(contour, mediaId))
        overwriteHeaderAndDelete(thumbFile(contour, mediaId))
    }

    /**
     * Клонирует зашифрованный `.mvbin` и `.mvthumb` с перепривязкой криптографического AAD к [newMediaId].
     */
    suspend fun cloneEncryptedMedia(
        session: VaultSessionKeys,
        sourceMediaId: String,
        newMediaId: String,
    ) = withContext(Dispatchers.IO) {
        val srcThumb = thumbFile(session.contour, sourceMediaId)
        if (srcThumb.exists()) {
            val plainThumb = VaultCryptoEngine.decryptThumbnail(session, sourceMediaId, srcThumb.readBytes())
            try {
                val reEncryptedThumb = VaultCryptoEngine.encryptThumbnail(session, newMediaId, plainThumb)
                thumbFile(session.contour, newMediaId).writeBytes(reEncryptedThumb)
            } finally {
                plainThumb.wipe()
            }
        }

        val srcBlob = blobFile(session.contour, sourceMediaId)
        if (srcBlob.exists()) {
            val dstBlob = blobFile(session.contour, newMediaId)
            FileChannel.open(srcBlob.toPath(), StandardOpenOption.READ).use { srcChannel ->
                val hdr = session.withBlobKey { kBlob ->
                    MvchStreamCipher.readHeader(srcChannel, kBlob, sourceMediaId)
                }
                val outStream = ByteArrayOutputStream(minOf(hdr.totalPlaintextSize, 4_194_304L).toInt().coerceAtLeast(64))
                // Потоковое перешифрование чанк за чанком без временных файлов
                for (idx in 0 until hdr.totalChunks) {
                    val plainChunk = session.withBlobKey { kBlob ->
                        MvchStreamCipher.decryptChunkAtIndex(srcChannel, hdr, kBlob, sourceMediaId, idx)
                    }
                    outStream.write(plainChunk)
                    plainChunk.wipe()
                }
                val allPlain = outStream.toByteArray()
                try {
                    session.withBlobKey { kBlob ->
                        MvchStreamCipher.encryptToFile(
                            input = ByteArrayInputStream(allPlain),
                            targetFile = dstBlob,
                            kBlob = kBlob,
                            fileUuid = newMediaId,
                        )
                    }
                } finally {
                    allPlain.wipe()
                }
            }
        }
    }

    fun decodeBlurHashInstant(blurHash: String, aspectRatio: Float): Bitmap? {
        if (blurHash.isBlank()) return null
        val key = "blur:$blurHash"
        synchronized(this) {
            bitmapCache.get(key)?.let { if (!it.isRecycled) return it }
        }
        val outW = 28
        val outH = (outW / aspectRatio.coerceIn(0.3f, 3.3f)).toInt().coerceIn(12, 64)
        val bmp = BlurHashCodec.decode(blurHash, outWidth = outW, outHeight = outH).toAndroidBitmap()
        synchronized(this) {
            bitmapCache.put(key, bmp)
        }
        return bmp
    }

    suspend fun loadDecryptedThumbnail(session: VaultSessionKeys, mediaId: String): Bitmap? {
        if (session.isLocked) return null
        val cacheKey = "thumb:$mediaId"
        synchronized(this) {
            bitmapCache.get(cacheKey)?.let { if (!it.isRecycled) return it }
        }

        return withContext(Dispatchers.Default) {
            decodeSemaphore.withPermit {
                if (session.isLocked) return@withPermit null
                synchronized(this@EncryptedMediaFileStore) {
                    bitmapCache.get(cacheKey)?.let { if (!it.isRecycled) return@withPermit it }
                }
                val file = thumbFile(session.contour, mediaId)
                if (!file.exists()) return@withPermit null

                val plainBytes = runCatching {
                    VaultCryptoEngine.decryptThumbnail(session, mediaId, file.readBytes())
                }.getOrNull() ?: return@withPermit null

                try {
                    val bmp = BitmapFactory.decodeByteArray(plainBytes, 0, plainBytes.size)
                    if (bmp != null) {
                        synchronized(this@EncryptedMediaFileStore) {
                            bitmapCache.put(cacheKey, bmp)
                        }
                    }
                    bmp
                } finally {
                    plainBytes.wipe()
                }
            }
        }
    }

    /**
     * Расшифровывает полноразмерное фото из MVCH v2 прямо в ОЗУ для глубокого зума 16× и пипетки.
     */
    suspend fun loadFullResolutionPhoto(session: VaultSessionKeys, mediaId: String): Bitmap? {
        if (session.isLocked) return null
        val cacheKey = "full:$mediaId"
        synchronized(this) {
            bitmapCache.get(cacheKey)?.let { if (!it.isRecycled) return it }
        }

        return withContext(Dispatchers.IO) {
            val file = blobFile(session.contour, mediaId)
            if (!file.exists()) return@withContext loadDecryptedThumbnail(session, mediaId)
            file.setLastModified(System.currentTimeMillis())

            val plainBytes = runCatching {
                FileChannel.open(file.toPath(), StandardOpenOption.READ).use { fc ->
                    val hdr = session.withBlobKey { kBlob ->
                        MvchStreamCipher.readHeader(fc, kBlob, mediaId)
                    }
                    val buf = ByteArray(hdr.totalPlaintextSize.toInt())
                    session.withBlobKey { kBlob ->
                        MvchStreamCipher.readPlaintextRange(fc, hdr, kBlob, mediaId, 0L, buf, 0, buf.size)
                    }
                    buf
                }
            }.getOrNull() ?: return@withContext null

            try {
                val boundsOpts = BitmapFactory.Options().apply { inJustDecodeBounds = true }
                BitmapFactory.decodeByteArray(plainBytes, 0, plainBytes.size, boundsOpts)
                val maxDim = profile.maxDecodeDimensionPx
                var sampleSize = 1
                while (max(boundsOpts.outWidth, boundsOpts.outHeight) / sampleSize > maxDim) {
                    sampleSize *= 2
                }
                val decodeOpts = BitmapFactory.Options().apply {
                    inSampleSize = sampleSize
                    inPreferredConfig = Bitmap.Config.ARGB_8888
                }
                val fullBmp = BitmapFactory.decodeByteArray(plainBytes, 0, plainBytes.size, decodeOpts)
                if (fullBmp != null && fullBmp.allocationByteCount <= 24 * 1024 * 1024) {
                    synchronized(this@EncryptedMediaFileStore) {
                        bitmapCache.put(cacheKey, fullBmp)
                    }
                }
                fullBmp
            } finally {
                plainBytes.wipe()
            }
        }
    }

    /**
     * Контролирует лимит зашифрованного LRU-кэша для папок в режиме «Экономия места (On-Demand)»:
     * вытесняет давно не открывавшиеся `.mvbin` оригиналы (уже синхронизированные в Dropbox),
     * сохраняя локально лёгкие `.mvthumb` превью и BlurHash!
     */
    suspend fun enforceOnDemandSpaceSaverQuota(
        contour: VaultContour,
        allFolders: List<VaultFolder>,
        allMedia: List<MediaItem>,
        maxCacheBytes: Long,
    ): List<MediaItem> = withContext(Dispatchers.IO) {
        val onDemandFolderIds = allFolders
            .filter { it.storagePolicy == StoragePolicy.ON_DEMAND_SPACE_SAVER }
            .map { it.id }
            .toSet()

        if (onDemandFolderIds.isEmpty()) return@withContext emptyList()

        val candidates = allMedia.filter { item ->
            item.folderId in onDemandFolderIds &&
                item.localBlobPresent &&
                (item.syncStatus == SyncItemStatus.SYNCED_DROPBOX || item.syncStatus == SyncItemStatus.ON_DEMAND_CLOUD) &&
                hasLocalBlob(contour, item.id)
        }

        var currentCachedBytes = candidates.sumOf { blobFile(contour, it.id).length() }
        if (currentCachedBytes <= maxCacheBytes) return@withContext emptyList()

        val evicted = mutableListOf<MediaItem>()
        val sortedOldestFirst = candidates.sortedBy { blobFile(contour, it.id).lastModified() }
        for (item in sortedOldestFirst) {
            if (currentCachedBytes <= maxCacheBytes) break
            val f = blobFile(contour, item.id)
            val len = f.length()
            overwriteHeaderAndDelete(f)
            currentCachedBytes -= len
            evicted += item.copy(
                localBlobPresent = false,
                syncStatus = SyncItemStatus.ON_DEMAND_CLOUD,
            )
        }
        evicted
    }

    private fun contourDir(contour: VaultContour): File =
        File(File(context.filesDir, "vault_media"), contour.mediaNamespace)

    private fun overwriteHeaderAndDelete(file: File) {
        if (!file.exists()) return
        runCatching {
            FileChannel.open(file.toPath(), StandardOpenOption.WRITE).use { ch ->
                val wipeLen = minOf(file.length(), 4096L).toInt()
                if (wipeLen > 0) {
                    ch.position(0L)
                    ch.write(java.nio.ByteBuffer.allocate(wipeLen))
                }
            }
        }
        file.delete()
    }

    private fun createBitmapLruCache(sizeMb: Int): LruCache<String, Bitmap> {
        val maxBytes = sizeMb.coerceIn(12, 256) * 1024 * 1024
        return object : LruCache<String, Bitmap>(maxBytes) {
            override fun sizeOf(key: String, value: Bitmap): Int = value.allocationByteCount
        }
    }
}
