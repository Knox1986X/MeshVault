package com.meshvault.data.media

import android.content.ContentResolver
import android.content.Context
import android.content.IntentSender
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.media.MediaMetadataRetriever
import android.net.Uri
import android.os.Build
import android.provider.MediaStore
import android.provider.OpenableColumns
import androidx.exifinterface.media.ExifInterface
import androidx.work.CoroutineWorker
import androidx.work.ListenableWorker.Result
import androidx.work.WorkerParameters
import com.meshvault.crypto.Blake3Hasher
import com.meshvault.crypto.BlindIndex
import com.meshvault.crypto.MvchStreamCipher
import com.meshvault.crypto.VaultCryptoEngine
import com.meshvault.crypto.VaultSessionKeys
import com.meshvault.crypto.wipe
import com.meshvault.domain.media.BlurHashCodec
import com.meshvault.domain.media.ColorInspector
import com.meshvault.domain.media.DuplicateCandidateInput
import com.meshvault.domain.media.ImportDuplicateHit
import com.meshvault.domain.media.ImportDuplicateStrategy
import com.meshvault.domain.media.PerceptualHasher
import com.meshvault.domain.model.MediaItem
import com.meshvault.domain.model.MediaKind
import com.meshvault.domain.model.SyncItemStatus
import com.meshvault.domain.repository.VaultDataRepository
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.ByteArrayInputStream
import java.util.UUID
import kotlin.math.max
import kotlin.math.min
import kotlin.math.roundToInt

data class StagedImportItem(
    val uri: Uri,
    val displayName: String,
    val mimeType: String,
    val kind: MediaKind,
    val candidateInfo: DuplicateCandidateInput?,
)

data class ImportPreflightReport(
    val stagedItems: List<StagedImportItem>,
    val duplicateHits: List<ImportDuplicateHit>,
)

data class ImportExecutionOutcome(
    val importedCount: Int,
    val skippedDuplicatesCount: Int,
    val replacedCount: Int,
    val systemDeleteIntentSender: IntentSender? = null,
)

class SecureMediaVaultManager(
    private val context: Context,
    private val fileStore: EncryptedMediaFileStore,
) {
    private val resolver: ContentResolver = context.contentResolver

    /**
     * Быстрый предпросмотр выбранных пользователем URI перед импортом:
     * вычисляет слепой HMAC BLAKE3 + перцептивные dHash/pHash в фоне и сверяет со всем хранилищем.
     */
    suspend fun preflightScanImports(
        uris: List<Uri>,
        session: VaultSessionKeys,
        existingVaultMedia: List<MediaItem>,
    ): ImportPreflightReport = withContext(Dispatchers.IO) {
        val staged = mutableListOf<StagedImportItem>()
        for (uri in uris) {
            val mime = resolver.getType(uri) ?: "image/jpeg"
            val name = queryDisplayName(uri) ?: "ref_${System.currentTimeMillis()}"
            val isVideo = mime.startsWith("video/", ignoreCase = true)

            if (isVideo) {
                staged += StagedImportItem(
                    uri = uri,
                    displayName = name,
                    mimeType = mime,
                    kind = MediaKind.VIDEO,
                    candidateInfo = null,
                )
            } else {
                val rawBytes = resolver.openInputStream(uri)?.use { it.readBytes() } ?: continue
                try {
                    val blake3 = Blake3Hasher.hash(rawBytes)
                    val blindHex = session.withMacKey { kMac ->
                        BlindIndex.computeBlindHex(kMac, "media_blake3", blake3)
                    }
                    blake3.wipe()

                    val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
                    BitmapFactory.decodeByteArray(rawBytes, 0, rawBytes.size, bounds)
                    val sample = computeInSampleSize(bounds.outWidth, bounds.outHeight, 512)
                    val bmp = BitmapFactory.decodeByteArray(
                        rawBytes,
                        0,
                        rawBytes.size,
                        BitmapFactory.Options().apply { inSampleSize = sample },
                    )
                    if (bmp != null) {
                        val exifOrient = runCatching {
                            ExifInterface(ByteArrayInputStream(rawBytes))
                                .getAttributeInt(ExifInterface.TAG_ORIENTATION, ExifInterface.ORIENTATION_NORMAL)
                        }.getOrDefault(ExifInterface.ORIENTATION_NORMAL)
                        val oriented = ExifOrientationHelper.applyOrientation(bmp, exifOrient)
                        val argb = oriented.toArgbImage(maxDimension = 256)
                        val dHash = PerceptualHasher.computeDHash64(argb)
                        val pHash = PerceptualHasher.computePHash64(argb)
                        val trueW = if (exifOrient == ExifInterface.ORIENTATION_ROTATE_90 ||
                            exifOrient == ExifInterface.ORIENTATION_ROTATE_270
                        ) {
                            bounds.outHeight
                        } else {
                            bounds.outWidth
                        }
                        val trueH = if (exifOrient == ExifInterface.ORIENTATION_ROTATE_90 ||
                            exifOrient == ExifInterface.ORIENTATION_ROTATE_270
                        ) {
                            bounds.outWidth
                        } else {
                            bounds.outHeight
                        }
                        oriented.recycle()

                        staged += StagedImportItem(
                            uri = uri,
                            displayName = name,
                            mimeType = mime,
                            kind = MediaKind.PHOTO,
                            candidateInfo = DuplicateCandidateInput(
                                tempId = uri.toString(),
                                displayName = name,
                                mimeType = mime,
                                width = trueW.coerceAtLeast(1),
                                height = trueH.coerceAtLeast(1),
                                plaintextSizeBytes = rawBytes.size.toLong(),
                                cryptoBlake3BlindHex = blindHex,
                                dHash64 = dHash,
                                pHash64 = pHash,
                            ),
                        )
                    }
                } finally {
                    rawBytes.wipe()
                }
            }
        }

        val hits = PerceptualHasher.inspectIncomingDuplicates(
            incomingList = staged.mapNotNull { it.candidateInfo },
            existingVaultItems = existingVaultMedia,
        )
        ImportPreflightReport(stagedItems = staged, duplicateHits = hits)
    }

    /**
     * Импортирует выбранные медиафайлы с очисткой EXIF/GPS, потоковым шифрованием MVCH v2,
     * генерацией WebP-миниатюр, BlurHash, авто-палитры и выбранной стратегией обработки дубликатов.
     */
    suspend fun executeImport(
        report: ImportPreflightReport,
        targetFolderId: String?,
        strategy: ImportDuplicateStrategy,
        deleteSystemOriginalsAfterEncrypt: Boolean,
        session: VaultSessionKeys,
        repository: VaultDataRepository,
        onProgress: (current: Int, total: Int) -> Unit = { _, _ -> },
    ): ImportExecutionOutcome = withContext(Dispatchers.IO) {
        val hitByTempId = report.duplicateHits.associateBy { it.incoming.tempId }
        val successfullyEncryptedUris = mutableListOf<Uri>()
        var imported = 0
        var skipped = 0
        var replaced = 0

        val total = report.stagedItems.size
        report.stagedItems.forEachIndexed { idx, staged ->
            onProgress(idx + 1, total)
            val hit = staged.candidateInfo?.let { hitByTempId[it.tempId] }

            if (hit != null) {
                when (strategy) {
                    ImportDuplicateStrategy.SKIP_DUPLICATES -> {
                        skipped++
                        return@forEachIndexed
                    }
                    ImportDuplicateStrategy.REPLACE_IF_BETTER_QUALITY -> {
                        if (!hit.incomingIsHigherQuality) {
                            skipped++
                            return@forEachIndexed
                        }
                    }
                    ImportDuplicateStrategy.KEEP_ALL -> Unit
                }
            }

            val targetFolderForItem = if (hit != null && strategy == ImportDuplicateStrategy.REPLACE_IF_BETTER_QUALITY) {
                hit.existing.folderId
            } else {
                targetFolderId
            }

            val createdItem = if (staged.kind == MediaKind.VIDEO) {
                encryptAndStoreVideoUri(staged.uri, staged.displayName, staged.mimeType, targetFolderForItem, session)
            } else {
                encryptAndStorePhotoUri(staged.uri, staged.displayName, staged.mimeType, targetFolderForItem, session)
            }

            if (createdItem != null) {
                if (hit != null && strategy == ImportDuplicateStrategy.REPLACE_IF_BETTER_QUALITY) {
                    repository.deleteMediaItems(setOf(hit.existing.id), purgeFromCloud = true)
                    replaced++
                } else {
                    imported++
                }
                repository.upsertMedia(createdItem)
                successfullyEncryptedUris += staged.uri
            }
        }

        val deleteSender = if (deleteSystemOriginalsAfterEncrypt && successfullyEncryptedUris.isNotEmpty()) {
            requestOrPerformSystemOriginalsDeletion(successfullyEncryptedUris)
        } else {
            null
        }

        ImportExecutionOutcome(
            importedCount = imported,
            skippedDuplicatesCount = skipped,
            replacedCount = replaced,
            systemDeleteIntentSender = deleteSender,
        )
    }

    /**
     * Извлекает точный стоп-кадр из зашифрованного видео MVCH v2 прямо в ОЗУ и сохраняет его
     * как полноценный зашифрованный фото-референс (с палитрой, BlurHash и dHash/pHash) в открытую папку!
     */
    suspend fun captureVideoFrameAsPhotoReference(
        videoItem: MediaItem,
        positionMs: Long,
        session: VaultSessionKeys,
        repository: VaultDataRepository,
    ): MediaItem? = withContext(Dispatchers.IO) {
        val encVideoFile = fileStore.blobFile(session.contour, videoItem.id)
        if (!encVideoFile.exists()) return@withContext null

        val retriever = MediaMetadataRetriever()
        val frameBitmap: Bitmap? = try {
            val ds = MvchAndroidMediaDataSource(encVideoFile, session, videoItem.id)
            retriever.setDataSource(ds)
            retriever.getFrameAtTime(positionMs.coerceAtLeast(0L) * 1000L, MediaMetadataRetriever.OPTION_CLOSEST)
        } catch (_: Throwable) {
            null
        } finally {
            runCatching { retriever.release() }
        }

        val bmp = frameBitmap ?: return@withContext null
        try {
            val newMediaId = UUID.randomUUID().toString()
            val cleanPngBytes = WebpBitmapEncoder.compressPngLossless(bmp)
            try {
                val encResult = session.withBlobKey { kBlob ->
                    MvchStreamCipher.encryptToFile(
                        input = ByteArrayInputStream(cleanPngBytes),
                        targetFile = fileStore.blobFile(session.contour, newMediaId),
                        kBlob = kBlob,
                        fileUuid = newMediaId,
                    )
                }

                val blindHex = session.withMacKey { kMac ->
                    BlindIndex.computeBlindHex(kMac, "media_blake3", encResult.blake3Hash)
                }
                encResult.blake3Hash.wipe()

                val thumbBmp = scaleDownKeepingRatio(bmp, maxSide = 384)
                val webpThumbBytes = WebpBitmapEncoder.compressWebpLossy(thumbBmp, quality = 84)
                if (thumbBmp !== bmp) thumbBmp.recycle()
                val encThumb = VaultCryptoEngine.encryptThumbnail(session, newMediaId, webpThumbBytes)
                webpThumbBytes.wipe()
                fileStore.thumbFile(session.contour, newMediaId).writeBytes(encThumb)

                val argb = bmp.toArgbImage(maxDimension = 256)
                val blurHash = BlurHashCodec.encode(argb, 4, 3)
                val palette = ColorInspector.extractDominantPalette(argb, targetColors = 6)
                val dHash = PerceptualHasher.computeDHash64(argb)
                val pHash = PerceptualHasher.computePHash64(argb)

                val secFormatted = "%02d_%02d".format((positionMs / 60_000L), (positionMs / 1000L) % 60L)
                val baseTitle = videoItem.displayName.substringBeforeLast('.')
                val now = System.currentTimeMillis()
                val refPhoto = MediaItem(
                    id = newMediaId,
                    folderId = videoItem.folderId,
                    displayName = "${baseTitle}_кадр_${secFormatted}.png",
                    mimeType = "image/png",
                    kind = MediaKind.PHOTO,
                    width = bmp.width,
                    height = bmp.height,
                    plaintextSizeBytes = encResult.plaintextSize,
                    encryptedSizeBytes = encResult.encryptedSize,
                    blurHash = blurHash,
                    dominantPaletteHex = palette,
                    cryptoBlake3BlindHex = blindHex,
                    dHash64 = dHash,
                    pHash64 = pHash,
                    tags = (videoItem.tags + "стоп-кадр").distinct(),
                    syncStatus = SyncItemStatus.QUEUED,
                    localBlobPresent = true,
                    lastAccessedAtMs = now,
                    createdAtMs = now,
                    updatedAtMs = now,
                )
                repository.upsertMedia(refPhoto)
                refPhoto
            } finally {
                cleanPngBytes.wipe()
            }
        } finally {
            bmp.recycle()
        }
    }

    private fun encryptAndStorePhotoUri(
        uri: Uri,
        displayName: String,
        mimeType: String,
        folderId: String?,
        session: VaultSessionKeys,
    ): MediaItem? {
        val rawInputBytes = resolver.openInputStream(uri)?.use { it.readBytes() } ?: return null
        try {
            val exifOrient = runCatching {
                ExifInterface(ByteArrayInputStream(rawInputBytes))
                    .getAttributeInt(ExifInterface.TAG_ORIENTATION, ExifInterface.ORIENTATION_NORMAL)
            }.getOrDefault(ExifInterface.ORIENTATION_NORMAL)

            val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
            BitmapFactory.decodeByteArray(rawInputBytes, 0, rawInputBytes.size, bounds)
            val sample = computeInSampleSize(bounds.outWidth, bounds.outHeight, 4096)
            val decoded = BitmapFactory.decodeByteArray(
                rawInputBytes,
                0,
                rawInputBytes.size,
                BitmapFactory.Options().apply {
                    inSampleSize = sample
                    inPreferredConfig = Bitmap.Config.ARGB_8888
                },
            ) ?: return null

            val oriented = ExifOrientationHelper.applyOrientation(decoded, exifOrient)
            try {
                // Перекодирование в чистый буфер гарантированно удаляет все EXIF/GPS/серийные номера камеры!
                val strippedBytes = if (mimeType.contains("png", ignoreCase = true)) {
                    WebpBitmapEncoder.compressPngLossless(oriented)
                } else {
                    WebpBitmapEncoder.compressWebpLossy(oriented, quality = 95)
                }
                val cleanMime = if (mimeType.contains("png", ignoreCase = true)) "image/png" else "image/webp"

                try {
                    val mediaId = UUID.randomUUID().toString()
                    val encResult = session.withBlobKey { kBlob ->
                        MvchStreamCipher.encryptToFile(
                            input = ByteArrayInputStream(strippedBytes),
                            targetFile = fileStore.blobFile(session.contour, mediaId),
                            kBlob = kBlob,
                            fileUuid = mediaId,
                        )
                    }
                    val blindHex = session.withMacKey { kMac ->
                        BlindIndex.computeBlindHex(kMac, "media_blake3", encResult.blake3Hash)
                    }
                    encResult.blake3Hash.wipe()

                    val thumbBmp = scaleDownKeepingRatio(oriented, maxSide = 384)
                    val thumbWebp = WebpBitmapEncoder.compressWebpLossy(thumbBmp, quality = 82)
                    if (thumbBmp !== oriented) thumbBmp.recycle()
                    val encThumb = VaultCryptoEngine.encryptThumbnail(session, mediaId, thumbWebp)
                    thumbWebp.wipe()
                    fileStore.thumbFile(session.contour, mediaId).writeBytes(encThumb)

                    val argb = oriented.toArgbImage(maxDimension = 256)
                    val blurHash = BlurHashCodec.encode(argb, 4, 3)
                    val palette = ColorInspector.extractDominantPalette(argb, targetColors = 6)
                    val dHash = PerceptualHasher.computeDHash64(argb)
                    val pHash = PerceptualHasher.computePHash64(argb)

                    val now = System.currentTimeMillis()
                    return MediaItem(
                        id = mediaId,
                        folderId = folderId,
                        displayName = displayName,
                        mimeType = cleanMime,
                        kind = MediaKind.PHOTO,
                        width = oriented.width,
                        height = oriented.height,
                        plaintextSizeBytes = encResult.plaintextSize,
                        encryptedSizeBytes = encResult.encryptedSize,
                        blurHash = blurHash,
                        dominantPaletteHex = palette,
                        cryptoBlake3BlindHex = blindHex,
                        dHash64 = dHash,
                        pHash64 = pHash,
                        syncStatus = SyncItemStatus.QUEUED,
                        localBlobPresent = true,
                        lastAccessedAtMs = now,
                        createdAtMs = now,
                        updatedAtMs = now,
                    )
                } finally {
                    strippedBytes.wipe()
                }
            } finally {
                oriented.recycle()
            }
        } finally {
            rawInputBytes.wipe()
        }
    }

    private fun encryptAndStoreVideoUri(
        uri: Uri,
        displayName: String,
        mimeType: String,
        folderId: String?,
        session: VaultSessionKeys,
    ): MediaItem? {
        val mediaId = UUID.randomUUID().toString()
        val dstBlob = fileStore.blobFile(session.contour, mediaId)
        val encResult = resolver.openInputStream(uri)?.use { inputStream ->
            session.withBlobKey { kBlob ->
                MvchStreamCipher.encryptToFile(
                    input = inputStream,
                    targetFile = dstBlob,
                    kBlob = kBlob,
                    fileUuid = mediaId,
                )
            }
        } ?: return null

        val blindHex = session.withMacKey { kMac ->
            BlindIndex.computeBlindHex(kMac, "media_blake3", encResult.blake3Hash)
        }
        encResult.blake3Hash.wipe()

        var videoW = 1920
        var videoH = 1080
        var durationMs = 0L
        var blurHash = "L009j[fQ00fQ00fQfQfQ00fQfQfQ"
        var palette = listOf("#10B981", "#111827", "#38BDF8")
        var dHash = 0L
        var pHash = 0L

        val retriever = MediaMetadataRetriever()
        try {
            val ds = MvchAndroidMediaDataSource(dstBlob, session, mediaId)
            retriever.setDataSource(ds)
            videoW = retriever.extractMetadata(MediaMetadataRetriever.METADATA_KEY_VIDEO_WIDTH)?.toIntOrNull() ?: 1920
            videoH = retriever.extractMetadata(MediaMetadataRetriever.METADATA_KEY_VIDEO_HEIGHT)?.toIntOrNull() ?: 1080
            val rot = retriever.extractMetadata(MediaMetadataRetriever.METADATA_KEY_VIDEO_ROTATION)?.toIntOrNull() ?: 0
            if (rot == 90 || rot == 270) {
                val tmp = videoW
                videoW = videoH
                videoH = tmp
            }
            durationMs = retriever.extractMetadata(MediaMetadataRetriever.METADATA_KEY_DURATION)?.toLongOrNull() ?: 0L

            val poster = retriever.getFrameAtTime(min(durationMs * 500L, 1_000_000L), MediaMetadataRetriever.OPTION_CLOSEST_SYNC)
            if (poster != null) {
                val thumbBmp = scaleDownKeepingRatio(poster, maxSide = 384)
                val thumbBytes = WebpBitmapEncoder.compressWebpLossy(thumbBmp, quality = 80)
                if (thumbBmp !== poster) thumbBmp.recycle()
                val encThumb = VaultCryptoEngine.encryptThumbnail(session, mediaId, thumbBytes)
                thumbBytes.wipe()
                fileStore.thumbFile(session.contour, mediaId).writeBytes(encThumb)

                val argb = poster.toArgbImage(maxDimension = 256)
                blurHash = BlurHashCodec.encode(argb, 4, 3)
                palette = ColorInspector.extractDominantPalette(argb, 6)
                dHash = PerceptualHasher.computeDHash64(argb)
                pHash = PerceptualHasher.computePHash64(argb)
                poster.recycle()
            }
        } catch (_: Throwable) {
            // Если редкий кодек не отдал постер через MediaMetadataRetriever — сохраняем базовые параметры
        } finally {
            runCatching { retriever.release() }
        }

        val now = System.currentTimeMillis()
        return MediaItem(
            id = mediaId,
            folderId = folderId,
            displayName = displayName,
            mimeType = mimeType,
            kind = MediaKind.VIDEO,
            width = videoW,
            height = videoH,
            durationMs = durationMs,
            plaintextSizeBytes = encResult.plaintextSize,
            encryptedSizeBytes = encResult.encryptedSize,
            blurHash = blurHash,
            dominantPaletteHex = palette,
            cryptoBlake3BlindHex = blindHex,
            dHash64 = dHash,
            pHash64 = pHash,
            syncStatus = SyncItemStatus.QUEUED,
            localBlobPresent = true,
            lastAccessedAtMs = now,
            createdAtMs = now,
            updatedAtMs = now,
        )
    }

    private fun requestOrPerformSystemOriginalsDeletion(uris: List<Uri>): IntentSender? {
        return try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                val mediaStoreUris = uris.filter { it.authority?.contains("media") == true }
                if (mediaStoreUris.isNotEmpty()) {
                    MediaStore.createDeleteRequest(resolver, mediaStoreUris).intentSender
                } else {
                    uris.forEach { uri -> runCatching { resolver.delete(uri, null, null) } }
                    null
                }
            } else {
                uris.forEach { uri -> runCatching { resolver.delete(uri, null, null) } }
                null
            }
        } catch (_: Exception) {
            null
        }
    }

    private fun queryDisplayName(uri: Uri): String? = runCatching {
        resolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { cursor ->
            if (cursor.moveToFirst()) cursor.getString(0) else null
        }
    }.getOrNull()

    private fun scaleDownKeepingRatio(source: Bitmap, maxSide: Int): Bitmap {
        val largest = max(source.width, source.height)
        if (largest <= maxSide) return source
        val scale = maxSide.toFloat() / largest.toFloat()
        val w = max(1, (source.width * scale).roundToInt())
        val h = max(1, (source.height * scale).roundToInt())
        return Bitmap.createScaledBitmap(source, w, h, true)
    }

    private fun computeInSampleSize(width: Int, height: Int, maxDim: Int): Int {
        var sample = 1
        while (max(width, height) / sample > maxDim) {
            sample *= 2
        }
        return sample
    }
}

/**
 * Фоновая задача WorkManager для фонового пересчёта перцептивных отпечатков (dHash + pHash)
 * у элементов, подтянутых из старых архивов или ожидающих индексации.
 */
class PerceptualHashMaintenanceWorker(
    appContext: Context,
    workerParams: WorkerParameters,
) : CoroutineWorker(appContext, workerParams) {

    override suspend fun doWork(): Result = withContext(Dispatchers.Default) {
        PerceptualHashScanRegistry.activeRunner?.invoke()
        Result.success()
    }
}

object PerceptualHashScanRegistry {
    @Volatile
    var activeRunner: (suspend () -> Unit)? = null
}
