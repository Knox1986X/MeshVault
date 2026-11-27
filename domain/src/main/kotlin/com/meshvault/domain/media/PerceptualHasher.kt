package com.meshvault.domain.media

import com.meshvault.domain.model.MediaItem
import com.meshvault.domain.model.MediaKind
import kotlin.math.PI
import kotlin.math.cos
import kotlin.math.max
import kotlin.math.min
import kotlin.math.roundToInt
import kotlin.math.sqrt

enum class DuplicateMatchKind(val badgeRu: String) {
    EXACT_BYTE_COPY("100% точная копия"),
    VISUAL_SIMILAR("Визуальный дубликат"),
}

enum class ImportDuplicateStrategy(val titleRu: String) {
    SKIP_DUPLICATES("Пропустить дубликаты"),
    REPLACE_IF_BETTER_QUALITY("Заменить, если новое лучшего качества"),
    KEEP_ALL("Всё равно сохранить"),
}

data class DuplicateCandidateInput(
    val tempId: String,
    val displayName: String,
    val mimeType: String,
    val width: Int,
    val height: Int,
    val plaintextSizeBytes: Long,
    val cryptoBlake3BlindHex: String,
    val dHash64: Long,
    val pHash64: Long,
)

data class ImportDuplicateHit(
    val incoming: DuplicateCandidateInput,
    val existing: MediaItem,
    val matchKind: DuplicateMatchKind,
    val similarityPercent: Int,
    val incomingIsHigherQuality: Boolean,
)

data class DuplicateMemberEvaluation(
    val item: MediaItem,
    val isRecommendedKeep: Boolean,
    val matchKindToKeep: DuplicateMatchKind,
    val similarityPercent: Int,
)

data class DuplicateGroup(
    val groupId: String,
    val keepItemId: String,
    val members: List<DuplicateMemberEvaluation>,
    val reclaimableBytes: Long,
    val dominantMatchKind: DuplicateMatchKind,
    val maxSimilarityPercent: Int,
)

/**
 * Двухуровневый перцептивный хэшер изображений:
 *  1) 64-bit dHash (градиент яркости на сетке 9×8) — мгновенно ловит ресайзы и перекодирование JPEG/WebP;
 *  2) 64-bit DCT pHash (2D ДКП 32×32, низкочастотный спектр 8×8 без DC) — устойчив к сжатию Telegram/Pinterest и гамме.
 */
object PerceptualHasher {
    const val DEFAULT_MAX_DHASH_DISTANCE = 9
    const val DEFAULT_MAX_PHASH_DISTANCE = 10

    private const val DCT_SIZE = 32
    private val DCT_MATRIX: Array<DoubleArray> = Array(DCT_SIZE) { u ->
        val alpha = if (u == 0) sqrt(1.0 / DCT_SIZE) else sqrt(2.0 / DCT_SIZE)
        DoubleArray(DCT_SIZE) { x ->
            alpha * cos(((2.0 * x + 1.0) * u * PI) / (2.0 * DCT_SIZE))
        }
    }

    fun computeDHash64(image: ArgbImage): Long {
        val lum = downsampleAreaLuminance(image, targetW = 9, targetH = 8)
        var hash = 0L
        var bit = 0
        for (y in 0 until 8) {
            val rowOffset = y * 9
            for (x in 0 until 8) {
                if (lum[rowOffset + x] > lum[rowOffset + x + 1]) {
                    hash = hash or (1L shl bit)
                }
                bit++
            }
        }
        return hash
    }

    fun computePHash64(image: ArgbImage): Long {
        val lum = downsampleAreaLuminance(image, targetW = DCT_SIZE, targetH = DCT_SIZE)

        // Сепарабельное 2D ДКП: temp = DCT_MATRIX * lum, dct = temp * DCT_MATRIX^T
        val temp = DoubleArray(DCT_SIZE * DCT_SIZE)
        for (u in 0 until DCT_SIZE) {
            val cosRow = DCT_MATRIX[u]
            for (x in 0 until DCT_SIZE) {
                var sum = 0.0
                for (y in 0 until DCT_SIZE) {
                    sum += cosRow[y] * lum[y * DCT_SIZE + x]
                }
                temp[u * DCT_SIZE + x] = sum
            }
        }

        // Нам нужен только верхний левый низкочастотный спектр (u in 0..8, v in 0..8)
        val acCoeffs = DoubleArray(64)
        var idx = 0
        for (u in 0 until 8) {
            for (v in 0 until 8) {
                if (u == 0 && v == 0) continue // Пропускаем среднюю яркость DC [0, 0]
                if (idx < 64) {
                    var sum = 0.0
                    val cosV = DCT_MATRIX[v]
                    for (x in 0 until DCT_SIZE) {
                        sum += temp[u * DCT_SIZE + x] * cosV[x]
                    }
                    acCoeffs[idx++] = sum
                }
            }
        }
        // 64-й AC-коэффициент берём из [0, 8]
        var extraAc = 0.0
        val cos8 = DCT_MATRIX[8]
        for (x in 0 until DCT_SIZE) {
            extraAc += temp[x] * cos8[x]
        }
        acCoeffs[63] = extraAc

        val sorted = acCoeffs.copyOf()
        sorted.sort()
        val median = (sorted[31] + sorted[32]) * 0.5

        var hash = 0L
        for (i in 0 until 64) {
            if (acCoeffs[i] > median) {
                hash = hash or (1L shl i)
            }
        }
        return hash
    }

    fun hammingDistance(hashA: Long, hashB: Long): Int =
        java.lang.Long.bitCount(hashA xor hashB)

    fun visualSimilarityPercent(dHashA: Long, pHashA: Long, dHashB: Long, pHashB: Long): Int {
        val dDist = hammingDistance(dHashA, dHashB)
        val pDist = hammingDistance(pHashA, pHashB)
        val weightedBitDiff = dDist * 0.55 + pDist * 0.45
        val sim = (1.0 - weightedBitDiff / 64.0) * 100.0
        return sim.roundToInt().coerceIn(0, 100)
    }

    fun areVisuallyDuplicate(
        dHashA: Long,
        pHashA: Long,
        dHashB: Long,
        pHashB: Long,
        maxDHashDist: Int = DEFAULT_MAX_DHASH_DISTANCE,
        maxPHashDist: Int = DEFAULT_MAX_PHASH_DISTANCE,
    ): Boolean {
        val dDist = hammingDistance(dHashA, dHashB)
        val pDist = hammingDistance(pHashA, pHashB)
        if (dDist <= maxDHashDist && pDist <= maxPHashDist) return true
        // Если один из хэшей практически идентичен (<= 4 бит), допускаем чуть больший зазор второго
        if (dDist <= 4 && pDist <= maxPHashDist + 4) return true
        if (pDist <= 4 && dDist <= maxDHashDist + 4) return true
        return false
    }

    /**
     * Кластеризует все фотографии хранилища в группы дубликатов (Union-Find),
     * выбирает лучший по качеству оригинал и вычисляет объём освобождаемого места.
     */
    fun clusterDuplicates(
        items: List<MediaItem>,
        maxDHashDist: Int = DEFAULT_MAX_DHASH_DISTANCE,
        maxPHashDist: Int = DEFAULT_MAX_PHASH_DISTANCE,
    ): List<DuplicateGroup> {
        val photos = items.filter { it.kind == MediaKind.PHOTO }
        val n = photos.size
        if (n < 2) return emptyList()

        val parent = IntArray(n) { it }
        fun find(x: Int): Int {
            var r = x
            while (parent[r] != r) r = parent[r]
            var curr = x
            while (curr != r) {
                val next = parent[curr]
                parent[curr] = r
                curr = next
            }
            return r
        }
        fun union(a: Int, b: Int) {
            val ra = find(a)
            val rb = find(b)
            if (ra != rb) parent[rb] = ra
        }

        // Шаг 1: Мгновенная группировка 100% побайтовых копий за O(N) по слепому HMAC BLAKE3
        val byExactHash = HashMap<String, Int>(n)
        for (i in 0 until n) {
            val hex = photos[i].cryptoBlake3BlindHex
            if (hex.isNotEmpty()) {
                val prev = byExactHash.putIfAbsent(hex, i)
                if (prev != null) union(prev, i)
            }
        }

        // Шаг 2: Перцептивное сравнение (dHash + pHash)
        for (i in 0 until n) {
            val a = photos[i]
            for (j in i + 1 until n) {
                if (find(i) == find(j)) continue
                val b = photos[j]
                if (areVisuallyDuplicate(a.dHash64, a.pHash64, b.dHash64, b.pHash64, maxDHashDist, maxPHashDist)) {
                    union(i, j)
                }
            }
        }

        val clusters = LinkedHashMap<Int, MutableList<MediaItem>>()
        for (i in 0 until n) {
            clusters.getOrPut(find(i)) { mutableListOf() }.add(photos[i])
        }

        return clusters.values
            .filter { it.size >= 2 }
            .map { groupMembers ->
                val best = selectBestOriginal(groupMembers)
                val evaluated = groupMembers
                    .sortedWith(
                        compareByDescending<MediaItem> { it.id == best.id }
                            .thenByDescending { it.width.toLong() * it.height.toLong() }
                            .thenByDescending { it.plaintextSizeBytes },
                    )
                    .map { member ->
                        val exact = member.cryptoBlake3BlindHex.isNotEmpty() &&
                            member.cryptoBlake3BlindHex == best.cryptoBlake3BlindHex
                        val kind = if (exact) {
                            DuplicateMatchKind.EXACT_BYTE_COPY
                        } else {
                            DuplicateMatchKind.VISUAL_SIMILAR
                        }
                        val sim = if (exact) {
                            100
                        } else {
                            visualSimilarityPercent(best.dHash64, best.pHash64, member.dHash64, member.pHash64)
                                .coerceAtMost(99)
                        }
                        DuplicateMemberEvaluation(
                            item = member,
                            isRecommendedKeep = member.id == best.id,
                            matchKindToKeep = kind,
                            similarityPercent = sim,
                        )
                    }

                val extras = evaluated.filterNot { it.isRecommendedKeep }
                val reclaimable = extras.sumOf { it.item.plaintextSizeBytes }
                val dominantKind = if (extras.all { it.matchKindToKeep == DuplicateMatchKind.EXACT_BYTE_COPY }) {
                    DuplicateMatchKind.EXACT_BYTE_COPY
                } else {
                    DuplicateMatchKind.VISUAL_SIMILAR
                }
                val maxSim = extras.maxOfOrNull { it.similarityPercent } ?: 100

                DuplicateGroup(
                    groupId = "dup_${best.id}",
                    keepItemId = best.id,
                    members = evaluated,
                    reclaimableBytes = reclaimable,
                    dominantMatchKind = dominantKind,
                    maxSimilarityPercent = maxSim,
                )
            }
            .sortedByDescending { it.reclaimableBytes }
    }

    /**
     * Выбирает лучший оригинал для сохранения:
     *  1) Максимальное разрешение (Ш × В пикселей);
     *  2) При равном разрешении — формат без потерь (PNG / lossless) выше JPEG;
     *  3) Больший размер файла (меньше артефактов квантования);
     *  4) Более ранняя дата добавления в хранилище.
     */
    fun selectBestOriginal(candidates: List<MediaItem>): MediaItem {
        require(candidates.isNotEmpty()) { "Список кандидатов пуст" }
        return candidates.maxWith(
            compareBy<MediaItem> { it.width.toLong() * it.height.toLong() }
                .thenBy { formatQualityRank(it.mimeType) }
                .thenBy { it.plaintextSizeBytes }
                .thenBy { -it.createdAtMs },
        )
    }

    /**
     * Проверяет импортируемые фотографии до сохранения в хранилище, находя как точные копии,
     * так и пережатые/уменьшенные визуальные дубликаты в любой папке хранилища.
     */
    fun inspectIncomingDuplicates(
        incomingList: List<DuplicateCandidateInput>,
        existingVaultItems: List<MediaItem>,
    ): List<ImportDuplicateHit> {
        val existingPhotos = existingVaultItems.filter { it.kind == MediaKind.PHOTO }
        if (incomingList.isEmpty() || existingPhotos.isEmpty()) return emptyList()

        val exactMap = existingPhotos
            .filter { it.cryptoBlake3BlindHex.isNotEmpty() }
            .associateBy { it.cryptoBlake3BlindHex }

        val hits = mutableListOf<ImportDuplicateHit>()
        for (incoming in incomingList) {
            val exactExisting = exactMap[incoming.cryptoBlake3BlindHex]
            if (exactExisting != null) {
                hits += ImportDuplicateHit(
                    incoming = incoming,
                    existing = exactExisting,
                    matchKind = DuplicateMatchKind.EXACT_BYTE_COPY,
                    similarityPercent = 100,
                    incomingIsHigherQuality = false,
                )
                continue
            }

            var bestMatch: MediaItem? = null
            var bestSim = -1
            for (ex in existingPhotos) {
                if (areVisuallyDuplicate(incoming.dHash64, incoming.pHash64, ex.dHash64, ex.pHash64)) {
                    val sim = visualSimilarityPercent(incoming.dHash64, incoming.pHash64, ex.dHash64, ex.pHash64)
                    if (sim > bestSim) {
                        bestSim = sim
                        bestMatch = ex
                    }
                }
            }

            if (bestMatch != null) {
                val incomingPixels = incoming.width.toLong() * incoming.height.toLong()
                val existingPixels = bestMatch.width.toLong() * bestMatch.height.toLong()
                val incomingBetter = when {
                    incomingPixels != existingPixels -> incomingPixels > existingPixels
                    formatQualityRank(incoming.mimeType) != formatQualityRank(bestMatch.mimeType) ->
                        formatQualityRank(incoming.mimeType) > formatQualityRank(bestMatch.mimeType)
                    else -> incoming.plaintextSizeBytes > bestMatch.plaintextSizeBytes
                }
                hits += ImportDuplicateHit(
                    incoming = incoming,
                    existing = bestMatch,
                    matchKind = DuplicateMatchKind.VISUAL_SIMILAR,
                    similarityPercent = bestSim.coerceAtMost(99),
                    incomingIsHigherQuality = incomingBetter,
                )
            }
        }
        return hits
    }

    private fun formatQualityRank(mimeType: String): Int {
        val lower = mimeType.lowercase()
        return when {
            "png" in lower || "bmp" in lower || "tiff" in lower -> 3
            "webp" in lower || "heic" in lower || "avif" in lower -> 2
            else -> 1
        }
    }

    /**
     * Точное площадное (box/area) усреднение яркости до сетки [targetW]×[targetH].
     * В отличие от nearest-neighbor не даёт алиасинга при сильном уменьшении 4K-фотографий!
     */
    internal fun downsampleAreaLuminance(image: ArgbImage, targetW: Int, targetH: Int): DoubleArray {
        val out = DoubleArray(targetW * targetH)
        val scaleX = image.width.toDouble() / targetW.toDouble()
        val scaleY = image.height.toDouble() / targetH.toDouble()

        for (ty in 0 until targetH) {
            val yStart = (ty * scaleY).toInt().coerceIn(0, image.height - 1)
            val yEnd = max(yStart + 1, min(image.height, ((ty + 1) * scaleY).roundToInt()))
            for (tx in 0 until targetW) {
                val xStart = (tx * scaleX).toInt().coerceIn(0, image.width - 1)
                val xEnd = max(xStart + 1, min(image.width, ((tx + 1) * scaleX).roundToInt()))

                // Ограничиваем шаг выборки на гигантских фото для мгновенной скорости
                val stepY = max(1, (yEnd - yStart) / 8)
                val stepX = max(1, (xEnd - xStart) / 8)

                var sumLum = 0.0
                var count = 0
                var sy = yStart
                while (sy < yEnd) {
                    val rowIdx = sy * image.width
                    var sx = xStart
                    while (sx < xEnd) {
                        val px = image.pixels[rowIdx + sx]
                        val r = (px ushr 16) and 0xFF
                        val g = (px ushr 8) and 0xFF
                        val b = px and 0xFF
                        sumLum += 0.299 * r + 0.587 * g + 0.114 * b
                        count++
                        sx += stepX
                    }
                    sy += stepY
                }
                out[ty * targetW + tx] = if (count > 0) sumLum / count else 0.0
            }
        }
        return out
    }
}
