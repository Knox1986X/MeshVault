package com.meshvault.domain.media

import com.meshvault.domain.model.MediaItem
import com.meshvault.domain.model.MediaKind
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import kotlin.math.sin
import kotlin.random.Random

class PerceptualHasherTest {

    @Test
    fun `dHash and pHash match resized and noisy recompressed versions while rejecting distinct scenes`() {
        val originalHiRes = createSyntheticPortraitReference(width = 320, height = 400, noiseAmplitude = 0)
        // Имитация пережатия в Telegram/Pinterest: ресайз 320x400 -> 160x200 + артефакты квантования яркости
        val recompressedSmall = createSyntheticPortraitReference(width = 160, height = 200, noiseAmplitude = 9)
        val distinctLandscape = createSyntheticLandscapeReference(width = 320, height = 200)

        val dOrig = PerceptualHasher.computeDHash64(originalHiRes)
        val pOrig = PerceptualHasher.computePHash64(originalHiRes)

        val dSmall = PerceptualHasher.computeDHash64(recompressedSmall)
        val pSmall = PerceptualHasher.computePHash64(recompressedSmall)

        val dOther = PerceptualHasher.computeDHash64(distinctLandscape)
        val pOther = PerceptualHasher.computePHash64(distinctLandscape)

        val dDistSimilar = PerceptualHasher.hammingDistance(dOrig, dSmall)
        val pDistSimilar = PerceptualHasher.hammingDistance(pOrig, pSmall)
        assertTrue("dHash должен быть близок для ресайза (получено $dDistSimilar)", dDistSimilar <= 5)
        assertTrue("pHash должен быть близок для пережатого фото (получено $pDistSimilar)", pDistSimilar <= 6)
        assertTrue(PerceptualHasher.areVisuallyDuplicate(dOrig, pOrig, dSmall, pSmall))
        assertTrue(PerceptualHasher.visualSimilarityPercent(dOrig, pOrig, dSmall, pSmall) >= 92)

        assertFalse(PerceptualHasher.areVisuallyDuplicate(dOrig, pOrig, dOther, pOther))
        assertTrue(PerceptualHasher.hammingDistance(dOrig, dOther) >= 14)
    }

    @Test
    fun `duplicate clustering groups cross-folder copies selects highest quality original and computes reclaimable space`() {
        val portraitHi = createSyntheticPortraitReference(240, 320, noiseAmplitude = 0)
        val portraitRecompressed = createSyntheticPortraitReference(120, 160, noiseAmplitude = 7)
        val uniqueScene = createSyntheticLandscapeReference(300, 200)

        val d1 = PerceptualHasher.computeDHash64(portraitHi)
        val p1 = PerceptualHasher.computePHash64(portraitHi)
        val d2 = PerceptualHasher.computeDHash64(portraitRecompressed)
        val p2 = PerceptualHasher.computePHash64(portraitRecompressed)
        val dUnique = PerceptualHasher.computeDHash64(uniqueScene)
        val pUnique = PerceptualHasher.computePHash64(uniqueScene)

        val bestPng4k = sampleMedia(
            id = "m-best-4k",
            folderId = "folder-models",
            mimeType = "image/png",
            width = 3840,
            height = 5120,
            sizeBytes = 14_500_000L,
            blindHex = "aa11bb22",
            dHash = d1,
            pHash = p1,
        )
        val exactByteDuplicate = sampleMedia(
            id = "m-exact-copy",
            folderId = "folder-unsorted",
            mimeType = "image/png",
            width = 3840,
            height = 5120,
            sizeBytes = 14_500_000L,
            blindHex = "aa11bb22",
            dHash = d1,
            pHash = p1,
            createdAtMs = 2_000L,
        )
        val telegramCompressedWebp = sampleMedia(
            id = "m-telegram-webp",
            folderId = "folder-lighting",
            mimeType = "image/webp",
            width = 960,
            height = 1280,
            sizeBytes = 420_000L,
            blindHex = "ff998877",
            dHash = d2,
            pHash = p2,
        )
        val unrelated = sampleMedia(
            id = "m-unique",
            folderId = "folder-models",
            mimeType = "image/jpeg",
            width = 2400,
            height = 1600,
            sizeBytes = 3_100_000L,
            blindHex = "12345678",
            dHash = dUnique,
            pHash = pUnique,
        )

        val groups = PerceptualHasher.clusterDuplicates(
            listOf(telegramCompressedWebp, exactByteDuplicate, bestPng4k, unrelated),
        )

        assertEquals(1, groups.size)
        val group = groups.first()
        assertEquals("m-best-4k", group.keepItemId)
        assertEquals(3, group.members.size)
        assertEquals(14_500_000L + 420_000L, group.reclaimableBytes)

        // Проверка пре-импортного советника дубликатов: если импортируется оригинал выше качеством, чем сжатая копия
        val incoming4kCandidate = DuplicateCandidateInput(
            tempId = "inc-1",
            displayName = "model_studio_raw.png",
            mimeType = "image/png",
            width = 4000,
            height = 6000,
            plaintextSizeBytes = 18_000_000L,
            cryptoBlake3BlindHex = "new_blind_hash",
            dHash64 = d1,
            pHash64 = p1,
        )
        val preflightHits = PerceptualHasher.inspectIncomingDuplicates(
            incomingList = listOf(incoming4kCandidate),
            existingVaultItems = listOf(telegramCompressedWebp, unrelated),
        )
        assertEquals(1, preflightHits.size)
        assertEquals("m-telegram-webp", preflightHits.first().existing.id)
        assertEquals(DuplicateMatchKind.VISUAL_SIMILAR, preflightHits.first().matchKind)
        assertTrue(preflightHits.first().incomingIsHigherQuality)
    }

    @Test
    fun `blurHash and color inspector extract accurate HEX HSL Value and palette`() {
        val img = createSyntheticPortraitReference(96, 128, noiseAmplitude = 0)
        val hash = BlurHashCodec.encode(img, componentsX = 4, componentsY = 3)
        assertEquals(4 + 2 * 4 * 3, hash.length)

        val decoded = BlurHashCodec.decode(hash, outWidth = 24, outHeight = 32)
        assertEquals(24, decoded.width)
        assertEquals(32, decoded.height)

        val palette = ColorInspector.extractDominantPalette(img, targetColors = 6)
        assertTrue(palette.size in 3..6)
        assertTrue(palette.all { it.startsWith("#") && it.length == 7 })

        val emeraldReadout = ColorInspector.inspectPixel(0xFF10B981.toInt())
        assertEquals("#10B981", emeraldReadout.hex)
        assertEquals(16, emeraldReadout.r)
        assertEquals(185, emeraldReadout.g)
        assertEquals(129, emeraldReadout.b)
        assertEquals(73, emeraldReadout.valuePct)
    }

    private fun sampleMedia(
        id: String,
        folderId: String,
        mimeType: String,
        width: Int,
        height: Int,
        sizeBytes: Long,
        blindHex: String,
        dHash: Long,
        pHash: Long,
        createdAtMs: Long = 1_000L,
    ): MediaItem = MediaItem(
        id = id,
        folderId = folderId,
        displayName = "$id.img",
        mimeType = mimeType,
        kind = MediaKind.PHOTO,
        width = width,
        height = height,
        plaintextSizeBytes = sizeBytes,
        encryptedSizeBytes = sizeBytes + 128L,
        blurHash = "LEHV6nWB2yk8pyo0adR*.7kCMdnj",
        dominantPaletteHex = listOf("#10B981", "#111827"),
        cryptoBlake3BlindHex = blindHex,
        dHash64 = dHash,
        pHash64 = pHash,
        createdAtMs = createdAtMs,
        updatedAtMs = createdAtMs,
    )

    private fun createSyntheticPortraitReference(width: Int, height: Int, noiseAmplitude: Int): ArgbImage {
        val rng = Random(42)
        val pixels = IntArray(width * height)
        for (y in 0 until height) {
            val ny = y.toDouble() / height.toDouble()
            for (x in 0 until width) {
                val nx = x.toDouble() / width.toDouble()
                val dx = nx - 0.45
                val dy = (ny - 0.38) * 1.25
                val distSq = dx * dx + dy * dy
                // Фигура с выраженным боковым рисующим светом (key light слева сверху)
                val baseLum = if (distSq < 0.08) {
                    210.0 - 380.0 * nx + 60.0 * sin(ny * 9.0)
                } else {
                    28.0 + 55.0 * (1.0 - ny) + 25.0 * sin(nx * 5.0)
                }
                val noise = if (noiseAmplitude > 0) rng.nextInt(-noiseAmplitude, noiseAmplitude + 1) else 0
                val r = (baseLum * 1.05 + noise).toInt().coerceIn(0, 255)
                val g = (baseLum * 0.92 + noise).toInt().coerceIn(0, 255)
                val b = (baseLum * 0.84 + noise).toInt().coerceIn(0, 255)
                pixels[y * width + x] = (0xFF shl 24) or (r shl 16) or (g shl 8) or b
            }
        }
        return ArgbImage(width, height, pixels)
    }

    private fun createSyntheticLandscapeReference(width: Int, height: Int): ArgbImage {
        val pixels = IntArray(width * height)
        for (y in 0 until height) {
            val ny = y.toDouble() / height.toDouble()
            for (x in 0 until width) {
                val nx = x.toDouble() / width.toDouble()
                val horizon = 0.52 + 0.12 * sin(nx * 14.0)
                val r: Int
                val g: Int
                val b: Int
                if (ny < horizon) {
                    r = (40 + 180 * nx).toInt().coerceIn(0, 255)
                    g = (110 + 90 * (1.0 - ny)).toInt().coerceIn(0, 255)
                    b = 235
                } else {
                    r = 18
                    g = (85 - 50 * ny).toInt().coerceIn(0, 255)
                    b = 35
                }
                pixels[y * width + x] = (0xFF shl 24) or (r shl 16) or (g shl 8) or b
            }
        }
        return ArgbImage(width, height, pixels)
    }
}
