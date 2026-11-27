package com.meshvault.domain.media

import kotlin.math.PI
import kotlin.math.abs
import kotlin.math.cos
import kotlin.math.max
import kotlin.math.min
import kotlin.math.pow
import kotlin.math.roundToInt
import kotlin.math.sign
import kotlin.math.sqrt

/**
 * Независимое от Android Bitmap представление пиксельного буфера ARGB_8888,
 * позволяющее выполнять хэширование dHash/pHash, извлечение палитры и BlurHash
 * как в фоновых пулах на устройстве, так и в быстрых JVM Unit-тестах.
 */
class ArgbImage(
    val width: Int,
    val height: Int,
    val pixels: IntArray,
) {
    init {
        require(width > 0 && height > 0) { "Некорректные размеры изображения: ${width}x${height}" }
        require(pixels.size >= width * height) { "Буфер пикселей меньше width * height" }
    }

    fun getPixel(x: Int, y: Int): Int =
        pixels[y.coerceIn(0, height - 1) * width + x.coerceIn(0, width - 1)]
}

data class PixelColorReadout(
    val argb: Int,
    val hex: String,
    val r: Int,
    val g: Int,
    val b: Int,
    val hueDeg: Int,
    val saturationPct: Int,
    val lightnessPct: Int,
    val valuePct: Int, // Светлота / тон 0–100% для художников (HSV Value / перцептивный тон)
    val luminancePct: Int, // Перцептивная яркость Rec.709 (0–100%) для Value Check
)

object ColorInspector {

    fun inspectPixel(argb: Int): PixelColorReadout {
        val r = (argb ushr 16) and 0xFF
        val g = (argb ushr 8) and 0xFF
        val b = argb and 0xFF

        val rf = r / 255.0
        val gf = g / 255.0
        val bf = b / 255.0

        val cMax = max(rf, max(gf, bf))
        val cMin = min(rf, min(gf, bf))
        val delta = cMax - cMin

        val hue = when {
            delta < 1e-6 -> 0.0
            cMax == rf -> 60.0 * (((gf - bf) / delta) % 6.0)
            cMax == gf -> 60.0 * (((bf - rf) / delta) + 2.0)
            else -> 60.0 * (((rf - gf) / delta) + 4.0)
        }.let { if (it < 0.0) it + 360.0 else it }

        val lightness = (cMax + cMin) / 2.0
        val satHsl = if (delta < 1e-6) {
            0.0
        } else {
            delta / (1.0 - abs(2.0 * lightness - 1.0)).coerceAtLeast(1e-6)
        }

        val rec709Lum = 0.2126 * rf + 0.7152 * gf + 0.0722 * bf

        return PixelColorReadout(
            argb = (0xFF shl 24) or (r shl 16) or (g shl 8) or b,
            hex = formatHex(r, g, b),
            r = r,
            g = g,
            b = b,
            hueDeg = hue.roundToInt() % 360,
            saturationPct = (satHsl * 100.0).roundToInt().coerceIn(0, 100),
            lightnessPct = (lightness * 100.0).roundToInt().coerceIn(0, 100),
            valuePct = (cMax * 100.0).roundToInt().coerceIn(0, 100),
            luminancePct = (rec709Lum * 100.0).roundToInt().coerceIn(0, 100),
        )
    }

    fun formatHex(r: Int, g: Int, b: Int): String =
        "#%02X%02X%02X".format(r.coerceIn(0, 255), g.coerceIn(0, 255), b.coerceIn(0, 255))

    fun parseHexColorOrNull(hex: String): Int? {
        val clean = hex.trim().removePrefix("#")
        if (clean.length != 6 && clean.length != 8) return null
        val parsed = clean.toLongOrNull(16) ?: return null
        return if (clean.length == 6) {
            (0xFF000000L or parsed).toInt()
        } else {
            parsed.toInt()
        }
    }

    /**
     * Извлекает 5–7 доминирующих цветов референса быстрым детерминированным k-means в RGB-пространстве,
     * сортируя образцы от наиболее весомого к акцентным.
     */
    fun extractDominantPalette(image: ArgbImage, targetColors: Int = 6): List<String> {
        val k = targetColors.coerceIn(3, 8)
        val stepX = max(1, image.width / 32)
        val stepY = max(1, image.height / 32)

        val samplesR = ArrayList<Int>(1024)
        val samplesG = ArrayList<Int>(1024)
        val samplesB = ArrayList<Int>(1024)

        var y = 0
        while (y < image.height) {
            var x = 0
            while (x < image.width) {
                val px = image.getPixel(x, y)
                val alpha = (px ushr 24) and 0xFF
                if (alpha >= 64) {
                    samplesR += (px ushr 16) and 0xFF
                    samplesG += (px ushr 8) and 0xFF
                    samplesB += px and 0xFF
                }
                x += stepX
            }
            y += stepY
        }

        if (samplesR.isEmpty()) return listOf("#111827")
        val n = samplesR.size
        val actualK = min(k, n)

        val centR = DoubleArray(actualK)
        val centG = DoubleArray(actualK)
        val centB = DoubleArray(actualK)
        for (c in 0 until actualK) {
            val idx = (c * (n - 1)) / max(1, actualK - 1)
            centR[c] = samplesR[idx].toDouble()
            centG[c] = samplesG[idx].toDouble()
            centB[c] = samplesB[idx].toDouble()
        }

        val counts = IntArray(actualK)
        val sumR = DoubleArray(actualK)
        val sumG = DoubleArray(actualK)
        val sumB = DoubleArray(actualK)

        repeat(8) {
            counts.fill(0)
            sumR.fill(0.0)
            sumG.fill(0.0)
            sumB.fill(0.0)

            for (i in 0 until n) {
                val r = samplesR[i].toDouble()
                val g = samplesG[i].toDouble()
                val b = samplesB[i].toDouble()
                var bestCluster = 0
                var bestDist = Double.MAX_VALUE
                for (c in 0 until actualK) {
                    val dr = r - centR[c]
                    val dg = g - centG[c]
                    val db = b - centB[c]
                    val dist = dr * dr + dg * dg + db * db
                    if (dist < bestDist) {
                        bestDist = dist
                        bestCluster = c
                    }
                }
                counts[bestCluster]++
                sumR[bestCluster] += r
                sumG[bestCluster] += g
                sumB[bestCluster] += b
            }

            for (c in 0 until actualK) {
                if (counts[c] > 0) {
                    centR[c] = sumR[c] / counts[c]
                    centG[c] = sumG[c] / counts[c]
                    centB[c] = sumB[c] / counts[c]
                }
            }
        }

        val ranked = (0 until actualK)
            .filter { counts[it] > 0 }
            .sortedByDescending { counts[it] }

        val deduped = mutableListOf<Int>()
        for (c in ranked) {
            val candidate = (0xFF shl 24) or
                (centR[c].roundToInt().coerceIn(0, 255) shl 16) or
                (centG[c].roundToInt().coerceIn(0, 255) shl 8) or
                centB[c].roundToInt().coerceIn(0, 255)
            if (deduped.none { cieLabDeltaE(it, candidate) < 7.5 }) {
                deduped += candidate
            }
        }
        if (deduped.isEmpty()) {
            deduped += (0xFF shl 24) or
                (centR[0].roundToInt() shl 16) or
                (centG[0].roundToInt() shl 8) or
                centB[0].roundToInt()
        }
        return deduped.take(targetColors).map { argb ->
            formatHex((argb ushr 16) and 0xFF, (argb ushr 8) and 0xFF, argb and 0xFF)
        }
    }

    /**
     * Перцептивное цветовое расстояние CIE76 ΔE в пространстве CIELAB (D65)
     * для умного поиска референсов по цвету палитры.
     */
    fun cieLabDeltaE(argbA: Int, argbB: Int): Double {
        val labA = rgbToLab(argbA)
        val labB = rgbToLab(argbB)
        val dl = labA[0] - labB[0]
        val da = labA[1] - labB[1]
        val db = labA[2] - labB[2]
        return sqrt(dl * dl + da * da + db * db)
    }

    private fun rgbToLab(argb: Int): DoubleArray {
        fun pivotRgb(v: Int): Double {
            val s = v / 255.0
            return if (s <= 0.04045) s / 12.92 else ((s + 0.055) / 1.055).pow(2.4)
        }
        val r = pivotRgb((argb ushr 16) and 0xFF)
        val g = pivotRgb((argb ushr 8) and 0xFF)
        val b = pivotRgb(argb and 0xFF)

        val x = (r * 0.4124564 + g * 0.3575761 + b * 0.1804375) / 0.95047
        val y = (r * 0.2126729 + g * 0.7151522 + b * 0.0721750) / 1.00000
        val z = (r * 0.0193339 + g * 0.1191920 + b * 0.9503041) / 1.08883

        fun pivotXyz(t: Double): Double =
            if (t > 0.008856) t.pow(1.0 / 3.0) else (7.787 * t) + (16.0 / 116.0)

        val fx = pivotXyz(x)
        val fy = pivotXyz(y)
        val fz = pivotXyz(z)

        return doubleArrayOf(
            (116.0 * fy) - 16.0,
            500.0 * (fx - fy),
            200.0 * (fy - fz),
        )
    }
}

/**
 * Компактный кодек BlurHash (Base83, 4×3 компоненты по умолчанию) для мгновенного (0 мс)
 * отображения цветовых подложек в Masonry-сетке до расшифровки WebP-миниатюры.
 */
object BlurHashCodec {
    private const val ALPHABET =
        "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz#$%*+,-.:;=?@[]^_{|}~"

    private val SRGB_TO_LINEAR = FloatArray(256) { i ->
        val v = i / 255f
        if (v <= 0.04045f) v / 12.92f else ((v + 0.055f) / 1.055f).pow(2.4f)
    }

    fun encode(image: ArgbImage, componentsX: Int = 4, componentsY: Int = 3): String {
        val cx = componentsX.coerceIn(1, 9)
        val cy = componentsY.coerceIn(1, 9)

        // Уменьшаем до компактного буфера <= 48x48 перед расчётом базиса косинусов
        val workW = min(image.width, 48)
        val workH = min(image.height, 48)
        val linR = FloatArray(workW * workH)
        val linG = FloatArray(workW * workH)
        val linB = FloatArray(workW * workH)

        for (y in 0 until workH) {
            val srcY = (y * image.height) / workH
            for (x in 0 until workW) {
                val srcX = (x * image.width) / workW
                val px = image.getPixel(srcX, srcY)
                val idx = y * workW + x
                linR[idx] = SRGB_TO_LINEAR[(px ushr 16) and 0xFF]
                linG[idx] = SRGB_TO_LINEAR[(px ushr 8) and 0xFF]
                linB[idx] = SRGB_TO_LINEAR[px and 0xFF]
            }
        }

        val factors = Array(cx * cy) { FloatArray(3) }
        for (j in 0 until cy) {
            for (i in 0 until cx) {
                val normalisation = if (i == 0 && j == 0) 1f else 2f
                var rSum = 0f
                var gSum = 0f
                var bSum = 0f
                for (y in 0 until workH) {
                    val basisY = cos((PI * j * y) / workH).toFloat()
                    for (x in 0 until workW) {
                        val basis = cos((PI * i * x) / workW).toFloat() * basisY
                        val idx = y * workW + x
                        rSum += basis * linR[idx]
                        gSum += basis * linG[idx]
                        bSum += basis * linB[idx]
                    }
                }
                val scale = normalisation / (workW * workH)
                val fIdx = j * cx + i
                factors[fIdx][0] = rSum * scale
                factors[fIdx][1] = gSum * scale
                factors[fIdx][2] = bSum * scale
            }
        }

        val sb = StringBuilder(4 + 2 * (cx * cy - 1))
        val sizeFlag = (cx - 1) + (cy - 1) * 9
        encodeBase83(sizeFlag, 1, sb)

        val maximumValue: Float
        if (factors.size > 1) {
            var actualMax = 0f
            for (k in 1 until factors.size) {
                actualMax = max(actualMax, abs(factors[k][0]))
                actualMax = max(actualMax, abs(factors[k][1]))
                actualMax = max(actualMax, abs(factors[k][2]))
            }
            val quantisedMax = max(0, min(82, (actualMax * 166f - 0.5f).toInt()))
            maximumValue = (quantisedMax + 1) / 166f
            encodeBase83(quantisedMax, 1, sb)
        } else {
            maximumValue = 1f
            encodeBase83(0, 1, sb)
        }

        encodeBase83(encodeDc(factors[0][0], factors[0][1], factors[0][2]), 4, sb)
        for (k in 1 until factors.size) {
            encodeBase83(encodeAc(factors[k][0], factors[k][1], factors[k][2], maximumValue), 2, sb)
        }
        return sb.toString()
    }

    fun decode(
        blurHash: String,
        outWidth: Int = 24,
        outHeight: Int = 24,
        punch: Float = 1.0f,
    ): ArgbImage {
        if (blurHash.length < 6) {
            return ArgbImage(outWidth, outHeight, IntArray(outWidth * outHeight) { 0xFF111827.toInt() })
        }
        val sizeFlag = decodeBase83(blurHash, 0, 1)
        val numY = (sizeFlag / 9) + 1
        val numX = (sizeFlag % 9) + 1
        val expectedLength = 4 + 2 * numX * numY
        if (blurHash.length != expectedLength) {
            return ArgbImage(outWidth, outHeight, IntArray(outWidth * outHeight) { 0xFF111827.toInt() })
        }

        val quantisedMax = decodeBase83(blurHash, 1, 2)
        val maxVal = ((quantisedMax + 1) / 166f) * punch

        val colors = Array(numX * numY) { FloatArray(3) }
        val dcVal = decodeBase83(blurHash, 2, 6)
        colors[0][0] = SRGB_TO_LINEAR[(dcVal ushr 16) and 0xFF]
        colors[0][1] = SRGB_TO_LINEAR[(dcVal ushr 8) and 0xFF]
        colors[0][2] = SRGB_TO_LINEAR[dcVal and 0xFF]

        for (i in 1 until numX * numY) {
            val acVal = decodeBase83(blurHash, 4 + i * 2, 6 + i * 2)
            val qR = acVal / (19 * 19)
            val qG = (acVal / 19) % 19
            val qB = acVal % 19
            colors[i][0] = signPow((qR - 9) / 9f, 2f) * maxVal
            colors[i][1] = signPow((qG - 9) / 9f, 2f) * maxVal
            colors[i][2] = signPow((qB - 9) / 9f, 2f) * maxVal
        }

        val cosX = Array(outWidth) { x ->
            FloatArray(numX) { i -> cos((PI * x * i) / outWidth).toFloat() }
        }
        val cosY = Array(outHeight) { y ->
            FloatArray(numY) { j -> cos((PI * y * j) / outHeight).toFloat() }
        }

        val pixels = IntArray(outWidth * outHeight)
        for (y in 0 until outHeight) {
            for (x in 0 until outWidth) {
                var r = 0f
                var g = 0f
                var b = 0f
                for (j in 0 until numY) {
                    val cyVal = cosY[y][j]
                    for (i in 0 until numX) {
                        val basis = cosX[x][i] * cyVal
                        val col = colors[j * numX + i]
                        r += col[0] * basis
                        g += col[1] * basis
                        b += col[2] * basis
                    }
                }
                pixels[y * outWidth + x] = (0xFF shl 24) or
                    (linearToSrgb(r) shl 16) or
                    (linearToSrgb(g) shl 8) or
                    linearToSrgb(b)
            }
        }
        return ArgbImage(outWidth, outHeight, pixels)
    }

    private fun encodeDc(r: Float, g: Float, b: Float): Int =
        (linearToSrgb(r) shl 16) or (linearToSrgb(g) shl 8) or linearToSrgb(b)

    private fun encodeAc(r: Float, g: Float, b: Float, maximumValue: Float): Int {
        val qR = max(0, min(18, (signPow(r / maximumValue, 0.5f) * 9f + 9.5f).toInt()))
        val qG = max(0, min(18, (signPow(g / maximumValue, 0.5f) * 9f + 9.5f).toInt()))
        val qB = max(0, min(18, (signPow(b / maximumValue, 0.5f) * 9f + 9.5f).toInt()))
        return qR * 19 * 19 + qG * 19 + qB
    }

    private fun linearToSrgb(value: Float): Int {
        val v = value.coerceIn(0f, 1f)
        val srgb = if (v <= 0.0031308f) {
            v * 12.92f
        } else {
            1.055f * v.pow(1f / 2.4f) - 0.055f
        }
        return (srgb * 255f + 0.5f).toInt().coerceIn(0, 255)
    }

    private fun signPow(value: Float, exp: Float): Float =
        abs(value).pow(exp) * sign(value)

    private fun encodeBase83(value: Int, length: Int, out: StringBuilder) {
        var divisor = 1
        repeat(length - 1) { divisor *= 83 }
        repeat(length) {
            val digit = (value / divisor) % 83
            divisor /= 83
            out.append(ALPHABET[digit.coerceIn(0, 82)])
        }
    }

    private fun decodeBase83(str: String, from: Int, to: Int): Int {
        var result = 0
        for (i in from until to) {
            val idx = ALPHABET.indexOf(str[i])
            if (idx >= 0) {
                result = result * 83 + idx
            }
        }
        return result
    }
}
