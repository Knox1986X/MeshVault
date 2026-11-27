package com.meshvault.data.media

import android.graphics.Bitmap
import android.graphics.Matrix
import android.os.Build
import androidx.exifinterface.media.ExifInterface
import com.google.zxing.BarcodeFormat
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.MultiFormatReader
import com.google.zxing.RGBLuminanceSource
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.qrcode.QRCodeWriter
import com.meshvault.domain.media.ArgbImage
import java.io.ByteArrayOutputStream
import kotlin.math.max
import kotlin.math.min
import kotlin.math.roundToInt

fun Bitmap.toArgbImage(maxDimension: Int = 256): ArgbImage {
    val scaled = if (width > maxDimension || height > maxDimension) {
        val ratio = min(maxDimension.toFloat() / width.toFloat(), maxDimension.toFloat() / height.toFloat())
        val tw = max(1, (width * ratio).roundToInt())
        val th = max(1, (height * ratio).roundToInt())
        Bitmap.createScaledBitmap(this, tw, th, true)
    } else {
        this
    }
    val softBitmap = if (scaled.config == Bitmap.Config.HARDWARE) {
        scaled.copy(Bitmap.Config.ARGB_8888, false) ?: scaled
    } else {
        scaled
    }
    val pixels = IntArray(softBitmap.width * softBitmap.height)
    softBitmap.getPixels(pixels, 0, softBitmap.width, 0, 0, softBitmap.width, softBitmap.height)
    val result = ArgbImage(softBitmap.width, softBitmap.height, pixels)
    if (softBitmap !== scaled && softBitmap !== this) softBitmap.recycle()
    if (scaled !== this) scaled.recycle()
    return result
}

fun ArgbImage.toAndroidBitmap(): Bitmap =
    Bitmap.createBitmap(pixels, width, height, Bitmap.Config.ARGB_8888)

object WebpBitmapEncoder {
    fun compressWebpLossy(bitmap: Bitmap, quality: Int = 82): ByteArray {
        val out = ByteArrayOutputStream(16_384)
        val format = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            Bitmap.CompressFormat.WEBP_LOSSY
        } else {
            @Suppress("DEPRECATION")
            Bitmap.CompressFormat.WEBP
        }
        bitmap.compress(format, quality.coerceIn(1, 100), out)
        return out.toByteArray()
    }

    fun compressPngLossless(bitmap: Bitmap): ByteArray {
        val out = ByteArrayOutputStream(65_536)
        bitmap.compress(Bitmap.CompressFormat.PNG, 100, out)
        return out.toByteArray()
    }
}

object ExifOrientationHelper {
    fun applyOrientation(source: Bitmap, exifOrientation: Int): Bitmap {
        val matrix = Matrix()
        when (exifOrientation) {
            ExifInterface.ORIENTATION_ROTATE_90 -> matrix.postRotate(90f)
            ExifInterface.ORIENTATION_ROTATE_180 -> matrix.postRotate(180f)
            ExifInterface.ORIENTATION_ROTATE_270 -> matrix.postRotate(270f)
            ExifInterface.ORIENTATION_FLIP_HORIZONTAL -> matrix.preScale(-1f, 1f)
            ExifInterface.ORIENTATION_FLIP_VERTICAL -> matrix.preScale(1f, -1f)
            ExifInterface.ORIENTATION_TRANSPOSE -> {
                matrix.postRotate(90f)
                matrix.preScale(-1f, 1f)
            }
            ExifInterface.ORIENTATION_TRANSVERSE -> {
                matrix.postRotate(270f)
                matrix.preScale(-1f, 1f)
            }
            else -> return source
        }
        val transformed = Bitmap.createBitmap(source, 0, 0, source.width, source.height, matrix, true)
        if (transformed !== source) source.recycle()
        return transformed
    }
}

/**
 * Автономный офлайн-сканер и генератор QR-кодов `otpauth://` на базе ZXing (без Google Play Services).
 */
object QrCodeImageScanner {
    fun decodeQrFromBitmap(bitmap: Bitmap): String? {
        val argb = bitmap.toArgbImage(maxDimension = 900)
        val source = RGBLuminanceSource(argb.width, argb.height, argb.pixels)
        val binary = BinaryBitmap(HybridBinarizer(source))
        val hints = mapOf(
            DecodeHintType.TRY_HARDER to true,
            DecodeHintType.POSSIBLE_FORMATS to listOf(BarcodeFormat.QR_CODE),
            DecodeHintType.CHARACTER_SET to "UTF-8",
        )
        return runCatching {
            MultiFormatReader().decode(binary, hints).text
        }.getOrNull()
    }

    fun generateQrBitmap(content: String, sizePx: Int = 512): Bitmap {
        val matrix = QRCodeWriter().encode(content, BarcodeFormat.QR_CODE, sizePx, sizePx)
        val pixels = IntArray(sizePx * sizePx)
        val fg = 0xFF10B981.toInt()
        val bg = 0xFF090D16.toInt()
        for (y in 0 until sizePx) {
            val rowOffset = y * sizePx
            for (x in 0 until sizePx) {
                pixels[rowOffset + x] = if (matrix.get(x, y)) fg else bg
            }
        }
        return Bitmap.createBitmap(pixels, sizePx, sizePx, Bitmap.Config.ARGB_8888)
    }
}
