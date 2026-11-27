package com.meshvault.ui.components

import androidx.compose.ui.graphics.Color
import kotlin.math.abs

/** Разбирает «#RRGGBB» / «#AARRGGBB» в Compose Color. Некорректные строки → изумрудный акцент. */
fun parseHexColor(hex: String): Color {
    val cleaned = hex.trim().removePrefix("#")
    return runCatching {
        when (cleaned.length) {
            6 -> Color(0xFF000000L or cleaned.toLong(16))
            8 -> Color(cleaned.toLong(16))
            3 -> {
                val expanded = cleaned.map { "$it$it" }.joinToString("")
                Color(0xFF000000L or expanded.toLong(16))
            }
            else -> CyberFallback
        }
    }.getOrDefault(CyberFallback)
}

private val CyberFallback: Color = Color(0xFF10B981L)

/** «12,4 МБ», «812 КБ», «1,3 ГБ» — компактные подписи размеров. */
fun formatBytesCompact(bytes: Long): String {
    val absBytes = abs(bytes)
    return when {
        absBytes >= 1L * 1024 * 1024 * 1024 -> String.format(java.util.Locale.US, "%.1f ГБ", bytes / (1024.0 * 1024.0 * 1024.0))
        absBytes >= 1L * 1024 * 1024 -> String.format(java.util.Locale.US, "%.1f МБ", bytes / (1024.0 * 1024.0))
        absBytes >= 1024L -> String.format(java.util.Locale.US, "%.0f КБ", bytes / 1024.0)
        else -> "$bytes Б"
    }
}

/** «01:47» для mm:ss — подписи длительности видео. */
fun formatDurationShort(durationMs: Long): String {
    val totalSec = (durationMs / 1000L).coerceAtLeast(0L)
    val minutes = totalSec / 60
    val seconds = totalSec % 60
    return String.format(java.util.Locale.US, "%02d:%02d", minutes, seconds)
}

/** «00:12:03» для HH:MM:SS — длина видео в деталях. */
fun formatDurationFull(durationMs: Long): String {
    val totalSec = (durationMs / 1000L).coerceAtLeast(0L)
    val hours = totalSec / 3600
    val minutes = (totalSec % 3600) / 60
    val seconds = totalSec % 60
    return String.format(java.util.Locale.US, "%02d:%02d:%02d", hours, minutes, seconds)
}
