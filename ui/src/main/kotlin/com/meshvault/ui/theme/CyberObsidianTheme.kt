package com.meshvault.ui.theme

import androidx.compose.material3.ColorScheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.Typography
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

/**
 * Фирменная палитра Cyber-Obsidian (OLED):
 * глубокий графит, плотные тонированные поверхности без тяжёлых размытий,
 * изумрудный акцент для подтверждений и голубой — для синхронизации и статусов.
 */
object CyberObsidian {
    val Abyss = Color(0xFF090D16)
    val Surface = Color(0xFF111827)
    val SurfaceRaised = Color(0xFF1F2937)
    val SurfaceHighest = Color(0xFF273449)
    val Emerald = Color(0xFF10B981)
    val EmeraldDim = Color(0xFF0F3D2E)
    val EmeraldOn = Color(0xFF06281D)
    val Sky = Color(0xFF38BDF8)
    val SkyDim = Color(0xFF0E3A52)
    val Violet = Color(0xFFA78BFA)
    val Amber = Color(0xFFF59E0B)
    val Danger = Color(0xFFF87171)
    val DangerDim = Color(0xFF3E0B0B)
    val TextPrimary = Color(0xFFE5E7EB)
    val TextSecondary = Color(0xFF9CA3AF)
    val TextMuted = Color(0xFF6B7280)
    val Outline = Color(0xFF1F2937)
    val OutlineStrong = Color(0xFF374151)
}

private val CyberObsidianColors: ColorScheme = darkColorScheme(
    primary = CyberObsidian.Emerald,
    onPrimary = CyberObsidian.EmeraldOn,
    primaryContainer = CyberObsidian.EmeraldDim,
    onPrimaryContainer = Color(0xFFD5F7E9),
    secondary = CyberObsidian.Sky,
    onSecondary = Color(0xFF062A3F),
    secondaryContainer = CyberObsidian.SkyDim,
    onSecondaryContainer = Color(0xFFD9F1FE),
    tertiary = CyberObsidian.Violet,
    onTertiary = Color(0xFF241A47),
    tertiaryContainer = Color(0xFF342A5C),
    onTertiaryContainer = Color(0xFFEBE3FF),
    error = CyberObsidian.Danger,
    onError = CyberObsidian.DangerDim,
    errorContainer = Color(0xFF7F1D1D),
    onErrorContainer = Color(0xFFFEE2E2),
    background = CyberObsidian.Abyss,
    onBackground = CyberObsidian.TextPrimary,
    surface = CyberObsidian.Surface,
    onSurface = CyberObsidian.TextPrimary,
    surfaceVariant = CyberObsidian.SurfaceRaised,
    onSurfaceVariant = CyberObsidian.TextSecondary,
    outline = CyberObsidian.OutlineStrong,
    outlineVariant = CyberObsidian.Outline,
    inversePrimary = CyberObsidian.Emerald,
    inverseSurface = CyberObsidian.TextPrimary,
    inverseOnSurface = CyberObsidian.Abyss,
    scrim = Color(0xFF000000),
)

private val CyberObsidianTypography = Typography()

@Composable
fun CyberObsidianTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = CyberObsidianColors,
        typography = CyberObsidianTypography,
        content = content,
    )
}
