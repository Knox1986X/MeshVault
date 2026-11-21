package io.github.knox1986x.meshvault.ui.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp

object CockpitColors {
    val Background = Color(0xFF0B0B14)
    val CardSurface = Color(0xFF12121E)
    val CardBorder = Color(0xFF1E1E30)
    val NavSurface = Color(0xFF0E0E18)
    val AccentViolet = Color(0xFF7C3AED)
    val AccentVioletLight = Color(0xFFA78BFA)
    val Emerald = Color(0xFF10B981)
    val Amber = Color(0xFFF59E0B)
    val Red = Color(0xFFEF4444)
    val Cyan = Color(0xFF06B6D4)
    val TextPrimary = Color(0xFFE2E8F0)
    val TextSecondary = Color(0xFF94A3B8)
    val TextMuted = Color(0xFF64748B)
}

object CockpitTypography {
    val MonoLabel = TextStyle(
        fontFamily = FontFamily.Monospace,
        fontWeight = FontWeight.Medium,
        fontSize = 12.sp,
        color = CockpitColors.TextSecondary,
    )
    val MonoValue = TextStyle(
        fontFamily = FontFamily.Monospace,
        fontWeight = FontWeight.SemiBold,
        fontSize = 18.sp,
        color = CockpitColors.TextPrimary,
    )
}

private val DarkCockpitScheme = darkColorScheme(
    primary = CockpitColors.AccentViolet,
    onPrimary = Color.White,
    secondary = CockpitColors.Cyan,
    background = CockpitColors.Background,
    surface = CockpitColors.CardSurface,
    surfaceVariant = CockpitColors.NavSurface,
    onBackground = CockpitColors.TextPrimary,
    onSurface = CockpitColors.TextPrimary,
    onSurfaceVariant = CockpitColors.TextSecondary,
    outline = CockpitColors.CardBorder,
    error = CockpitColors.Red,
)

@Composable
fun MeshVaultCockpitTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = DarkCockpitScheme,
        content = content,
    )
}
