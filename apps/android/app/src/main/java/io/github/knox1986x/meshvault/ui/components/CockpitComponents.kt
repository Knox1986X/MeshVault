package io.github.knox1986x.meshvault.ui.components

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Add
import androidx.compose.material.icons.rounded.Folder
import androidx.compose.material.icons.rounded.Lock
import androidx.compose.material.icons.rounded.PushPin
import androidx.compose.material.icons.rounded.VisibilityOff
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import io.github.knox1986x.meshvault.i18n.RussianPlurals
import io.github.knox1986x.meshvault.security.VaultFolderItem
import io.github.knox1986x.meshvault.ui.theme.CockpitColors

@Composable
fun CockpitCard(
    modifier: Modifier = Modifier,
    onClick: (() -> Unit)? = null,
    content: @Composable () -> Unit,
) {
    val shape = RoundedCornerShape(12.dp)
    Surface(
        modifier = modifier
            .clip(shape)
            .let { if (onClick != null) it.clickable(onClick = onClick) else it },
        shape = shape,
        color = CockpitColors.CardSurface,
        border = BorderStroke(1.dp, CockpitColors.CardBorder),
    ) {
        content()
    }
}

@Composable
fun StatusPill(
    label: String,
    dotColor: Color,
    modifier: Modifier = Modifier,
) {
    Surface(
        modifier = modifier,
        shape = RoundedCornerShape(20.dp),
        color = CockpitColors.CardSurface,
        border = BorderStroke(1.dp, CockpitColors.CardBorder),
    ) {
        Row(
            modifier = Modifier.padding(horizontal = 10.dp, vertical = 5.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            Box(
                modifier = Modifier
                    .size(8.dp)
                    .clip(CircleShape)
                    .background(dotColor)
            )
            Text(
                text = label,
                color = CockpitColors.TextPrimary,
                fontSize = 11.sp,
                fontFamily = FontFamily.Monospace,
                maxLines = 1,
            )
        }
    }
}

@Composable
fun MetricCard(
    title: String,
    value: String,
    subtitle: String,
    accentColor: Color = CockpitColors.AccentVioletLight,
    progress: Float? = null,
    badge: String? = null,
    modifier: Modifier = Modifier,
) {
    CockpitCard(modifier = modifier) {
        Column(modifier = Modifier.padding(14.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    text = title,
                    color = CockpitColors.TextSecondary,
                    fontSize = 12.sp,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                if (badge != null) {
                    Text(
                        text = badge,
                        color = accentColor,
                        fontSize = 10.sp,
                        fontFamily = FontFamily.Monospace,
                        modifier = Modifier
                            .border(1.dp, accentColor.copy(alpha = 0.4f), RoundedCornerShape(6.dp))
                            .padding(horizontal = 6.dp, vertical = 2.dp)
                    )
                }
            }
            Spacer(modifier = Modifier.height(6.dp))
            Text(
                text = value,
                color = CockpitColors.TextPrimary,
                fontSize = 20.sp,
                fontWeight = FontWeight.Bold,
                fontFamily = FontFamily.Monospace,
            )
            Spacer(modifier = Modifier.height(4.dp))
            Text(
                text = subtitle,
                color = CockpitColors.TextMuted,
                fontSize = 11.sp,
                fontFamily = FontFamily.Monospace,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            if (progress != null) {
                Spacer(modifier = Modifier.height(8.dp))
                LinearProgressIndicator(
                    progress = { progress.coerceIn(0f, 1f) },
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(4.dp)
                        .clip(RoundedCornerShape(2.dp)),
                    color = accentColor,
                    trackColor = CockpitColors.CardBorder,
                )
            }
        }
    }
}

data class DonutSegment(
    val label: String,
    val bytes: Long,
    val color: Color,
)

@Composable
fun StorageDonut(
    segments: List<DonutSegment>,
    totalLabel: String,
    modifier: Modifier = Modifier,
) {
    val total = segments.sumOf { it.bytes }.coerceAtLeast(1L)
    CockpitCard(modifier = modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text(
                text = "Распределение хранилища",
                color = CockpitColors.TextPrimary,
                fontSize = 15.sp,
                fontWeight = FontWeight.SemiBold,
            )
            Spacer(modifier = Modifier.height(14.dp))
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(18.dp),
            ) {
                Box(
                    modifier = Modifier.size(116.dp),
                    contentAlignment = Alignment.Center,
                ) {
                    Canvas(modifier = Modifier.size(112.dp)) {
                        val stroke = Stroke(width = 16.dp.toPx(), cap = StrokeCap.Butt)
                        val active = segments.filter { it.bytes > 0L }
                        if (active.isEmpty()) {
                            drawArc(
                                color = CockpitColors.CardBorder,
                                startAngle = 0f,
                                sweepAngle = 360f,
                                useCenter = false,
                                style = stroke,
                            )
                        } else {
                            var start = -90f
                            active.forEach { seg ->
                                val sweep = (seg.bytes.toFloat() / total.toFloat()) * 360f
                                drawArc(
                                    color = seg.color,
                                    startAngle = start,
                                    sweepAngle = (sweep - 2f).coerceAtLeast(1f),
                                    useCenter = false,
                                    style = stroke,
                                )
                                start += sweep
                            }
                        }
                    }
                    Text(
                        text = totalLabel,
                        color = CockpitColors.TextPrimary,
                        fontSize = 12.sp,
                        fontFamily = FontFamily.Monospace,
                        fontWeight = FontWeight.SemiBold,
                    )
                }

                Column(
                    modifier = Modifier.weight(1f),
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    segments.forEach { seg ->
                        val pct = if (seg.bytes == 0L) 0 else ((seg.bytes * 100) / total).toInt()
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.spacedBy(6.dp),
                            ) {
                                Box(
                                    modifier = Modifier
                                        .size(8.dp)
                                        .clip(CircleShape)
                                        .background(seg.color)
                                )
                                Text(
                                    text = seg.label,
                                    color = CockpitColors.TextSecondary,
                                    fontSize = 12.sp,
                                )
                            }
                            Text(
                                text = "${formatBytesCompact(seg.bytes)} · $pct%",
                                color = CockpitColors.TextPrimary,
                                fontSize = 11.sp,
                                fontFamily = FontFamily.Monospace,
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
fun ImportTelemetryChart(
    throughputSamplesMb: List<Float>,
    workerLoadSamples: List<Float>,
    modifier: Modifier = Modifier,
) {
    CockpitCard(modifier = modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    text = "Поток шифрования (60s)",
                    color = CockpitColors.TextPrimary,
                    fontSize = 14.sp,
                    fontWeight = FontWeight.SemiBold,
                )
                Text(
                    text = "AEAD XChaCha20",
                    color = CockpitColors.Emerald,
                    fontSize = 11.sp,
                    fontFamily = FontFamily.Monospace,
                )
            }
            Spacer(modifier = Modifier.height(10.dp))
            Canvas(
                modifier = Modifier
                    .fillMaxWidth()
                    .height(74.dp)
            ) {
                val w = size.width
                val h = size.height
                drawLine(
                    color = CockpitColors.CardBorder,
                    start = Offset(0f, h * 0.5f),
                    end = Offset(w, h * 0.5f),
                    strokeWidth = 1.dp.toPx(),
                )
                drawLine(
                    color = CockpitColors.CardBorder,
                    start = Offset(0f, h - 1f),
                    end = Offset(w, h - 1f),
                    strokeWidth = 1.dp.toPx(),
                )

                drawSeries(throughputSamplesMb, CockpitColors.AccentViolet, Size(w, h))
                drawSeries(workerLoadSamples, CockpitColors.Emerald, Size(w, h))
            }
        }
    }
}

private fun androidx.compose.ui.graphics.drawscope.DrawScope.drawSeries(
    samples: List<Float>,
    color: Color,
    canvasSize: Size,
) {
    if (samples.size < 2) return
    val maxVal = (samples.maxOrNull() ?: 1f).coerceAtLeast(1f)
    val stepX = canvasSize.width / (samples.size - 1).toFloat()
    val path = Path()
    samples.forEachIndexed { idx, value ->
        val x = idx * stepX
        val y = canvasSize.height - ((value / maxVal).coerceIn(0f, 1f) * (canvasSize.height - 6f)) - 3f
        if (idx == 0) path.moveTo(x, y) else path.lineTo(x, y)
    }
    drawPath(path = path, color = color, style = Stroke(width = 2.dp.toPx(), cap = StrokeCap.Round))
}

@Composable
fun FolderTreeCard(
    folder: VaultFolderItem,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    CockpitCard(
        modifier = modifier.fillMaxWidth(),
        onClick = onClick,
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(14.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Box(
                modifier = Modifier
                    .size(44.dp)
                    .clip(RoundedCornerShape(10.dp))
                    .background(
                        if (folder.blurShield) CockpitColors.Amber.copy(alpha = 0.14f)
                        else CockpitColors.AccentViolet.copy(alpha = 0.18f)
                    ),
                contentAlignment = Alignment.Center,
            ) {
                Icon(
                    imageVector = if (folder.blurShield) Icons.Rounded.VisibilityOff else Icons.Rounded.Folder,
                    contentDescription = folder.name,
                    tint = if (folder.blurShield) CockpitColors.Amber else CockpitColors.AccentVioletLight,
                )
            }
            Column(modifier = Modifier.weight(1f)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        text = if (folder.blurShield) "${folder.name} (Blur Shield)" else folder.name,
                        color = CockpitColors.TextPrimary,
                        fontSize = 15.sp,
                        fontWeight = FontWeight.Medium,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        modifier = Modifier.weight(1f, fill = false),
                    )
                    if (folder.pinned) {
                        Spacer(modifier = Modifier.width(6.dp))
                        Icon(
                            imageVector = Icons.Rounded.PushPin,
                            contentDescription = "Закреплено",
                            tint = CockpitColors.Cyan,
                            modifier = Modifier.size(14.dp),
                        )
                    }
                }
                Spacer(modifier = Modifier.height(3.dp))
                val summary = "${RussianPlurals.subfoldersCount(folder.subfolderCount)} · " +
                    "${RussianPlurals.filesCount(folder.mediaCount)} · ${formatBytesCompact(folder.totalBytes)}"
                Text(
                    text = summary,
                    color = CockpitColors.TextSecondary,
                    fontSize = 11.sp,
                    fontFamily = FontFamily.Monospace,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
            Icon(
                imageVector = Icons.Rounded.Lock,
                contentDescription = "Зашифровано",
                tint = CockpitColors.Emerald,
                modifier = Modifier.size(16.dp),
            )
        }
    }
}

@Composable
fun PrimaryImportButton(
    label: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Button(
        onClick = onClick,
        modifier = modifier,
        shape = RoundedCornerShape(8.dp),
        colors = ButtonDefaults.buttonColors(
            containerColor = CockpitColors.AccentViolet,
            contentColor = Color.White,
        ),
    ) {
        Icon(imageVector = Icons.Rounded.Add, contentDescription = null, modifier = Modifier.size(18.dp))
        Spacer(modifier = Modifier.width(6.dp))
        Text(text = label, fontWeight = FontWeight.SemiBold, fontSize = 13.sp)
    }
}

fun formatBytesCompact(bytes: Long): String {
    if (bytes < 1024L) return "$bytes B"
    val kib = bytes / 1024.0
    if (kib < 1024.0) return String.format("%.1f KB", kib)
    val mib = kib / 1024.0
    if (mib < 1024.0) return String.format("%.1f MB", mib)
    val gib = mib / 1024.0
    return String.format("%.2f GB", gib)
}
