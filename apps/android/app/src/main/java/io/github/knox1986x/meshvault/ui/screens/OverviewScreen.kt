package io.github.knox1986x.meshvault.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import io.github.knox1986x.meshvault.i18n.RussianPlurals
import io.github.knox1986x.meshvault.security.VaultFolderItem
import io.github.knox1986x.meshvault.security.VaultMetricsSnapshot
import io.github.knox1986x.meshvault.ui.components.DonutSegment
import io.github.knox1986x.meshvault.ui.components.FolderTreeCard
import io.github.knox1986x.meshvault.ui.components.ImportTelemetryChart
import io.github.knox1986x.meshvault.ui.components.MetricCard
import io.github.knox1986x.meshvault.ui.components.PrimaryImportButton
import io.github.knox1986x.meshvault.ui.components.StorageDonut
import io.github.knox1986x.meshvault.ui.components.formatBytesCompact
import io.github.knox1986x.meshvault.ui.theme.CockpitColors

@Composable
fun OverviewScreen(
    metrics: VaultMetricsSnapshot,
    pinnedFolders: List<VaultFolderItem>,
    pipelineThroughputMb: List<Float>,
    workerLoadSamples: List<Float>,
    onOpenImportMenu: () -> Unit,
    onOpenFolder: (VaultFolderItem) -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            MetricCard(
                title = "Медиа в сейфе",
                value = metrics.totalMedia.toString(),
                subtitle = RussianPlurals.foldersCount(metrics.folderCount),
                accentColor = CockpitColors.AccentVioletLight,
                badge = "E2EE",
                modifier = Modifier.weight(1f),
            )
            MetricCard(
                title = "Объём сейфа",
                value = formatBytesCompact(metrics.totalBytes),
                subtitle = "Паки превью: ${formatBytesCompact(metrics.thumbPackBytes)}",
                accentColor = CockpitColors.Cyan,
                progress = ((metrics.totalBytes % (1024L * 1024L * 1024L)) / (1024f * 1024f * 1024f)).coerceAtLeast(0.08f),
                modifier = Modifier.weight(1f),
            )
        }

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            val latestRate = pipelineThroughputMb.lastOrNull() ?: 0f
            MetricCard(
                title = "Скорость конвейера",
                value = if (latestRate > 0.1f) String.format("%.1f MB/s", latestRate) else "0 B/s",
                subtitle = if (latestRate > 0.1f) "Активное шифрование" else "Покой · ОЗУ чистое",
                accentColor = CockpitColors.Emerald,
                badge = "Live",
                modifier = Modifier.weight(1f),
            )
            MetricCard(
                title = "Индекс и защита",
                value = "rev ${metrics.headerRevision}",
                subtitle = "Argon2id + Keystore · Корзина: ${metrics.trashedCount}",
                accentColor = CockpitColors.Emerald,
                modifier = Modifier.weight(1f),
            )
        }

        StorageDonut(
            segments = listOf(
                DonutSegment("Фото", metrics.photoBytes, CockpitColors.AccentViolet),
                DonutSegment("Видео 4K", metrics.videoBytes, CockpitColors.Cyan),
                DonutSegment("RAW", metrics.rawBytes, CockpitColors.Amber),
                DonutSegment("Сканы / PDF", metrics.docBytes, CockpitColors.Emerald),
                DonutSegment("Превью .mvt", metrics.thumbPackBytes, CockpitColors.AccentVioletLight),
            ),
            totalLabel = formatBytesCompact(metrics.totalBytes + metrics.thumbPackBytes),
        )

        ImportTelemetryChart(
            throughputSamplesMb = pipelineThroughputMb,
            workerLoadSamples = workerLoadSamples,
        )

        PrimaryImportButton(
            label = "+ Импорт фото или дерева папок",
            onClick = onOpenImportMenu,
            modifier = Modifier.fillMaxWidth(),
        )

        if (pinnedFolders.isNotEmpty()) {
            Spacer(modifier = Modifier.height(2.dp))
            Text(
                text = "Закреплённые папки",
                color = CockpitColors.TextPrimary,
                fontSize = 15.sp,
                fontWeight = FontWeight.SemiBold,
            )
            pinnedFolders.forEach { folder ->
                FolderTreeCard(
                    folder = folder,
                    onClick = { onOpenFolder(folder) },
                )
            }
        }
    }
}
