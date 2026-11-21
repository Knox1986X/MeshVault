package io.github.knox1986x.meshvault.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import io.github.knox1986x.meshvault.i18n.RussianPlurals
import io.github.knox1986x.meshvault.saf.SafTreePreview
import io.github.knox1986x.meshvault.ui.components.formatBytesCompact
import io.github.knox1986x.meshvault.ui.theme.CockpitColors

@Composable
fun ImportPreviewDialog(
    preview: SafTreePreview,
    freeDeviceBytes: Long,
    onConfirmImport: (selectedBranches: Set<String>) -> Unit,
    onDismiss: () -> Unit,
) {
    val selections = remember(preview) {
        mutableStateMapOf<String, Boolean>().apply {
            preview.branches.forEach { put(it.relativePath, it.selected) }
        }
    }
    val hasEnoughSpace = freeDeviceBytes > (preview.totalBytes + 32L * 1024L * 1024L)

    AlertDialog(
        onDismissRequest = onDismiss,
        containerColor = CockpitColors.CardSurface,
        title = {
            Column {
                Text(
                    text = "Предпросмотр дерева импорта",
                    color = CockpitColors.TextPrimary,
                    fontWeight = FontWeight.SemiBold,
                    fontSize = 17.sp,
                )
                Text(
                    text = "Фото: ${preview.photoCount} · Видео: ${preview.videoCount} · RAW: ${preview.rawCount} · Док: ${preview.documentCount}",
                    color = CockpitColors.TextSecondary,
                    fontFamily = FontFamily.Monospace,
                    fontSize = 11.sp,
                )
            }
        },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(
                    text = "Размер: ${formatBytesCompact(preview.totalBytes)} · Свободно: ${formatBytesCompact(freeDeviceBytes)}",
                    color = if (hasEnoughSpace) CockpitColors.Emerald else CockpitColors.Amber,
                    fontFamily = FontFamily.Monospace,
                    fontSize = 12.sp,
                )
                LazyColumn(
                    modifier = Modifier
                        .fillMaxWidth()
                        .heightIn(max = 280.dp),
                ) {
                    items(preview.branches, key = { it.relativePath }) { branch ->
                        val checked = selections[branch.relativePath] ?: true
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(start = (branch.depth * 14).dp),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Checkbox(
                                checked = checked,
                                onCheckedChange = { selections[branch.relativePath] = it },
                            )
                            Column(modifier = Modifier.weight(1f)) {
                                Text(
                                    text = branch.displayName,
                                    color = CockpitColors.TextPrimary,
                                    fontSize = 13.sp,
                                )
                                Text(
                                    text = "${RussianPlurals.filesCount(branch.fileCount.toLong())} · ${formatBytesCompact(branch.totalBytes)}",
                                    color = CockpitColors.TextMuted,
                                    fontFamily = FontFamily.Monospace,
                                    fontSize = 11.sp,
                                )
                            }
                        }
                    }
                }
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = "Оригиналы останутся нетронутыми до полной верификации Poly1305-тегов и коммита каталога.",
                    color = CockpitColors.TextSecondary,
                    fontSize = 11.sp,
                )
            }
        },
        confirmButton = {
            Button(
                shape = RoundedCornerShape(8.dp),
                colors = ButtonDefaults.buttonColors(containerColor = CockpitColors.AccentViolet),
                onClick = {
                    val selected = selections.filterValues { it }.keys.toSet()
                    onConfirmImport(selected)
                },
            ) {
                Text("Зашифровать выбранное")
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text("Отмена")
            }
        },
    )
}
