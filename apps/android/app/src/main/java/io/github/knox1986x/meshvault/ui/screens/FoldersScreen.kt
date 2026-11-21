package io.github.knox1986x.meshvault.ui.screens

import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.CreateNewFolder
import androidx.compose.material.icons.rounded.Image
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import io.github.knox1986x.meshvault.security.FolderContentsSnapshot
import io.github.knox1986x.meshvault.security.VaultFolderItem
import io.github.knox1986x.meshvault.security.VaultMediaItem
import io.github.knox1986x.meshvault.ui.components.CockpitCard
import io.github.knox1986x.meshvault.ui.components.FolderTreeCard
import io.github.knox1986x.meshvault.ui.components.PrimaryImportButton
import io.github.knox1986x.meshvault.ui.components.formatBytesCompact
import io.github.knox1986x.meshvault.ui.theme.CockpitColors

@Composable
fun FoldersScreen(
    breadcrumbs: List<VaultFolderItem>,
    contents: FolderContentsSnapshot,
    onNavigateFolder: (String) -> Unit,
    onCreateSubfolder: (String) -> Unit,
    onOpenImportMenu: () -> Unit,
    onOpenMedia: (VaultMediaItem) -> Unit,
) {
    var showCreateDialog by remember { mutableStateOf(false) }
    var newFolderName by remember { mutableStateOf("") }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Row(
                modifier = Modifier
                    .weight(1f)
                    .horizontalScroll(rememberScrollState()),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                breadcrumbs.forEachIndexed { idx, node ->
                    TextButton(onClick = { onNavigateFolder(node.id) }) {
                        Text(
                            text = if (idx == 0) "Сейф" else node.name,
                            color = if (idx == breadcrumbs.lastIndex) CockpitColors.AccentVioletLight else CockpitColors.TextSecondary,
                            fontFamily = FontFamily.Monospace,
                            fontSize = 12.sp,
                        )
                    }
                    if (idx < breadcrumbs.lastIndex) {
                        Text(text = "/", color = CockpitColors.TextMuted, fontFamily = FontFamily.Monospace)
                    }
                }
            }

            IconButton(onClick = { showCreateDialog = true }) {
                Icon(
                    imageVector = Icons.Rounded.CreateNewFolder,
                    contentDescription = "Новая папка",
                    tint = CockpitColors.TextPrimary,
                )
            }
            PrimaryImportButton(label = "+ Импорт", onClick = onOpenImportMenu)
        }

        Spacer(modifier = Modifier.height(10.dp))

        if (contents.subfolders.isEmpty() && contents.media.isEmpty()) {
            CockpitCard(modifier = Modifier.fillMaxWidth()) {
                Column(modifier = Modifier.padding(20.dp)) {
                    Text(
                        text = "Папка пуста",
                        color = CockpitColors.TextPrimary,
                        fontSize = 16.sp,
                    )
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        text = "Нажмите «+ Импорт», чтобы добавить фото, видео или целое дерево папок с сохранением всех подпапок.",
                        color = CockpitColors.TextSecondary,
                        fontSize = 13.sp,
                    )
                }
            }
        } else {
            LazyColumn(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                items(contents.subfolders, key = { it.id }) { folder ->
                    FolderTreeCard(
                        folder = folder,
                        onClick = { onNavigateFolder(folder.id) },
                    )
                }
                items(contents.media, key = { it.id }) { item ->
                    CockpitCard(
                        modifier = Modifier.fillMaxWidth(),
                        onClick = { onOpenMedia(item) },
                    ) {
                        Row(
                            modifier = Modifier.padding(12.dp),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(12.dp),
                        ) {
                            Icon(
                                imageVector = Icons.Rounded.Image,
                                contentDescription = item.originalName,
                                tint = CockpitColors.Cyan,
                            )
                            Column(modifier = Modifier.weight(1f)) {
                                Text(
                                    text = item.originalName,
                                    color = CockpitColors.TextPrimary,
                                    fontSize = 14.sp,
                                    maxLines = 1,
                                )
                                Text(
                                    text = "${item.mimeType} · ${formatBytesCompact(item.plaintextSize)}",
                                    color = CockpitColors.TextSecondary,
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

    if (showCreateDialog) {
        AlertDialog(
            onDismissRequest = { showCreateDialog = false },
            containerColor = CockpitColors.CardSurface,
            title = { Text("Новая зашифрованная папка", color = CockpitColors.TextPrimary) },
            text = {
                OutlinedTextField(
                    value = newFolderName,
                    onValueChange = { newFolderName = it },
                    singleLine = true,
                    label = { Text("Название папки") },
                )
            },
            confirmButton = {
                Button(
                    shape = RoundedCornerShape(8.dp),
                    onClick = {
                        val trimmed = newFolderName.trim()
                        if (trimmed.isNotEmpty()) {
                            onCreateSubfolder(trimmed)
                            newFolderName = ""
                            showCreateDialog = false
                        }
                    },
                ) {
                    Text("Создать")
                }
            },
            dismissButton = {
                TextButton(onClick = { showCreateDialog = false }) {
                    Text("Отмена")
                }
            },
        )
    }
}
