package io.github.knox1986x.meshvault.ui.screens

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
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Search
import androidx.compose.material3.Icon
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import io.github.knox1986x.meshvault.security.VaultMediaItem
import io.github.knox1986x.meshvault.ui.components.CockpitCard
import io.github.knox1986x.meshvault.ui.components.formatBytesCompact
import io.github.knox1986x.meshvault.ui.theme.CockpitColors

@Composable
fun SearchScreen(
    allMedia: List<VaultMediaItem>,
    onOpenMedia: (VaultMediaItem) -> Unit,
) {
    var query by remember { mutableStateOf("") }

    val matches = remember(query, allMedia) {
        val q = query.trim().lowercase()
        if (q.isEmpty()) {
            allMedia
        } else {
            allMedia.filter { item ->
                item.originalName.lowercase().contains(q) ||
                    item.mimeType.lowercase().contains(q) ||
                    (item.exifCamera?.lowercase()?.contains(q) == true) ||
                    item.tags.any { it.lowercase().contains(q) }
            }
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
    ) {
        OutlinedTextField(
            value = query,
            onValueChange = { query = it },
            leadingIcon = { Icon(Icons.Rounded.Search, contentDescription = null) },
            label = { Text("Поиск по имени, тегам, камере EXIF и формату") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )
        Spacer(modifier = Modifier.height(10.dp))
        Text(
            text = "Найдено объектов: ${matches.size} · офлайн-индекс в ОЗУ",
            color = CockpitColors.TextSecondary,
            fontFamily = FontFamily.Monospace,
            fontSize = 11.sp,
        )
        Spacer(modifier = Modifier.height(10.dp))

        LazyColumn(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            items(matches, key = { it.id }) { item ->
                CockpitCard(
                    modifier = Modifier.fillMaxWidth(),
                    onClick = { onOpenMedia(item) },
                ) {
                    Row(
                        modifier = Modifier.padding(12.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(text = item.originalName, color = CockpitColors.TextPrimary, fontSize = 14.sp)
                            Text(
                                text = listOfNotNull(item.exifCamera, item.mimeType, formatBytesCompact(item.plaintextSize)).joinToString(" · "),
                                color = CockpitColors.TextMuted,
                                fontFamily = FontFamily.Monospace,
                                fontSize = 11.sp,
                            )
                        }
                    }
                }
            }
        }
    }
}
