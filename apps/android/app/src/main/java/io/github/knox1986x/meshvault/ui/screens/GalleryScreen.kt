package io.github.knox1986x.meshvault.ui.screens

import android.graphics.BitmapFactory
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.grid.GridCells
import androidx.compose.foundation.lazy.grid.LazyVerticalGrid
import androidx.compose.foundation.lazy.grid.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Favorite
import androidx.compose.material.icons.rounded.Lock
import androidx.compose.material.icons.rounded.Videocam
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import io.github.knox1986x.meshvault.security.MediaCategory
import io.github.knox1986x.meshvault.security.VaultMediaItem
import io.github.knox1986x.meshvault.ui.components.CockpitCard
import io.github.knox1986x.meshvault.ui.theme.CockpitColors

private enum class QuickFilter(val label: String) {
    ALL("Все"),
    PHOTOS("Фото"),
    VIDEOS("Видео"),
    RAW("RAW"),
    DOCS("Документы"),
    FAVORITES("Избранное"),
}

@Composable
fun GalleryScreen(
    timeline: List<VaultMediaItem>,
    loadThumbBytes: (String) -> ByteArray,
    onOpenMedia: (VaultMediaItem) -> Unit,
) {
    var columns by remember { mutableIntStateOf(3) }
    var filter by remember { mutableStateOf(QuickFilter.ALL) }

    val filtered = remember(timeline, filter) {
        when (filter) {
            QuickFilter.ALL -> timeline
            QuickFilter.PHOTOS -> timeline.filter { it.category == MediaCategory.PHOTO }
            QuickFilter.VIDEOS -> timeline.filter { it.category == MediaCategory.VIDEO }
            QuickFilter.RAW -> timeline.filter { it.category == MediaCategory.RAW_PHOTO }
            QuickFilter.DOCS -> timeline.filter {
                it.category == MediaCategory.DOCUMENT_PDF || it.category == MediaCategory.MARKDOWN_NOTE
            }
            QuickFilter.FAVORITES -> timeline.filter { it.favorite }
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 12.dp, vertical = 8.dp),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            Row(
                modifier = Modifier
                    .weight(1f)
                    .horizontalScroll(rememberScrollState()),
                horizontalArrangement = Arrangement.spacedBy(6.dp),
            ) {
                QuickFilter.entries.forEach { item ->
                    FilterChip(
                        selected = filter == item,
                        onClick = { filter = item },
                        label = { Text(item.label, fontSize = 11.sp) },
                    )
                }
            }
            Row(verticalAlignment = Alignment.CenterVertically) {
                IconButton(onClick = { if (columns > 2) columns-- }) {
                    Text("-", color = CockpitColors.TextPrimary, fontFamily = FontFamily.Monospace)
                }
                Text(
                    text = "${columns}x",
                    color = CockpitColors.AccentVioletLight,
                    fontFamily = FontFamily.Monospace,
                    fontSize = 12.sp,
                )
                IconButton(onClick = { if (columns < 7) columns++ }) {
                    Text("+", color = CockpitColors.TextPrimary, fontFamily = FontFamily.Monospace)
                }
            }
        }

        if (filtered.isEmpty()) {
            CockpitCard(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(top = 12.dp),
            ) {
                Text(
                    text = "Нет медиафайлов для выбранного фильтра.",
                    color = CockpitColors.TextSecondary,
                    modifier = Modifier.padding(18.dp),
                )
            }
        } else {
            LazyVerticalGrid(
                columns = GridCells.Fixed(columns),
                horizontalArrangement = Arrangement.spacedBy(6.dp),
                verticalArrangement = Arrangement.spacedBy(6.dp),
                modifier = Modifier.fillMaxSize(),
            ) {
                items(filtered, key = { it.id }) { media ->
                    val bitmap = remember(media.id) {
                        val bytes = media.microThumbBytes ?: loadThumbBytes(media.id)
                        if (bytes.isNotEmpty()) BitmapFactory.decodeByteArray(bytes, 0, bytes.size)?.asImageBitmap()
                        else null
                    }
                    Box(
                        modifier = Modifier
                            .aspectRatio(1f)
                            .clip(RoundedCornerShape(8.dp))
                            .background(CockpitColors.CardSurface)
                            .clickable { onOpenMedia(media) },
                    ) {
                        if (bitmap != null) {
                            Image(
                                bitmap = bitmap,
                                contentDescription = media.originalName,
                                contentScale = ContentScale.Crop,
                                modifier = Modifier.fillMaxSize(),
                            )
                        } else {
                            Icon(
                                imageVector = if (media.category == MediaCategory.VIDEO) Icons.Rounded.Videocam else Icons.Rounded.Lock,
                                contentDescription = media.originalName,
                                tint = CockpitColors.AccentVioletLight,
                                modifier = Modifier.align(Alignment.Center),
                            )
                        }
                        if (media.favorite) {
                            Icon(
                                imageVector = Icons.Rounded.Favorite,
                                contentDescription = "Избранное",
                                tint = CockpitColors.Red,
                                modifier = Modifier
                                    .align(Alignment.TopEnd)
                                    .padding(4.dp),
                            )
                        }
                    }
                }
            }
        }
    }
}
