package com.meshvault.ui.components

import android.graphics.Bitmap
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.Image
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.clickable
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.painter.BitmapPainter
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.material.icons.Icons
import com.meshvault.domain.model.FolderIconType
import com.meshvault.domain.model.MediaItem
import com.meshvault.domain.model.VaultFolder
import com.meshvault.ui.theme.CyberObsidian
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/** Карточка папки: обложка из выбранного фото или автоколлаж из 4 превью. */
@Composable
fun FolderCoverCard(
    folder: VaultFolder,
    folderMedia: List<MediaItem>,
    loadThumbnail: suspend (MediaItem) -> Bitmap?,
    modifier: Modifier = Modifier,
    onClick: () -> Unit,
    onEdit: () -> Unit,
) {
    val coverSelection: List<MediaItem> = remember(folder.coverMediaId, folderMedia) {
        when {
            folder.coverMediaId != null -> folderMedia.filter { it.id == folder.coverMediaId }.ifEmpty { folderMedia.take(4) }
            else -> folderMedia.take(4)
        }
    }

    val coverBitmaps by produceState<List<Bitmap?>>(
        initialValue = emptyList(),
        key1 = coverSelection.map { it.id },
    ) {
        value = coverSelection.map { item ->
            withContext(Dispatchers.IO) { loadThumbnail(item) }
        }
    }

    Column(
        modifier = modifier.width(148.dp),
    ) {
        Box(
            modifier = Modifier
                .size(148.dp, 96.dp)
                .clip(RoundedCornerShape(14.dp))
                .background(CyberObsidian.Surface)
                .border(1.dp, parseHexColor(folder.accentColorHex).copy(alpha = 0.55f), RoundedCornerShape(14.dp))
                .clickable { onClick() },
        ) {
            val bitmaps = coverBitmaps.filterNotNull()
            if (bitmaps.isEmpty()) {
                Icon(
                    imageVector = Icons.Filled.Folder,
                    contentDescription = null,
                    tint = parseHexColor(folder.accentColorHex),
                    modifier = Modifier
                        .align(Alignment.Center)
                        .size(38.dp),
                )
            } else if (bitmaps.size == 1) {
                Image(
                    painter = BitmapPainter(bitmaps[0].asImageBitmap()),
                    contentDescription = folder.name,
                    modifier = Modifier.fillMaxSize(),
                    contentScale = ContentScale.Crop,
                )
            } else {
                // Автоколлаж 2×2 из четырёх первых превью
                val gridItems = bitmaps.take(4)
                Column(modifier = Modifier.fillMaxSize()) {
                    Row(modifier = Modifier.weight(1f).fillMaxWidth()) {
                        CollageCell(gridItems.getOrNull(0), Modifier.weight(1f))
                        CollageCell(gridItems.getOrNull(1), Modifier.weight(1f))
                    }
                    Row(modifier = Modifier.weight(1f).fillMaxWidth()) {
                        CollageCell(gridItems.getOrNull(2), Modifier.weight(1f))
                        CollageCell(gridItems.getOrNull(3), Modifier.weight(1f))
                    }
                }
            }

            Box(
                modifier = Modifier
                    .align(Alignment.BottomStart)
                    .background(CyberObsidian.Abyss.copy(alpha = 0.72f), RoundedCornerShape(topEnd = 10.dp))
                    .padding(horizontal = 6.dp, vertical = 2.dp),
            ) {
                Text(
                    text = folder.iconType.labelRu,
                    style = MaterialTheme.typography.labelSmall,
                    color = parseHexColor(folder.accentColorHex),
                    fontWeight = FontWeight.SemiBold,
                )
            }

            if (folder.isPinned) {
                Box(
                    modifier = Modifier
                        .align(Alignment.TopEnd)
                        .padding(6.dp)
                        .background(CyberObsidian.Emerald.copy(alpha = 0.9f), RoundedCornerShape(6.dp))
                        .padding(horizontal = 4.dp, vertical = 1.dp),
                ) {
                    Text(
                        text = "PIN",
                        style = MaterialTheme.typography.labelSmall,
                        color = CyberObsidian.EmeraldOn,
                        fontWeight = FontWeight.Black,
                    )
                }
            }
        }

        Text(
            text = folder.name,
            modifier = Modifier
                .padding(top = 6.dp, start = 2.dp, end = 2.dp)
                .clickable { onClick() },
            style = MaterialTheme.typography.bodySmall,
            color = CyberObsidian.TextPrimary,
            fontWeight = FontWeight.Medium,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
        )
        Text(
            text = "${folderMedia.size} объектов",
            modifier = Modifier.padding(start = 2.dp),
            style = MaterialTheme.typography.labelSmall,
            color = CyberObsidian.TextMuted,
        )
    }
}

@Composable
private fun CollageCell(bitmap: Bitmap?, modifier: Modifier = Modifier) {
    Box(
        modifier = modifier
            .background(CyberObsidian.SurfaceRaised),
    ) {
        if (bitmap != null) {
            Image(
                painter = BitmapPainter(bitmap.asImageBitmap()),
                contentDescription = null,
                modifier = Modifier.fillMaxSize(),
                contentScale = ContentScale.Crop,
            )
        }
    }
}
