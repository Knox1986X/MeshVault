package com.meshvault.ui.components

import android.graphics.Bitmap
import androidx.compose.foundation.background
import androidx.compose.ui.draw.clip
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.produceState
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.painter.BitmapPainter
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.meshvault.domain.media.BlurHashCodec
import com.meshvault.domain.model.MediaItem
import com.meshvault.domain.model.SyncItemStatus
import com.meshvault.ui.theme.CyberObsidian
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Мгновенный BlurHash (~0 мс) показывается первым, пока фон расшифровывает WebP-превью.
 * Никаких битмапов на флеш-памяти — только ОЗУ-кэш вызывающего модуля.
 */
@Composable
fun VaultImage(
    item: MediaItem,
    thumb: Bitmap?,
    modifier: Modifier = Modifier,
    contentScale: ContentScale = ContentScale.Crop,
) {
    Box(
        modifier = modifier
            .background(CyberObsidian.SurfaceRaised)
            .clip(RoundedCornerShape(2.dp)),
    ) {
        val blur by produceState<Bitmap?>(initialValue = null, key1 = item.blurHash) {
            value = withContext(Dispatchers.Default) {
                if (item.blurHash.isBlank()) return@withContext null
                runCatching {
                    val aspect = item.aspectRatio
                    val w = 28
                    val h = (w / aspect.coerceIn(0.3f, 3.3f)).toInt().coerceIn(12, 64)
                    val argb = BlurHashCodec.decode(item.blurHash, w, h)
                    Bitmap.createBitmap(argb.pixels, w, h, Bitmap.Config.ARGB_8888)
                }.getOrNull()
            }
        }

        val blurBmp = blur
        if (thumb == null && blurBmp != null) {
            Image(
                painter = BitmapPainter(blurBmp.asImageBitmap()),
                contentDescription = null,
                modifier = Modifier.matchParentSize(),
                contentScale = contentScale,
            )
        }
        if (thumb != null) {
            Image(
                painter = BitmapPainter(thumb.asImageBitmap()),
                contentDescription = item.displayName,
                modifier = Modifier.matchParentSize(),
                contentScale = contentScale,
            )
        }
    }
}

@Composable
fun SectionHeader(
    title: String,
    subtitle: String? = null,
    modifier: Modifier = Modifier,
) {
    Column(modifier = modifier.fillMaxWidth().padding(horizontal = 4.dp, vertical = 6.dp)) {
        Text(
            text = title.uppercase(),
            style = MaterialTheme.typography.labelSmall,
            color = CyberObsidian.Sky,
            fontWeight = FontWeight.Bold,
        )
        if (subtitle != null) {
            Text(
                text = subtitle,
                style = MaterialTheme.typography.bodySmall,
                color = CyberObsidian.TextSecondary,
                maxLines = 2,
                overflow = TextOverflow.Ellipsis,
            )
        }
    }
}

@Composable
fun SyncStatusBadge(
    status: SyncItemStatus,
    modifier: Modifier = Modifier,
) {
    val (label, tint) = when (status) {
        SyncItemStatus.LOCAL_ONLY -> "Локально" to CyberObsidian.TextSecondary
        SyncItemStatus.QUEUED -> "В очереди" to CyberObsidian.Amber
        SyncItemStatus.SYNCED_DROPBOX -> "В Dropbox" to CyberObsidian.Emerald
        SyncItemStatus.ON_DEMAND_CLOUD -> "По требованию" to CyberObsidian.Sky
    }
    Box(
        modifier = modifier
            .background(CyberObsidian.SurfaceRaised, RoundedCornerShape(4.dp))
            .padding(horizontal = 4.dp, vertical = 2.dp),
    ) {
        Text(
            text = label,
            style = MaterialTheme.typography.labelSmall,
            color = tint,
        )
    }
}

@Composable
fun EmptyStateBlock(
    title: String,
    subtitle: String,
    modifier: Modifier = Modifier,
) {
    Column(
        modifier = modifier.fillMaxWidth().padding(horizontal = 32.dp, vertical = 48.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text(
            text = title,
            style = MaterialTheme.typography.titleMedium,
            color = CyberObsidian.TextPrimary,
            fontWeight = FontWeight.SemiBold,
        )
        Text(
            text = subtitle,
            style = MaterialTheme.typography.bodyMedium,
            color = CyberObsidian.TextSecondary,
            modifier = Modifier.padding(top = 8.dp),
        )
    }
}
