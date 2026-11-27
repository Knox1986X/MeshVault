package com.meshvault.app.ui

import android.graphics.Bitmap
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.gestures.detectTransformGestures
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.getValue
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.graphics.painter.BitmapPainter
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.media3.common.MediaItem as ExoMediaItem
import androidx.media3.common.util.UnstableApi
import androidx.media3.exoplayer.ExoPlayer
import androidx.media3.exoplayer.source.DefaultMediaSourceFactory
import androidx.media3.ui.PlayerView
import com.meshvault.data.media.MvchExoPlayerDataSource
import com.meshvault.domain.model.MediaItem
import com.meshvault.domain.model.MediaKind
import com.meshvault.ui.components.formatBytesCompact
import com.meshvault.app.VaultViewModel
import java.io.File
import androidx.compose.material.icons.filled.ArrowBack

/**
 * Полноэкранный просмотрщик медиа.
 * - Фото: полное разрешение из зашифрованного `.mvbin`, зум щипком до 12× (референс для рисования).
 * - Видео: MVCH v2 через Media3 ExoPlayer с побайтной расшифровкой нужного 64 КБ чанка по требованию.
 */
@Composable
fun MediaViewerScreen(
    item: MediaItem,
    viewModel: VaultViewModel,
    onClose: () -> Unit,
) {
    BackHandler(enabled = true) { onClose() }

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(Color.Black),
    ) {
        if (item.kind == MediaKind.VIDEO) {
            VideoPlayerSurface(item = item, viewModel = viewModel)
        } else {
            ZoomablePhoto(item = item, viewModel = viewModel)
        }

        // Верхняя панель: назад + имя файла
        Row(
            modifier = Modifier
                .align(Alignment.TopStart)
                .fillMaxWidth()
                .background(Color.Black.copy(alpha = 0.55f))
                .padding(horizontal = 4.dp, vertical = 6.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            IconButton(onClick = onClose) {
                Icon(
                    imageVector = androidx.compose.material.icons.Icons.Filled.ArrowBack,
                    contentDescription = "Назад",
                    tint = Color.White,
                )
            }
            Column(modifier = Modifier.weight(1f).padding(end = 8.dp)) {
                Text(
                    text = item.displayName,
                    color = Color.White,
                    fontWeight = FontWeight.SemiBold,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                Text(
                    text = buildString {
                        append(item.resolutionLabel)
                        append(" · ")
                        append(formatBytesCompact(item.plaintextSizeBytes))
                        if (item.kind == MediaKind.VIDEO && item.durationMs > 0L) {
                            append(" · ")
                            append(com.meshvault.ui.components.formatDurationFull(item.durationMs))
                        }
                    },
                    color = Color.White.copy(alpha = 0.75f),
                    maxLines = 1,
                )
            }
        }
    }
}

@Composable
private fun ZoomablePhoto(item: MediaItem, viewModel: VaultViewModel) {
    var scale by remember { mutableStateOf(1f) }
    var offset by remember { mutableStateOf(androidx.compose.ui.geometry.Offset.Zero) }

    val bitmap by produceState<Bitmap?>(initialValue = null, key1 = item.id) {
        value = viewModel.loadFullResolution(item)
    }

    Box(
        modifier = Modifier.fillMaxSize(),
        contentAlignment = Alignment.Center,
    ) {
        val bmp = bitmap
        if (bmp == null) {
            CircularProgressIndicator(color = Color(0xFF10B981))
        } else {
            Image(
                painter = BitmapPainter(bmp.asImageBitmap()),
                contentDescription = item.displayName,
                contentScale = ContentScale.Fit,
                modifier = Modifier
                    .fillMaxSize()
                    .pointerInput(item.id) {
                        detectTransformGestures { _, pan, zoom, _ ->
                            val newScale = (scale * zoom).coerceIn(1f, 12f)
                            scale = newScale
                            offset += pan
                        }
                    }
                    .pointerInput(item.id) {
                        detectTapGestures(
                            onDoubleTap = {
                                scale = 1f
                                offset = androidx.compose.ui.geometry.Offset.Zero
                            },
                        )
                    }
                    .graphicsLayer(
                        scaleX = scale,
                        scaleY = scale,
                        translationX = offset.x,
                        translationY = offset.y,
                    ),
            )
        }
    }
}
@OptIn(UnstableApi::class)
@Composable
private fun VideoPlayerSurface(item: MediaItem, viewModel: VaultViewModel) {
    val context = LocalContext.current
    val session = viewModel.currentSession()

    if (session == null) {
        LaunchedEffect(item.id) { viewModel.closeViewer() }
        return
    }

    val player = remember(item.id) {
        ExoPlayer.Builder(context).build().apply {
            val dataSourceFactory = MvchExoPlayerDataSource.Factory(session) { mediaId ->
                viewModel.resolveEncryptedBlobFile(mediaId)
                    ?: File(context.cacheDir, "meshvault-missing.mvbin")
            }
            val mediaSource = DefaultMediaSourceFactory(context)
                .setDataSourceFactory(dataSourceFactory)
                .createMediaSource(ExoMediaItem.fromUri(MvchExoPlayerDataSource.buildUri(item.id)))
            setMediaSource(mediaSource)
            playWhenReady = true
            prepare()
        }
    }

    DisposableEffect(player) {
        onDispose { player.release() }
    }

    AndroidView(
        factory = { ctx ->
            PlayerView(ctx).apply {
                this.player = player
            }
        },
        modifier = Modifier.fillMaxSize(),
    )
}

