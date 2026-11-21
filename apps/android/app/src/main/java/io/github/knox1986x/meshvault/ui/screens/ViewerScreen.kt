package io.github.knox1986x.meshvault.ui.screens

import android.graphics.BitmapFactory
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.gestures.detectTransformGestures
import androidx.compose.foundation.gestures.detectVerticalDragGestures
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.ArrowBack
import androidx.compose.material.icons.rounded.DeleteOutline
import androidx.compose.material.icons.rounded.Favorite
import androidx.compose.material.icons.rounded.FavoriteBorder
import androidx.compose.material.icons.rounded.Lock
import androidx.compose.material.icons.rounded.Share
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import io.github.knox1986x.meshvault.security.VaultMediaItem
import io.github.knox1986x.meshvault.ui.components.StatusPill
import io.github.knox1986x.meshvault.ui.components.formatBytesCompact
import io.github.knox1986x.meshvault.ui.theme.CockpitColors

/**
 * In-memory image viewer with double-tap zoom, pinch zoom, swipe-to-dismiss,
 * Clean Export (EXIF/GPS strip), Trash move, and Safe Presentation re-auth unlock.
 */
@Composable
fun ViewerScreen(
    media: VaultMediaItem,
    safePresentationActive: Boolean,
    loadFullBytes: (String) -> ByteArray,
    onToggleFavorite: (String) -> Unit,
    onCleanExport: (String) -> Unit,
    onMoveToTrash: (String) -> Unit,
    onUnlockSafePresentation: (String) -> Boolean,
    onClose: () -> Unit,
) {
    var scale by remember { mutableFloatStateOf(1f) }
    var offsetX by remember { mutableFloatStateOf(0f) }
    var offsetY by remember { mutableFloatStateOf(0f) }
    var dismissDragY by remember { mutableFloatStateOf(0f) }
    var favorite by remember(media.id) { mutableStateOf(media.favorite) }
    var showUnlockDialog by remember { mutableStateOf(false) }
    var unlockInput by remember { mutableStateOf("") }
    var unlockErr by remember { mutableStateOf<String?>(null) }

    val imageBitmap = remember(media.id) {
        val raw = loadFullBytes(media.id)
        if (raw.isNotEmpty()) {
            val bmp = BitmapFactory.decodeByteArray(raw, 0, raw.size)?.asImageBitmap()
            raw.fill(0)
            bmp
        } else {
            null
        }
    }

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(Color.Black)
            .pointerInput(media.id) {
                detectTransformGestures { _, pan, zoom, _ ->
                    val nextScale = (scale * zoom).coerceIn(1f, 6f)
                    scale = nextScale
                    if (nextScale > 1f) {
                        offsetX += pan.x
                        offsetY += pan.y
                    } else {
                        offsetX = 0f
                        offsetY = 0f
                    }
                }
            }
            .pointerInput(media.id, safePresentationActive) {
                if (!safePresentationActive) {
                    detectVerticalDragGestures(
                        onDragEnd = {
                            if (scale <= 1.05f && kotlin.math.abs(dismissDragY) > 140f) {
                                onClose()
                            }
                            dismissDragY = 0f
                        },
                        onVerticalDrag = { _, dragAmount ->
                            if (scale <= 1.05f) {
                                dismissDragY += dragAmount
                            }
                        },
                    )
                }
            }
            .pointerInput(media.id) {
                detectTapGestures(
                    onDoubleTap = {
                        if (scale > 1.2f) {
                            scale = 1f
                            offsetX = 0f
                            offsetY = 0f
                        } else {
                            scale = 2.6f
                        }
                    },
                )
            },
    ) {
        if (imageBitmap != null) {
            Image(
                bitmap = imageBitmap,
                contentDescription = media.originalName,
                contentScale = ContentScale.Fit,
                modifier = Modifier
                    .fillMaxSize()
                    .graphicsLayer(
                        scaleX = scale,
                        scaleY = scale,
                        translationX = offsetX,
                        translationY = offsetY + dismissDragY,
                    ),
            )
        } else {
            Column(
                modifier = Modifier.align(Alignment.Center),
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                Icon(
                    imageVector = Icons.Rounded.Lock,
                    contentDescription = null,
                    tint = CockpitColors.AccentVioletLight,
                )
                Text(
                    text = "${media.originalName} (${formatBytesCompact(media.plaintextSize)})",
                    color = CockpitColors.TextPrimary,
                    fontFamily = FontFamily.Monospace,
                    fontSize = 13.sp,
                    modifier = Modifier.padding(top = 8.dp),
                )
            }
        }

        Row(
            modifier = Modifier
                .fillMaxWidth()
                .align(Alignment.TopCenter)
                .background(Color.Black.copy(alpha = 0.55f))
                .padding(horizontal = 8.dp, vertical = 10.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            if (!safePresentationActive) {
                IconButton(onClick = onClose) {
                    Icon(
                        imageVector = Icons.AutoMirrored.Rounded.ArrowBack,
                        contentDescription = "Назад",
                        tint = Color.White,
                    )
                }
            } else {
                TextButton(onClick = { showUnlockDialog = true }) {
                    StatusPill(
                        label = "Safe Presentation (Выход)",
                        dotColor = CockpitColors.Amber,
                    )
                }
            }

            Column(modifier = Modifier.weight(1f).padding(horizontal = 8.dp)) {
                Text(
                    text = media.originalName,
                    color = Color.White,
                    fontSize = 14.sp,
                    maxLines = 1,
                )
                val details = listOfNotNull(
                    media.exifCamera,
                    formatBytesCompact(media.plaintextSize),
                ).joinToString(" · ")
                Text(
                    text = details,
                    color = CockpitColors.TextSecondary,
                    fontFamily = FontFamily.Monospace,
                    fontSize = 11.sp,
                    maxLines = 1,
                )
            }

            if (!safePresentationActive) {
                Row {
                    IconButton(onClick = { onCleanExport(media.id) }) {
                        Icon(
                            imageVector = Icons.Rounded.Share,
                            contentDescription = "Чистый экспорт без EXIF",
                            tint = CockpitColors.Cyan,
                        )
                    }
                    IconButton(
                        onClick = {
                            onMoveToTrash(media.id)
                            onClose()
                        },
                    ) {
                        Icon(
                            imageVector = Icons.Rounded.DeleteOutline,
                            contentDescription = "В корзину",
                            tint = CockpitColors.TextSecondary,
                        )
                    }
                    IconButton(
                        onClick = {
                            favorite = !favorite
                            onToggleFavorite(media.id)
                        },
                    ) {
                        Icon(
                            imageVector = if (favorite) Icons.Rounded.Favorite else Icons.Rounded.FavoriteBorder,
                            contentDescription = "Избранное",
                            tint = if (favorite) CockpitColors.Red else Color.White,
                        )
                    }
                }
            }
        }
    }

    if (showUnlockDialog) {
        AlertDialog(
            onDismissRequest = { showUnlockDialog = false },
            containerColor = CockpitColors.CardSurface,
            title = { Text("Выход из Safe Presentation", color = CockpitColors.TextPrimary) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(
                        text = "Подтвердите мастер-пароль, чтобы вернуться к папкам и полному сейфу.",
                        color = CockpitColors.TextSecondary,
                        fontSize = 12.sp,
                    )
                    OutlinedTextField(
                        value = unlockInput,
                        onValueChange = { unlockInput = it },
                        singleLine = true,
                        visualTransformation = PasswordVisualTransformation(),
                        keyboardOptions = KeyboardOptions(
                            keyboardType = KeyboardType.Password,
                            autoCorrectEnabled = false,
                        ),
                        label = { Text("Мастер-пароль") },
                    )
                    unlockErr?.let { Text(it, color = CockpitColors.Red, fontSize = 11.sp) }
                }
            },
            confirmButton = {
                Button(
                    shape = RoundedCornerShape(8.dp),
                    onClick = {
                        if (onUnlockSafePresentation(unlockInput)) {
                            unlockInput = ""
                            unlockErr = null
                            showUnlockDialog = false
                            onClose()
                        } else {
                            unlockErr = "Неверный мастер-пароль"
                        }
                    },
                ) {
                    Text("Подтвердить")
                }
            },
            dismissButton = {
                TextButton(onClick = { showUnlockDialog = false }) {
                    Text("Отмена")
                }
            },
        )
    }
}
