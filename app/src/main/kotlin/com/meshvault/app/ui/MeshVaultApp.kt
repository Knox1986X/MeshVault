package com.meshvault.app.ui

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.view.WindowManager
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.ComponentActivity
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.getValue
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.meshvault.app.ShakeDetector
import com.meshvault.app.VaultViewModel
import com.meshvault.domain.media.ImportDuplicateStrategy
import com.meshvault.ui.gallery.GalleryScreen
import com.meshvault.ui.gallery.DuplicateBannerState
import com.meshvault.ui.onboarding.UnlockScreen
import com.meshvault.ui.theme.CyberObsidian
import androidx.compose.material.icons.filled.Settings

private const val REQUEST_SYSTEM_DELETE: Int = 7321

/**
 * Корневой composable приложения:
 * разблокированное хранилище → [GalleryScreen] + плавающие кнопки,
 * заблокированное → [UnlockScreen].
 */
@Composable
fun MeshVaultApp(
    viewModel: VaultViewModel,
    onRequestBiometricUnlock: () -> Unit,
    onRequestBiometricEnrollment: () -> Unit,
) {
    val uiState by viewModel.uiState.collectAsStateWithLifecycle()
    val context = LocalContext.current
    val activity = context as? ComponentActivity

    // FLAG_SECURE — запрет скриншотов/захвата экрана по настройке
    LaunchedEffect(uiState.settings.flagSecureEnabled) {
        (context as? Activity)?.window?.let { window ->
            if (uiState.settings.flagSecureEnabled) {
                window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
            } else {
                window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
            }
        }
    }

    // Panic Lock по встряхиванию
    val shakeDetector = remember { ShakeDetector(context) }
    DisposableEffect(uiState.unlocked, uiState.settings.shakeToPanicLockEnabled) {
        val shouldListen = uiState.unlocked && uiState.settings.shakeToPanicLockEnabled && shakeDetector.isAvailable()
        if (shouldListen) {
            shakeDetector.start { viewModel.lockVault() }
        } else {
            shakeDetector.stop()
        }
        onDispose { shakeDetector.stop() }
    }

    // Снэкбары
    val snackbarHostState = remember { SnackbarHostState() }
    LaunchedEffect(uiState.snackbarMessage) {
        val message = uiState.snackbarMessage ?: return@LaunchedEffect
        snackbarHostState.showSnackbar(message)
        viewModel.consumeSnackbar()
    }

    // Запрос системного диалога удаления оригиналов после импорта
    LaunchedEffect(uiState.pendingSystemDeleteSender) {
        val sender = uiState.pendingSystemDeleteSender ?: return@LaunchedEffect
        val act = activity
        if (act == null) {
            viewModel.consumeSystemDeleteSender()
            return@LaunchedEffect
        }
        runCatching {
            @Suppress("DEPRECATION")
            act.startIntentSenderForResult(sender, REQUEST_SYSTEM_DELETE, null, 0, 0, 0)
        }
        viewModel.consumeSystemDeleteSender()
    }

    // SAF-пикер: импорт фото/видео в зашифрованное хранилище
    val pickMediaLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenMultipleDocuments(),
    ) { uris ->
        if (uris.isNotEmpty()) {
            viewModel.onImportUrisPicked(uris)
        }
    }

    var settingsOpen by remember { mutableStateOf(false) }

    Scaffold(
        snackbarHost = { SnackbarHost(snackbarHostState) },
    ) { innerPadding ->
        Box(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding),
        ) {
            if (!uiState.unlocked) {
                UnlockScreen(
                    vaultExists = uiState.vaultExists,
                    isWorking = uiState.isWorking,
                    errorMessage = uiState.errorMessage,
                    biometricEnabled = uiState.settings.biometricUnlockEnabled,
                    onUnlock = viewModel::unlock,
                    onCreateVault = viewModel::createVault,
                    onBiometricUnlock = onRequestBiometricUnlock,
                )
            } else {
                GalleryScreen(
                    folders = uiState.folders,
                    media = uiState.media,
                    currentFolderId = uiState.currentFolderId,
                    duplicateBanner = null,
                    loadThumbnail = viewModel::loadThumbnail,
                    onNavigateToFolder = viewModel::navigateToFolder,
                    onCreateFolder = viewModel::createFolder,
                    onEditFolder = viewModel::editFolder,
                    onDeleteFolder = viewModel::deleteFolder,
                    onMediaClick = { item, _ -> viewModel.openViewer(item) },
                    onImportRequested = { pickMediaLauncher.launch(arrayOf("image/*", "video/*")) },
                    onMoveSelected = { ids, target -> viewModel.moveMedia(ids, target) },
                    onCopySelected = { ids, target -> viewModel.copyMedia(ids, target) },
                    onDeleteSelected = { ids, purgeFromCloud -> viewModel.deleteMedia(ids, purgeFromCloud) },
                    onToggleFavorites = { ids, favorite -> viewModel.toggleFavorites(ids, favorite) },
                    onDuplicateCleanerOpen = {
                        viewModel.postSnackbar("Дубликаты подсвечиваются при импорте — оригиналы не будут задвоены")
                    },
                )

                // Плавающая кнопка настроек (правый угол строки хлебных крошек)
                IconButton(
                    onClick = { settingsOpen = true },
                    modifier = Modifier
                        .align(Alignment.TopEnd)
                        .padding(end = 8.dp, top = 4.dp)
                        .size(40.dp)
                        .clip(CircleShape)
                        .background(CyberObsidian.SurfaceRaised),
                ) {
                    Icon(
                        imageVector = androidx.compose.material.icons.Icons.Filled.Settings,
                        contentDescription = "Настройки хранилища",
                        tint = CyberObsidian.Emerald,
                    )
                }
            }

            // Полноэкранный просмотрщик
            uiState.viewerMediaId?.let { viewerId ->
                val item = uiState.media.firstOrNull { it.id == viewerId }
                if (item != null) {
                    MediaViewerScreen(
                        item = item,
                        viewModel = viewModel,
                        onClose = viewModel::closeViewer,
                    )
                } else {
                    LaunchedEffect(viewerId) { viewModel.closeViewer() }
                }
            }

            // Оверлей прогресса импорта
            if (uiState.isImporting) {
                ImportProgressOverlay(progress = uiState.importProgress)
            }

            // Диалог стратегии при найденных дубликатах
            uiState.pendingDuplicateReport?.let { report ->
                DuplicateImportDialog(
                    duplicateCount = report.duplicateHits.size,
                    totalCount = report.stagedItems.size,
                    onConfirm = viewModel::confirmDuplicateImport,
                    onDismiss = viewModel::dismissDuplicateImport,
                )
            }

            // Шторка настроек
            if (settingsOpen) {
                VaultSettingsSheet(
                    uiState = uiState,
                    viewModel = viewModel,
                    onDismiss = { settingsOpen = false },
                    onRequestBiometricEnrollment = onRequestBiometricEnrollment,
                    onOpenUrl = { url ->
                        val intent = Intent(Intent.ACTION_VIEW, Uri.parse(url))
                        runCatching { context.startActivity(intent) }
                            .onFailure { viewModel.postSnackbar("Не удалось открыть браузер для авторизации Dropbox") }
                    },
                )
            }
        }
    }
}

@Composable
private fun ImportProgressOverlay(progress: Pair<Int, Int>?) {
    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(CyberObsidian.Abyss.copy(alpha = 0.72f)),
        contentAlignment = Alignment.Center,
    ) {
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            CircularProgressIndicator(color = CyberObsidian.Emerald)
            Text(
                text = if (progress != null) {
                    "Шифрование и сохранение… ${progress.first}/${progress.second}"
                } else {
                    "Анализ файлов…"
                },
                color = CyberObsidian.TextPrimary,
                style = MaterialTheme.typography.bodyMedium,
                modifier = Modifier.padding(top = 12.dp),
            )
        }
    }
}

@Composable
private fun DuplicateImportDialog(
    duplicateCount: Int,
    totalCount: Int,
    onConfirm: (strategy: ImportDuplicateStrategy, deleteSystemOriginals: Boolean) -> Unit,
    onDismiss: () -> Unit,
) {
    var deleteOriginals by remember { mutableStateOf(false) }

    Dialog(onDismissRequest = onDismiss) {
        Column(
            modifier = Modifier
                .width(340.dp)
                .clip(MaterialTheme.shapes.large)
                .background(CyberObsidian.Surface)
                .padding(20.dp),
        ) {
            Text(
                text = "Найдены дубликаты: $duplicateCount из $totalCount",
                style = MaterialTheme.typography.titleMedium,
                color = CyberObsidian.TextPrimary,
                fontWeight = FontWeight.Bold,
            )
            Text(
                text = "Слепые HMAC-отпечатки и перцептивные хэши совпали с объектами в хранилище. Выберите, как поступить:",
                style = MaterialTheme.typography.bodySmall,
                color = CyberObsidian.TextSecondary,
                modifier = Modifier.padding(top = 6.dp, bottom = 12.dp),
            )
            OutlinedButton(
                onClick = { onConfirm(ImportDuplicateStrategy.SKIP_DUPLICATES, deleteOriginals) },
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text("Пропустить дубликаты")
            }
            OutlinedButton(
                onClick = { onConfirm(ImportDuplicateStrategy.REPLACE_IF_BETTER_QUALITY, deleteOriginals) },
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(top = 8.dp),
            ) {
                Text("Заменить, если новое лучше")
            }
            OutlinedButton(
                onClick = { onConfirm(ImportDuplicateStrategy.KEEP_ALL, deleteOriginals) },
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(top = 8.dp),
            ) {
                Text("Сохранить всё (keep both)")
            }
            androidx.compose.foundation.layout.Row(
                modifier = Modifier.padding(top = 12.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                androidx.compose.material3.Checkbox(
                    checked = deleteOriginals,
                    onCheckedChange = { deleteOriginals = it },
                )
                Text(
                    text = "Удалить оригиналы из галереи после шифрования",
                    style = MaterialTheme.typography.bodySmall,
                    color = CyberObsidian.TextSecondary,
                    modifier = Modifier.padding(start = 4.dp),
                )
            }
            TextButton(
                onClick = onDismiss,
                modifier = Modifier.align(Alignment.End),
            ) {
                Text("Отмена", color = CyberObsidian.Sky)
            }
        }
    }
}
