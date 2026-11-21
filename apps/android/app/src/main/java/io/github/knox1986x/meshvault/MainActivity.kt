package io.github.knox1986x.meshvault

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.os.StatFs
import android.provider.OpenableColumns
import android.view.WindowManager
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.PickVisualMediaRequest
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Dashboard
import androidx.compose.material.icons.rounded.Folder
import androidx.compose.material.icons.rounded.Lock
import androidx.compose.material.icons.rounded.PhotoLibrary
import androidx.compose.material.icons.rounded.Search
import androidx.compose.material.icons.rounded.Shield
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationDrawerItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import io.github.knox1986x.meshvault.saf.SafTreePreview
import io.github.knox1986x.meshvault.saf.SafTreeScanner
import io.github.knox1986x.meshvault.security.DedupPolicy
import io.github.knox1986x.meshvault.security.InMemoryVaultBackend
import io.github.knox1986x.meshvault.security.KeystoreVaultWrapper
import io.github.knox1986x.meshvault.security.VaultBackend
import io.github.knox1986x.meshvault.security.VaultMediaItem
import io.github.knox1986x.meshvault.security.VaultSecurityState
import io.github.knox1986x.meshvault.ui.components.StatusPill
import io.github.knox1986x.meshvault.ui.screens.FoldersScreen
import io.github.knox1986x.meshvault.ui.screens.GalleryScreen
import io.github.knox1986x.meshvault.ui.screens.ImportPreviewDialog
import io.github.knox1986x.meshvault.ui.screens.OverviewScreen
import io.github.knox1986x.meshvault.ui.screens.SearchScreen
import io.github.knox1986x.meshvault.ui.screens.SecurityScreen
import io.github.knox1986x.meshvault.ui.screens.UnlockScreen
import io.github.knox1986x.meshvault.ui.screens.ViewerScreen
import io.github.knox1986x.meshvault.ui.theme.CockpitColors
import io.github.knox1986x.meshvault.ui.theme.MeshVaultCockpitTheme

enum class CockpitTab(val label: String, val icon: ImageVector) {
    OVERVIEW("Обзор", Icons.Rounded.Dashboard),
    GALLERY("Галерея", Icons.Rounded.PhotoLibrary),
    FOLDERS("Папки", Icons.Rounded.Folder),
    SEARCH("Поиск", Icons.Rounded.Search),
    SECURITY("Защита", Icons.Rounded.Shield),
}

class MainActivity : FragmentActivity() {

    private val backend: VaultBackend = InMemoryVaultBackend()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Enforce FLAG_SECURE: block screenshots, screen recording, and task-switcher previews.
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE,
        )

        val sharedUris = extractSharedUris(intent)

        setContent {
            MeshVaultCockpitTheme {
                MeshVaultAppRoot(
                    backend = backend,
                    initialSharedUris = sharedUris,
                )
            }
        }
    }

    private fun extractSharedUris(intent: Intent?): List<Uri> {
        if (intent == null) return emptyList()
        return when (intent.action) {
            Intent.ACTION_SEND -> listOfNotNull(intent.getParcelableExtra(Intent.EXTRA_STREAM, Uri::class.java))
            Intent.ACTION_SEND_MULTIPLE -> intent.getParcelableArrayListExtra(Intent.EXTRA_STREAM, Uri::class.java) ?: emptyList()
            else -> emptyList()
        }
    }
}

@Composable
fun MeshVaultAppRoot(
    backend: VaultBackend,
    initialSharedUris: List<Uri>,
) {
    val context = LocalContext.current
    val lifecycleOwner = LocalLifecycleOwner.current

    var selectedVaultName by remember { mutableStateOf("Личное") }
    var securityState by remember { mutableStateOf(backend.securityState) }
    var unlockError by remember { mutableStateOf<String?>(null) }
    var activeTab by remember { mutableStateOf(CockpitTab.OVERVIEW) }
    var currentFolderId by remember { mutableStateOf("") }
    var refreshTick by remember { mutableIntStateOf(0) }
    var activeMediaViewer by remember { mutableStateOf<VaultMediaItem?>(null) }
    var showImportModeChooser by remember { mutableStateOf(false) }
    var pendingSafPreview by remember { mutableStateOf<SafTreePreview?>(null) }

    val keystoreWrapper = remember(selectedVaultName) {
        KeystoreVaultWrapper(context, selectedVaultName)
    }

    // Auto-lock immediately when app moves to background.
    DisposableEffect(lifecycleOwner) {
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_STOP && securityState != VaultSecurityState.LOCKED) {
                backend.lock()
                activeMediaViewer = null
                securityState = backend.securityState
            }
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose { lifecycleOwner.lifecycle.removeObserver(observer) }
    }

    val photoPickerLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.PickMultipleVisualMedia(maxItems = 50),
    ) { uris ->
        if (uris.isNotEmpty() && securityState != VaultSecurityState.LOCKED) {
            val targetId = currentFolderId.ifEmpty { backend.rootFolderId() }
            uris.forEach { uri ->
                val fileName = queryDisplayName(context.contentResolver, uri)
                val bytes = context.contentResolver.openInputStream(uri)?.use { it.readBytes() } ?: return@forEach
                backend.importStreamItem(targetId, emptyList(), fileName, bytes, DedupPolicy.SKIP_DUPLICATE)
                bytes.fill(0)
            }
            refreshTick++
        }
    }

    val folderTreeLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocumentTree(),
    ) { treeUri ->
        if (treeUri != null && securityState != VaultSecurityState.LOCKED) {
            pendingSafPreview = SafTreeScanner.scanTree(context.contentResolver, treeUri)
        }
    }

    if (securityState == VaultSecurityState.LOCKED) {
        UnlockScreen(
            selectedVaultName = selectedVaultName,
            biometricsAvailable = keystoreWrapper.hasEnrolledSlot(),
            errorText = unlockError,
            onUnlockPassphrase = { pass ->
                if (pass.isBlank()) {
                    unlockError = "Введите мастер-пароль"
                } else if (backend.unlockWithPassphrase(pass)) {
                    unlockError = null
                    currentFolderId = backend.rootFolderId()
                    securityState = backend.securityState
                    if (initialSharedUris.isNotEmpty()) {
                        initialSharedUris.forEach { uri ->
                            val name = queryDisplayName(context.contentResolver, uri)
                            val bytes = context.contentResolver.openInputStream(uri)?.use { it.readBytes() } ?: return@forEach
                            backend.importStreamItem(currentFolderId, listOf("Поделиться"), name, bytes, DedupPolicy.SKIP_DUPLICATE)
                            bytes.fill(0)
                        }
                    }
                    refreshTick++
                } else {
                    unlockError = "Неверный мастер-пароль"
                }
            },
            onUnlockBiometric = {
                unlockError = "Подтвердите биометрию через Android Keystore TEE"
            },
            onUnlockRecoveryKit = { mnemonic ->
                if (backend.unlockWithRecoveryKit(mnemonic)) {
                    unlockError = null
                    currentFolderId = backend.rootFolderId()
                    securityState = backend.securityState
                    refreshTick++
                } else {
                    unlockError = "Неверная фраза Recovery Kit (ожидается 24 слова)"
                }
            },
            onSelectVaultName = {
                selectedVaultName = it
                unlockError = null
            },
        )
        return
    }

    val viewerMedia = activeMediaViewer
    if (viewerMedia != null) {
        ViewerScreen(
            media = viewerMedia,
            safePresentationActive = securityState == VaultSecurityState.UNLOCKED_SAFE_PRESENTATION,
            loadFullBytes = { backend.readMediaAllBytes(it) },
            onToggleFavorite = {
                backend.toggleFavorite(it)
                refreshTick++
            },
            onClose = { activeMediaViewer = null },
        )
        return
    }

    val metrics = remember(refreshTick) { backend.vaultMetrics() }
    val timeline = remember(refreshTick) { backend.listAllMediaTimeline() }
    val folderId = currentFolderId.ifEmpty { backend.rootFolderId() }
    val breadcrumbs = remember(refreshTick, folderId) { backend.getBreadcrumbs(folderId) }
    val contents = remember(refreshTick, folderId) { backend.listFolderContents(folderId) }
    val pinnedFolders = remember(refreshTick) {
        backend.listFolderContents(backend.rootFolderId()).subfolders.filter { it.pinned }
    }

    BoxWithConstraints(
        modifier = Modifier
            .fillMaxSize()
            .background(CockpitColors.Background),
    ) {
        val useSidebar = maxWidth >= 600.dp

        Row(modifier = Modifier.fillMaxSize()) {
            if (useSidebar) {
                Column(
                    modifier = Modifier
                        .width(260.dp)
                        .fillMaxHeight()
                        .background(CockpitColors.NavSurface)
                        .padding(14.dp),
                    verticalArrangement = Arrangement.spacedBy(6.dp),
                ) {
                    Text(
                        text = "MeshVault",
                        color = CockpitColors.TextPrimary,
                        fontSize = 18.sp,
                        fontWeight = FontWeight.Bold,
                    )
                    Text(
                        text = "Сейф: $selectedVaultName",
                        color = CockpitColors.TextSecondary,
                        fontFamily = FontFamily.Monospace,
                        fontSize = 11.sp,
                    )
                    Spacer(modifier = Modifier.height(10.dp))
                    CockpitTab.entries.forEach { tab ->
                        NavigationDrawerItem(
                            selected = activeTab == tab,
                            onClick = { activeTab = tab },
                            icon = { Icon(tab.icon, contentDescription = tab.label) },
                            label = { Text(tab.label) },
                        )
                    }
                }
            }

            Scaffold(
                modifier = Modifier.weight(1f),
                containerColor = CockpitColors.Background,
                topBar = {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .background(CockpitColors.NavSurface)
                            .padding(horizontal = 14.dp, vertical = 10.dp),
                    ) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.SpaceBetween,
                        ) {
                            Column {
                                Text(
                                    text = "$selectedVaultName · ${activeTab.label}",
                                    color = CockpitColors.TextPrimary,
                                    fontSize = 16.sp,
                                    fontWeight = FontWeight.SemiBold,
                                )
                            }
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                IconButton(onClick = { activeTab = CockpitTab.SEARCH }) {
                                    Icon(Icons.Rounded.Search, contentDescription = "Поиск", tint = CockpitColors.TextPrimary)
                                }
                                IconButton(
                                    onClick = {
                                        backend.lock()
                                        securityState = backend.securityState
                                    },
                                ) {
                                    Icon(Icons.Rounded.Lock, contentDescription = "Заблокировать", tint = CockpitColors.Red)
                                }
                            }
                        }
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .horizontalScroll(rememberScrollState()),
                            horizontalArrangement = Arrangement.spacedBy(8.dp),
                        ) {
                            StatusPill(label = "AEAD: XChaCha20", dotColor = CockpitColors.Emerald)
                            StatusPill(label = "Screen: FLAG_SECURE", dotColor = CockpitColors.AccentVioletLight)
                            StatusPill(label = "Sync: Local Only", dotColor = CockpitColors.Amber)
                        }
                    }
                },
                bottomBar = {
                    if (!useSidebar) {
                        NavigationBar(containerColor = CockpitColors.NavSurface) {
                            CockpitTab.entries.forEach { tab ->
                                NavigationBarItem(
                                    selected = activeTab == tab,
                                    onClick = { activeTab = tab },
                                    icon = { Icon(tab.icon, contentDescription = tab.label) },
                                    label = { Text(tab.label, fontSize = 10.sp) },
                                )
                            }
                        }
                    }
                },
            ) { paddingValues ->
                Box(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(paddingValues),
                ) {
                    when (activeTab) {
                        CockpitTab.OVERVIEW -> OverviewScreen(
                            metrics = metrics,
                            pinnedFolders = pinnedFolders,
                            pipelineThroughputMb = listOf(0f, 12f, 48f, 64f, 22f, 0f),
                            workerLoadSamples = listOf(0.1f, 0.35f, 0.7f, 0.8f, 0.4f, 0.1f),
                            onOpenImportMenu = { showImportModeChooser = true },
                            onOpenFolder = {
                                currentFolderId = it.id
                                activeTab = CockpitTab.FOLDERS
                            },
                        )

                        CockpitTab.GALLERY -> GalleryScreen(
                            timeline = timeline,
                            loadThumbBytes = { backend.readThumbnailBytes(it) },
                            onOpenMedia = { activeMediaViewer = it },
                        )

                        CockpitTab.FOLDERS -> FoldersScreen(
                            breadcrumbs = breadcrumbs,
                            contents = contents,
                            onNavigateFolder = { currentFolderId = it },
                            onCreateSubfolder = { name ->
                                backend.createFolder(folderId, name)
                                refreshTick++
                            },
                            onOpenImportMenu = { showImportModeChooser = true },
                            onOpenMedia = { activeMediaViewer = it },
                        )

                        CockpitTab.SEARCH -> SearchScreen(
                            allMedia = timeline,
                            onOpenMedia = { activeMediaViewer = it },
                        )

                        CockpitTab.SECURITY -> SecurityScreen(
                            biometricEnrolled = keystoreWrapper.hasEnrolledSlot(),
                            onRunScrub = { backend.scrubVault() },
                            onGenerateRecoveryKit = { backend.generateRecoveryKit() },
                            onEnterSafePresentation = {
                                val first = timeline.firstOrNull()
                                if (first != null) {
                                    backend.enterSafePresentation(setOf(first.id))
                                    securityState = backend.securityState
                                    activeMediaViewer = first
                                }
                            },
                            onLockNow = {
                                backend.lock()
                                securityState = backend.securityState
                            },
                        )
                    }
                }
            }
        }
    }

    if (showImportModeChooser) {
        AlertDialog(
            onDismissRequest = { showImportModeChooser = false },
            containerColor = CockpitColors.CardSurface,
            title = { Text("Выберите режим импорта", color = CockpitColors.TextPrimary) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    TextButton(
                        onClick = {
                            showImportModeChooser = false
                            photoPickerLauncher.launch(
                                PickVisualMediaRequest(ActivityResultContracts.PickVisualMedia.ImageAndVideo),
                            )
                        },
                    ) {
                        Text("Фото и видео (Android Photo Picker)")
                    }
                    TextButton(
                        onClick = {
                            showImportModeChooser = false
                            folderTreeLauncher.launch(null)
                        },
                    ) {
                        Text("Импорт папки с подпапками (SAF DocumentsContract)")
                    }
                }
            },
            confirmButton = {
                TextButton(onClick = { showImportModeChooser = false }) {
                    Text("Закрыть")
                }
            },
        )
    }

    pendingSafPreview?.let { preview ->
        val stat = StatFs(context.filesDir.absolutePath)
        val freeBytes = stat.availableBytes
        ImportPreviewDialog(
            preview = preview,
            freeDeviceBytes = freeBytes,
            onConfirmImport = { selectedBranches ->
                val targetId = currentFolderId.ifEmpty { backend.rootFolderId() }
                preview.files.forEach { file ->
                    val branchKey = file.relativeFolderSegments.joinToString("/")
                    if (selectedBranches.contains(branchKey)) {
                        val bytes = context.contentResolver.openInputStream(file.documentUri)?.use { it.readBytes() }
                        if (bytes != null && bytes.isNotEmpty()) {
                            backend.importStreamItem(
                                targetParentId = targetId,
                                relativeSegments = file.relativeFolderSegments,
                                fileName = file.fileName,
                                bytes = bytes,
                                policy = DedupPolicy.SKIP_DUPLICATE,
                            )
                            bytes.fill(0)
                        }
                    }
                }
                pendingSafPreview = null
                refreshTick++
            },
            onDismiss = { pendingSafPreview = null },
        )
    }
}

private fun queryDisplayName(resolver: android.content.ContentResolver, uri: Uri): String {
    resolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { c ->
        if (c.moveToFirst()) {
            return c.getString(0) ?: "media_item"
        }
    }
    return uri.lastPathSegment ?: "media_item"
}
