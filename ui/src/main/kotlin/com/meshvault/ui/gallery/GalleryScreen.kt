package com.meshvault.ui.gallery

import android.graphics.Bitmap
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.background
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.grid.GridCells
import androidx.compose.foundation.lazy.grid.LazyVerticalGrid
import androidx.compose.foundation.lazy.grid.items
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.staggeredgrid.LazyVerticalStaggeredGrid
import androidx.compose.foundation.lazy.staggeredgrid.StaggeredGridCells
import androidx.compose.foundation.lazy.staggeredgrid.items as staggeredItems
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.Image
import androidx.compose.foundation.clickable
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.gestures.detectTransformGestures
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.material.icons.Icons
import com.meshvault.domain.model.BreadcrumbNode
import com.meshvault.domain.model.FolderIconType
import com.meshvault.domain.model.FolderTreeNavigator
import com.meshvault.domain.model.GalleryViewMode
import com.meshvault.domain.model.MediaItem
import com.meshvault.domain.model.MediaSmartFilter
import com.meshvault.domain.model.MediaKind
import com.meshvault.domain.model.MediaKindFilter
import com.meshvault.domain.model.OrientationFilter
import com.meshvault.domain.model.StoragePolicy
import com.meshvault.domain.model.VaultFolder
import com.meshvault.ui.components.EmptyStateBlock
import com.meshvault.ui.components.parseHexColor
import com.meshvault.ui.components.VaultImage
import com.meshvault.ui.theme.CyberObsidian
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.Locale

/** Состояние верхнего баннера дубликатов (свободная память показывается как текст). */
data class DuplicateBannerState(
    val groupCount: Int,
    val reclaimableBytes: Long,
)

private const val COLUMNS_MIN = 1
private const val COLUMNS_MAX = 5

@OptIn(ExperimentalFoundationApi::class)
@Composable
fun GalleryScreen(
    folders: List<VaultFolder>,
    media: List<MediaItem>,
    currentFolderId: String?,
    duplicateBanner: DuplicateBannerState?,
    loadThumbnail: suspend (MediaItem) -> Bitmap?,
    onNavigateToFolder: (String?) -> Unit,
    onCreateFolder: (
        name: String,
        colorHex: String,
        iconType: FolderIconType,
        policy: StoragePolicy,
        coverMediaId: String?,
        pinned: Boolean,
        parentId: String?,
    ) -> Unit,
    onEditFolder: (VaultFolder) -> Unit,
    onDeleteFolder: (folderId: String) -> Unit,
    onMediaClick: (item: MediaItem, visibleItems: List<MediaItem>) -> Unit,
    onImportRequested: () -> Unit,
    onMoveSelected: (ids: Set<String>, targetFolderId: String?) -> Unit,
    onCopySelected: (ids: Set<String>, targetFolderId: String?) -> Unit,
    onDeleteSelected: (ids: Set<String>, purgeFromCloud: Boolean) -> Unit,
    onToggleFavorites: (ids: Set<String>, favorite: Boolean) -> Unit,
    onDuplicateCleanerOpen: () -> Unit,
) {
    var viewMode by remember { mutableStateOf(GalleryViewMode.MASONRY) }
    var columns by remember { mutableStateOf(3) }
    var searchQuery by remember { mutableStateOf("") }
    var kindFilter by remember { mutableStateOf(MediaKindFilter.ALL) }
    var orientationFilter by remember { mutableStateOf(OrientationFilter.ALL) }
    var favoritesOnly by remember { mutableStateOf(false) }
    var selectedTag by remember { mutableStateOf<String?>(null) }
    var targetPaletteHex by remember { mutableStateOf<String?>(null) }

    var selectionMode by remember { mutableStateOf(false) }
    val selectedIds = remember { mutableStateMapOf<String, Boolean>() }

    var createFolderDialogVisible by remember { mutableStateOf(false) }
    var editingFolder by remember { mutableStateOf<VaultFolder?>(null) }
    var folderPickerForMove by remember { mutableStateOf(false) }
    var folderPickerForCopy by remember { mutableStateOf(false) }
    var deleteConfirmVisible by remember { mutableStateOf(false) }
    var deleteInCloudAlso by remember { mutableStateOf(true) }
    var folderMenuFor by remember { mutableStateOf<VaultFolder?>(null) }

    // ---------- Производные коллекции ----------
    val childFolders = remember(folders, currentFolderId) {
        FolderTreeNavigator.childFoldersOf(folders, currentFolderId)
    }
    val breadcrumbs = remember(folders, currentFolderId) {
        FolderTreeNavigator.buildBreadcrumbs(folders, currentFolderId)
    }

    val smartFilter = MediaSmartFilter(
        searchQuery = searchQuery,
        kindFilter = kindFilter,
        orientationFilter = orientationFilter,
        selectedTag = selectedTag,
        targetPaletteHex = targetPaletteHex,
        favoritesOnly = favoritesOnly,
    )

    val folderScopedMedia = remember(media, currentFolderId) {
        media.filter { it.folderId == currentFolderId }
    }
    val visibleMedia = remember(folderScopedMedia, smartFilter) {
        folderScopedMedia.filter { smartFilter.matches(it) }
    }
    val allTagsInView = remember(folderScopedMedia) {
        folderScopedMedia.flatMap { it.tags }.distinct().sorted()
    }

    val selectedCount = selectedIds.size

    fun exitSelectionMode() {
        selectionMode = false
        selectedIds.clear()
    }

    fun toggleSelected(id: String) {
        if (selectedIds.containsKey(id)) {
            selectedIds.remove(id)
        } else {
            selectedIds[id] = true
        }
        if (selectedIds.isEmpty()) selectionMode = false
    }

    fun visibleIdSet(): Set<String> = visibleMedia.map { it.id }.toSet()

    // ---------- Корневой контейнер ----------
    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(CyberObsidian.Abyss),
    ) {
        BreadcrumbBar(
            breadcrumbs = breadcrumbs,
            onNavigateToFolder = onNavigateToFolder,
        )
        SearchAndToolbar(
            searchQuery = searchQuery,
            onSearchQueryChange = { searchQuery = it },
            viewMode = viewMode,
            onViewModeChange = { viewMode = it },
            columns = columns,
            allTags = allTagsInView,
            selectedTag = selectedTag,
            onSelectedTagChange = { selectedTag = it },
            kindFilter = kindFilter,
            onKindFilterChange = { kindFilter = it },
            orientationFilter = orientationFilter,
            onOrientationFilterChange = { orientationFilter = it },
            favoritesOnly = favoritesOnly,
            onFavoritesOnlyChange = { favoritesOnly = it },
            targetPaletteHex = targetPaletteHex,
            onTargetPaletteChange = { targetPaletteHex = it },
            onCreateFolder = { createFolderDialogVisible = true },
            selectionMode = selectionMode,
            onToggleSelectAll = {
                if (selectedIds.size == visibleMedia.size) {
                    selectedIds.clear()
                    selectionMode = false
                } else {
                    selectionMode = true
                    visibleMedia.forEach { selectedIds[it.id] = true }
                }
            },
            onExitSelection = ::exitSelectionMode,
        )

        if (duplicateBanner != null && !selectionMode) {
            DuplicateBannerCard(
                state = duplicateBanner,
                onOpen = onDuplicateCleanerOpen,
                modifier = Modifier.padding(horizontal = 12.dp, vertical = 4.dp),
            )
        }

        // ---------- Папки (горизонтальный ряд подпапок) ----------
        if (childFolders.isNotEmpty()) {
            LazyRow(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 12.dp, vertical = 4.dp),
                horizontalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                items(childFolders, key = { it.id }) { folder ->
                    FolderCard(
                        folder = folder,
                        folderMedia = media.filter { it.folderId == folder.id },
                        loadThumbnail = loadThumbnail,
                        onOpen = { onNavigateToFolder(folder.id) },
                        onEdit = { editingFolder = folder },
                        onOpenMenu = { folderMenuFor = folder },
                    )
                }
            }
        }

        // ---------- Основной контент ----------
        Box(
            modifier = Modifier
                .fillMaxSize()
                .pointerInput(viewMode, columns) {
                    detectTransformGestures { _, _, zoom, _ ->
                        // Pinch: 1–5 колонок
                        if (zoom > 1.12f && columns > COLUMNS_MIN) {
                            columns -= 1 // разводим пальцы — крупнее сетка
                        } else if (zoom < 0.89f && columns < COLUMNS_MAX) {
                            columns += 1
                        }
                    }
                },
        ) {
            when {
                folderScopedMedia.isEmpty() && childFolders.isEmpty() -> {
                    Column(
                        modifier = Modifier
                            .fillMaxSize()
                            .verticalScroll(rememberScrollState()),
                        horizontalAlignment = Alignment.CenterHorizontally,
                    ) {
                        if (currentFolderId == null) {
                            EmptyStateBlock(
                                title = "Корень хранилища пуст",
                                subtitle = "Папки не создаются автоматически. Постройте собственную структуру как в Eagle: " +
                                    "«Фото-референсы», «Свет и тень», «Анатомия» — любая глубина вложенности.",
                                modifier = Modifier.padding(top = 72.dp),
                            )
                            Button(
                                onClick = { createFolderDialogVisible = true },
                                modifier = Modifier.padding(top = 8.dp),
                                colors = ButtonDefaults.buttonColors(
                                    containerColor = CyberObsidian.Emerald,
                                    contentColor = CyberObsidian.EmeraldOn,
                                ),
                            ) {
                                Icon(Icons.Filled.CreateNewFolder, contentDescription = null)
                                Text("Создать первую папку", modifier = Modifier.padding(start = 8.dp))
                            }
                            TextButton(
                                onClick = onImportRequested,
                                modifier = Modifier.padding(top = 4.dp),
                            ) {
                                Text("Импортировать фото и видео", color = CyberObsidian.Sky)
                            }
                        } else {
                            EmptyStateBlock(
                                title = "Папка пуста",
                                subtitle = "Импортируйте медиафайлы: оригиналы будут зашифрованы MVCH v2 " +
                                    "и попадут только в эту папку.",
                                modifier = Modifier.padding(top = 72.dp),
                            )
                            Button(
                                onClick = onImportRequested,
                                modifier = Modifier.padding(top = 8.dp),
                                colors = ButtonDefaults.buttonColors(
                                    containerColor = CyberObsidian.Emerald,
                                    contentColor = CyberObsidian.EmeraldOn,
                                ),
                            ) {
                                Icon(Icons.Filled.Add, contentDescription = null)
                                Text("Импортировать", modifier = Modifier.padding(start = 8.dp))
                            }
                        }
                    }
                }

                visibleMedia.isEmpty() -> {
                    EmptyStateBlock(
                        title = "Ничего не найдено",
                        subtitle = "Попробуйте сбросить фильтры или поисковый запрос.",
                        modifier = Modifier.padding(top = 72.dp),
                    )
                }

                viewMode == GalleryViewMode.MASONRY -> MasonryGrid(
                    items = visibleMedia,
                    columns = columns,
                    selectionMode = selectionMode,
                    selectedIds = selectedIds,
                    onToggleSelected = ::toggleSelected,
                    onEnterSelection = { selectionMode = true },
                    loadThumbnail = loadThumbnail,
                    onMediaClick = onMediaClick,
                    visibleMedia = visibleMedia,
                )

                viewMode == GalleryViewMode.SQUARE_GRID -> SquareGrid(
                    items = visibleMedia,
                    columns = columns,
                    selectionMode = selectionMode,
                    selectedIds = selectedIds,
                    onToggleSelected = ::toggleSelected,
                    onEnterSelection = { selectionMode = true },
                    loadThumbnail = loadThumbnail,
                    onMediaClick = onMediaClick,
                    visibleMedia = visibleMedia,
                )

                else -> DetailedList(
                    items = visibleMedia,
                    selectionMode = selectionMode,
                    selectedIds = selectedIds,
                    onToggleSelected = ::toggleSelected,
                    onEnterSelection = { selectionMode = true },
                    loadThumbnail = loadThumbnail,
                    onMediaClick = onMediaClick,
                    visibleMedia = visibleMedia,
                )
            }

            // ---------- Нижняя панель действий при выделении ----------
            if (selectionMode) {
                SelectionActionBar(
                    selectedCount = selectedCount,
                    onMove = { folderPickerForMove = true },
                    onCopy = { folderPickerForCopy = true },
                    onFavorite = {
                        onToggleFavorites(selectedIds.keys.toSet(), true)
                        exitSelectionMode()
                    },
                    onDelete = { deleteConfirmVisible = true },
                    onClose = ::exitSelectionMode,
                    modifier = Modifier.align(Alignment.BottomCenter),
                )
            }
        }
    }

    // ---------- Диалоги ----------
    if (createFolderDialogVisible) {
        FolderEditDialog(
            initial = null,
            onDismiss = { createFolderDialogVisible = false },
            onConfirm = { name, color, icon, policy, coverId, pinned ->
                onCreateFolder(name, color, icon, policy, coverId, pinned, currentFolderId)
                createFolderDialogVisible = false
            },
        )
    }
    editingFolder?.let { target ->
        FolderEditDialog(
            initial = target,
            onDismiss = { editingFolder = null },
            onConfirm = { name, color, icon, policy, coverId, pinned ->
                onEditFolder(target.copy(
                    name = name,
                    accentColorHex = color,
                    iconType = icon,
                    storagePolicy = policy,
                    coverMediaId = coverId,
                    isPinned = pinned,
                    updatedAtMs = System.currentTimeMillis(),
                ))
                editingFolder = null
            },
        )
    }
    folderMenuFor?.let { folder ->
        FolderContextDialog(
            folder = folder,
            onDismiss = { folderMenuFor = null },
            onTogglePin = {
                onEditFolder(folder.copy(isPinned = !folder.isPinned))
                folderMenuFor = null
            },
            onEdit = {
                editingFolder = folder
                folderMenuFor = null
            },
            onDelete = {
                onDeleteFolder(folder.id)
                folderMenuFor = null
            },
        )
    }
    if (folderPickerForMove || folderPickerForCopy) {
        FolderPickerDialog(
            folders = folders,
            title = if (folderPickerForMove) "Переместить в папку" else "Копировать в папку",
            onDismiss = {
                folderPickerForMove = false
                folderPickerForCopy = false
            },
            onPick = { targetFolderId ->
                val ids = selectedIds.keys.toSet()
                if (folderPickerForMove) onMoveSelected(ids, targetFolderId) else onCopySelected(ids, targetFolderId)
                folderPickerForMove = false
                folderPickerForCopy = false
                exitSelectionMode()
            },
        )
    }
    if (deleteConfirmVisible) {
        AlertDialog(
            onDismissRequest = { deleteConfirmVisible = false },
            confirmButton = {
                TextButton(onClick = {
                    onDeleteSelected(selectedIds.keys.toSet(), deleteInCloudAlso)
                    deleteConfirmVisible = false
                    exitSelectionMode()
                }) {
                    Text("Удалить", color = CyberObsidian.Danger)
                }
            },
            dismissButton = {
                TextButton(onClick = { deleteConfirmVisible = false }) {
                    Text("Отмена")
                }
            },
            title = { Text("Удалить выбранные объекты?") },
            text = {
                Column {
                    Text(
                        "Удаление затронет $selectedCount объектов. Зашифрованные файлы будут " +
                            "безвозвратно уничтожены вместе с ключами.",
                    )
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(top = 12.dp)
                            .clickable { deleteInCloudAlso = !deleteInCloudAlso },
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        RadioButton(
                            selected = deleteInCloudAlso,
                            onClick = { deleteInCloudAlso = !deleteInCloudAlso },
                        )
                        Text(
                            text = "Также удалить из Dropbox (атомарно по Tombstone)",
                            modifier = Modifier.padding(start = 8.dp),
                        )
                    }
                }
            },
        )
    }
}

// ============================================================
// Вспомогательные компоненты галереи
// ============================================================

@Composable
private fun BreadcrumbBar(
    breadcrumbs: List<BreadcrumbNode>,
    onNavigateToFolder: (String?) -> Unit,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(CyberObsidian.Abyss)
            .padding(horizontal = 12.dp, vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        breadcrumbs.forEachIndexed { index, node ->
            val isLast = index == breadcrumbs.lastIndex
            Text(
                text = node.title,
                modifier = Modifier
                    .clip(RoundedCornerShape(6.dp))
                    .clickable(enabled = !isLast) { onNavigateToFolder(node.folderId) }
                    .padding(horizontal = 6.dp, vertical = 4.dp),
                style = MaterialTheme.typography.labelLarge,
                color = if (isLast) CyberObsidian.TextPrimary else CyberObsidian.Sky,
                fontWeight = if (isLast) FontWeight.Bold else FontWeight.Medium,
                maxLines = 1,
            )
            if (!isLast) {
                Icon(
                    imageVector = Icons.Filled.KeyboardArrowRight,
                    contentDescription = null,
                    tint = CyberObsidian.TextMuted,
                    modifier = Modifier.size(16.dp),
                )
            }
        }
    }
}

@Composable
private fun SearchAndToolbar(
    searchQuery: String,
    onSearchQueryChange: (String) -> Unit,
    viewMode: GalleryViewMode,
    onViewModeChange: (GalleryViewMode) -> Unit,
    columns: Int,
    allTags: List<String>,
    selectedTag: String?,
    onSelectedTagChange: (String?) -> Unit,
    kindFilter: MediaKindFilter,
    onKindFilterChange: (MediaKindFilter) -> Unit,
    orientationFilter: OrientationFilter,
    onOrientationFilterChange: (OrientationFilter) -> Unit,
    favoritesOnly: Boolean,
    onFavoritesOnlyChange: (Boolean) -> Unit,
    targetPaletteHex: String?,
    onTargetPaletteChange: (String?) -> Unit,
    onCreateFolder: () -> Unit,
    selectionMode: Boolean,
    onToggleSelectAll: () -> Unit,
    onExitSelection: () -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .background(CyberObsidian.Abyss)
            .padding(horizontal = 12.dp, vertical = 2.dp),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            OutlinedTextField(
                value = searchQuery,
                onValueChange = onSearchQueryChange,
                modifier = Modifier.weight(1f),
                placeholder = { Text("Поиск по имени и тегам…") },
                singleLine = true,
                leadingIcon = {
                    Icon(Icons.Filled.Search, contentDescription = null, tint = CyberObsidian.TextSecondary)
                },
                trailingIcon = {
                    if (searchQuery.isNotEmpty()) {
                        IconButton(onClick = { onSearchQueryChange("") }) {
                            Icon(Icons.Filled.Close, contentDescription = "Очистить", tint = CyberObsidian.TextSecondary)
                        }
                    }
                },
            )

            ViewModeToggle(viewMode = viewMode, onViewModeChange = onViewModeChange)

            IconButton(onClick = onCreateFolder) {
                Icon(Icons.Filled.CreateNewFolder, contentDescription = "Новая папка", tint = CyberObsidian.Emerald)
            }

            if (selectionMode) {
                IconButton(onClick = onToggleSelectAll) {
                    Icon(Icons.Filled.SelectAll, contentDescription = "Выбрать все", tint = CyberObsidian.Sky)
                }
                IconButton(onClick = onExitSelection) {
                    Icon(Icons.Filled.Close, contentDescription = "Отменить выделение", tint = CyberObsidian.TextSecondary)
                }
            }
        }

        androidx.compose.foundation.lazy.LazyRow(
            modifier = Modifier
                .fillMaxWidth()
                .padding(top = 2.dp),
            horizontalArrangement = Arrangement.spacedBy(6.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            item {
                CyclingFilterChip(
                    label = "Тип",
                    current = kindFilter.labelRu,
                    onCycle = {
                        val values = MediaKindFilter.entries
                        val idx = values.indexOf(kindFilter)
                        onKindFilterChange(values[(idx + 1) % values.size])
                    },
                )
            }
            item {
                CyclingFilterChip(
                    label = "Ориентация",
                    current = orientationFilter.labelRu,
                    onCycle = {
                        val values = OrientationFilter.entries
                        val idx = values.indexOf(orientationFilter)
                        onOrientationFilterChange(values[(idx + 1) % values.size])
                    },
                )
            }
            item {
                FilterChip(
                    selected = favoritesOnly,
                    onClick = { onFavoritesOnlyChange(!favoritesOnly) },
                    label = { Text("Избранное") },
                    leadingIcon = {
                        Icon(
                            imageVector = if (favoritesOnly) Icons.Filled.Favorite else Icons.Filled.FavoriteBorder,
                            contentDescription = null,
                            modifier = Modifier.size(16.dp),
                            tint = if (favoritesOnly) CyberObsidian.Danger else CyberObsidian.TextSecondary,
                        )
                    },
                )
            }
            if (targetPaletteHex != null) {
                item {
                    FilterChip(
                        selected = true,
                        onClick = { onTargetPaletteChange(null) },
                        label = { Text("Цвет: $targetPaletteHex") },
                        leadingIcon = {
                            Box(
                                modifier = Modifier
                                    .size(14.dp)
                                    .clip(androidx.compose.foundation.shape.CircleShape)
                                    .background(parseHexColor(targetPaletteHex)),
                            )
                        },
                    )
                }
            } else {
                item {
                    PaletteDotPicker(onPick = onTargetPaletteChange)
                }
            }
            allTags.take(30).forEach { tag ->
                item(key = "tag_$tag") {
                    FilterChip(
                        selected = selectedTag == tag,
                        onClick = { onSelectedTagChange(if (selectedTag == tag) null else tag) },
                        label = { Text("#$tag") },
                    )
                }
            }
            if (allTags.isNotEmpty() || selectedTag != null) {
                item {
                    TextButton(onClick = { onSelectedTagChange(null) }) {
                        Text("Сбросить тег", color = CyberObsidian.TextSecondary)
                    }
                }
            }
        }
    }
}

@Composable
private fun ViewModeToggle(
    viewMode: GalleryViewMode,
    onViewModeChange: (GalleryViewMode) -> Unit,
) {
    Row(
        modifier = Modifier
            .clip(RoundedCornerShape(12.dp))
            .background(CyberObsidian.Surface),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        ModeToggleIcon(
            icon = Icons.Filled.GridView,
            label = "Masonry",
            selected = viewMode == GalleryViewMode.MASONRY,
            onClick = { onViewModeChange(GalleryViewMode.MASONRY) },
        )
        ModeToggleIcon(
            icon = Icons.Filled.ViewModule,
            label = "Квадраты",
            selected = viewMode == GalleryViewMode.SQUARE_GRID,
            onClick = { onViewModeChange(GalleryViewMode.SQUARE_GRID) },
        )
        ModeToggleIcon(
            icon = Icons.Filled.ViewList,
            label = "Список",
            selected = viewMode == GalleryViewMode.DETAILED_LIST,
            onClick = { onViewModeChange(GalleryViewMode.DETAILED_LIST) },
        )
    }
}

@Composable
private fun ModeToggleIcon(
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    label: String,
    selected: Boolean,
    onClick: () -> Unit,
) {
    IconButton(onClick = onClick) {
        Icon(
            imageVector = icon,
            contentDescription = label,
            tint = if (selected) CyberObsidian.Emerald else CyberObsidian.TextMuted,
        )
    }
}

@Composable
private fun CyclingFilterChip(
    label: String,
    current: String,
    onCycle: () -> Unit,
) {
    FilterChip(
        selected = false,
        onClick = onCycle,
        label = { Text("$label: $current") },
        leadingIcon = {
            Icon(Icons.Filled.ArrowDropDown, contentDescription = null, modifier = Modifier.size(16.dp))
        },
    )
}

@Composable
private fun PaletteDotPicker(onPick: (String) -> Unit) {
    val dots = listOf(
        "#EF4444", "#F97316", "#F59E0B", "#84CC16", "#10B981", "#14B8A6",
        "#38BDF8", "#3B82F6", "#8B5CF6", "#EC4899", "#A8A29E", "#111827",
    )
    Row(
        modifier = Modifier
            .clip(RoundedCornerShape(14.dp))
            .background(CyberObsidian.Surface)
            .padding(horizontal = 6.dp, vertical = 6.dp),
        horizontalArrangement = Arrangement.spacedBy(5.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        dots.forEach { hex ->
            Box(
                modifier = Modifier
                    .size(16.dp)
                    .clip(androidx.compose.foundation.shape.CircleShape)
                    .background(parseHexColor(hex))
                    .clickable { onPick(hex) },
            )
        }
    }
}

@Composable
private fun DuplicateBannerCard(
    state: DuplicateBannerState,
    onOpen: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Card(
        modifier = modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = CyberObsidian.SkyDim),
        shape = RoundedCornerShape(14.dp),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 12.dp, vertical = 10.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Icon(
                imageVector = Icons.Filled.Warning,
                contentDescription = null,
                tint = CyberObsidian.Sky,
            )
            Column(
                modifier = Modifier
                    .weight(1f)
                    .padding(horizontal = 10.dp),
            ) {
                Text(
                    text = "Обнаружены одинаковые фото: ${state.groupCount} групп",
                    color = CyberObsidian.TextPrimary,
                    style = MaterialTheme.typography.bodyMedium,
                    fontWeight = FontWeight.SemiBold,
                )
                Text(
                    text = "можно освободить ${com.meshvault.ui.components.formatBytesCompact(state.reclaimableBytes)} — разобрать",
                    color = CyberObsidian.TextSecondary,
                    style = MaterialTheme.typography.bodySmall,
                )
            }
            TextButton(onClick = onOpen) {
                Text("Проверить", color = CyberObsidian.Sky, fontWeight = FontWeight.Bold)
            }
        }
    }
}

@Composable
private fun FolderCard(
    folder: VaultFolder,
    folderMedia: List<MediaItem>,
    loadThumbnail: suspend (MediaItem) -> Bitmap?,
    onOpen: () -> Unit,
    onEdit: () -> Unit,
    onOpenMenu: () -> Unit,
) {
    Box {
        com.meshvault.ui.components.FolderCoverCard(
            folder = folder,
            folderMedia = folderMedia,
            loadThumbnail = loadThumbnail,
            onClick = onOpen,
            onEdit = onEdit,
        )
        IconButton(
            onClick = onOpenMenu,
            modifier = Modifier.align(Alignment.TopEnd),
        ) {
            Icon(
                imageVector = Icons.Filled.MoreVert,
                contentDescription = "Действия с папкой",
                tint = CyberObsidian.TextPrimary,
            )
        }
    }
}

@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun MediaCell(
    item: MediaItem,
    selectionMode: Boolean,
    selected: Boolean,
    onToggleSelected: (String) -> Unit,
    onEnterSelection: () -> Unit,
    loadThumbnail: suspend (MediaItem) -> Bitmap?,
    onMediaClick: (item: MediaItem) -> Unit,
    modifier: Modifier = Modifier,
    fixedSquare: Boolean = false,
) {
    val thumb by produceState<Bitmap?>(initialValue = null, key1 = item.id, key2 = item.updatedAtMs) {
        value = withContext(Dispatchers.IO) { loadThumbnail(item) }
    }

    Box(
        modifier = modifier
            .clip(RoundedCornerShape(10.dp))
            .background(CyberObsidian.Surface)
            .combinedClickable(
                onClick = {
                    if (selectionMode) onToggleSelected(item.id) else onMediaClick(item)
                },
                onLongClick = {
                    if (!selectionMode) onEnterSelection()
                    onToggleSelected(item.id)
                },
            ),
    ) {
        VaultImage(
            item = item,
            thumb = thumb,
            modifier = Modifier
                .fillMaxSize()
                .let { if (fixedSquare) it.aspectRatio(1f) else it },
            contentScale = ContentScale.Crop,
        )

        // Видео-маркер и длительность
        if (item.kind == MediaKind.VIDEO) {
            Row(
                modifier = Modifier
                    .align(Alignment.TopStart)
                    .padding(6.dp)
                    .clip(RoundedCornerShape(6.dp))
                    .background(CyberObsidian.Abyss.copy(alpha = 0.78f))
                    .padding(horizontal = 5.dp, vertical = 3.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Icon(
                    imageVector = Icons.Filled.Videocam,
                    contentDescription = "Видео",
                    tint = CyberObsidian.Sky,
                    modifier = Modifier.size(13.dp),
                )
                Text(
                    text = com.meshvault.ui.components.formatDurationShort(item.durationMs),
                    style = MaterialTheme.typography.labelSmall,
                    color = CyberObsidian.TextPrimary,
                    modifier = Modifier.padding(start = 4.dp),
                )
            }
        }

        // Слепой HMAC-индикатор синхронизации
        Box(
            modifier = Modifier
                .align(Alignment.BottomStart)
                .padding(6.dp)
                .size(10.dp)
                .clip(androidx.compose.foundation.shape.CircleShape)
                .background(
                    when (item.syncStatus) {
                        com.meshvault.domain.model.SyncItemStatus.SYNCED_DROPBOX -> CyberObsidian.Emerald
                        com.meshvault.domain.model.SyncItemStatus.QUEUED -> CyberObsidian.Amber
                        com.meshvault.domain.model.SyncItemStatus.ON_DEMAND_CLOUD -> CyberObsidian.Sky
                        com.meshvault.domain.model.SyncItemStatus.LOCAL_ONLY -> CyberObsidian.TextMuted
                    },
                ),
        )

        if (item.isFavorite) {
            Icon(
                imageVector = Icons.Filled.Favorite,
                contentDescription = null,
                tint = CyberObsidian.Danger,
                modifier = Modifier
                    .align(Alignment.BottomEnd)
                    .padding(6.dp)
                    .size(14.dp),
            )
        }

        // Оверлей выделения
        if (selectionMode) {
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .background(
                        if (selected) CyberObsidian.Emerald.copy(alpha = 0.22f)
                        else CyberObsidian.Abyss.copy(alpha = 0.38f),
                    ),
            )
            Icon(
                imageVector = if (selected) Icons.Filled.CheckCircle else Icons.Filled.Check,
                contentDescription = if (selected) "Выбрано" else "Не выбрано",
                tint = if (selected) CyberObsidian.Emerald else CyberObsidian.TextSecondary.copy(alpha = 0.6f),
                modifier = Modifier
                    .align(Alignment.TopEnd)
                    .padding(6.dp)
                    .size(26.dp),
            )
        }
    }
}

@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun MasonryGrid(
    items: List<MediaItem>,
    columns: Int,
    selectionMode: Boolean,
    selectedIds: Map<String, Boolean>,
    onToggleSelected: (String) -> Unit,
    onEnterSelection: () -> Unit,
    loadThumbnail: suspend (MediaItem) -> Bitmap?,
    onMediaClick: (MediaItem, List<MediaItem>) -> Unit,
    visibleMedia: List<MediaItem>,
) {
    LazyVerticalStaggeredGrid(
        columns = StaggeredGridCells.Fixed(columns.coerceIn(COLUMNS_MIN, COLUMNS_MAX)),
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 6.dp),
        verticalItemSpacing = 6.dp,
        horizontalArrangement = Arrangement.spacedBy(6.dp),
        contentPadding = androidx.compose.foundation.layout.PaddingValues(vertical = 6.dp),
    ) {
        staggeredItems(items, key = { it.id }) { item ->
            MediaCell(
                item = item,
                selectionMode = selectionMode,
                selected = selectedIds.containsKey(item.id),
                onToggleSelected = onToggleSelected,
                onEnterSelection = onEnterSelection,
                loadThumbnail = loadThumbnail,
                onMediaClick = { onMediaClick(item, visibleMedia) },
                modifier = Modifier
                    .fillMaxWidth()
                    .aspectRatio(item.aspectRatio),
            )
        }
    }
}

@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun SquareGrid(
    items: List<MediaItem>,
    columns: Int,
    selectionMode: Boolean,
    selectedIds: Map<String, Boolean>,
    onToggleSelected: (String) -> Unit,
    onEnterSelection: () -> Unit,
    loadThumbnail: suspend (MediaItem) -> Bitmap?,
    onMediaClick: (MediaItem, List<MediaItem>) -> Unit,
    visibleMedia: List<MediaItem>,
) {
    LazyVerticalGrid(
        columns = GridCells.Fixed(columns.coerceIn(COLUMNS_MIN, COLUMNS_MAX)),
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 6.dp),
        horizontalArrangement = Arrangement.spacedBy(6.dp),
        verticalArrangement = Arrangement.spacedBy(6.dp),
        contentPadding = androidx.compose.foundation.layout.PaddingValues(vertical = 6.dp),
    ) {
        items(items, key = { it.id }) { item ->
            MediaCell(
                item = item,
                selectionMode = selectionMode,
                selected = selectedIds.containsKey(item.id),
                onToggleSelected = onToggleSelected,
                onEnterSelection = onEnterSelection,
                loadThumbnail = loadThumbnail,
                onMediaClick = { onMediaClick(item, visibleMedia) },
                modifier = Modifier
                    .fillMaxWidth()
                    .aspectRatio(1f),
                fixedSquare = true,
            )
        }
    }
}

@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun DetailedList(
    items: List<MediaItem>,
    selectionMode: Boolean,
    selectedIds: Map<String, Boolean>,
    onToggleSelected: (String) -> Unit,
    onEnterSelection: () -> Unit,
    loadThumbnail: suspend (MediaItem) -> Bitmap?,
    onMediaClick: (MediaItem, List<MediaItem>) -> Unit,
    visibleMedia: List<MediaItem>,
) {
    androidx.compose.foundation.lazy.LazyColumn(
        modifier = Modifier.fillMaxSize(),
        verticalArrangement = Arrangement.spacedBy(8.dp),
        contentPadding = androidx.compose.foundation.layout.PaddingValues(12.dp),
    ) {
        items(items, key = { it.id }) { item ->
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = CyberObsidian.Surface),
                shape = RoundedCornerShape(14.dp),
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .combinedClickable(
                            onClick = {
                                if (selectionMode) {
                                    onToggleSelected(item.id)
                                } else {
                                    onMediaClick(item, visibleMedia)
                                }
                            },
                            onLongClick = {
                                if (!selectionMode) onEnterSelection()
                                onToggleSelected(item.id)
                            },
                        )
                        .padding(10.dp),
                    horizontalArrangement = Arrangement.spacedBy(12.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    MediaCell(
                        item = item,
                        selectionMode = selectionMode,
                        selected = selectedIds.containsKey(item.id),
                        onToggleSelected = onToggleSelected,
                        onEnterSelection = onEnterSelection,
                        loadThumbnail = loadThumbnail,
                        onMediaClick = { onMediaClick(item, visibleMedia) },
                        modifier = Modifier.size(84.dp),
                        fixedSquare = true,
                    )
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = item.displayName,
                            style = MaterialTheme.typography.bodyMedium,
                            color = CyberObsidian.TextPrimary,
                            fontWeight = FontWeight.SemiBold,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                        )
                        Text(
                            text = "${item.resolutionLabel} · ${com.meshvault.ui.components.formatBytesCompact(item.plaintextSizeBytes)} · ${item.kind.labelRu}",
                            style = MaterialTheme.typography.bodySmall,
                            color = CyberObsidian.TextSecondary,
                        )
                        if (item.tags.isNotEmpty()) {
                            Text(
                                text = item.tags.take(4).joinToString("  ") { "#$it" },
                                style = MaterialTheme.typography.labelSmall,
                                color = CyberObsidian.Sky,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                            )
                        }
                        Row(
                            modifier = Modifier.padding(top = 4.dp),
                            horizontalArrangement = Arrangement.spacedBy(3.dp),
                        ) {
                            item.dominantPaletteHex.take(5).forEach { hex ->
                                Box(
                                    modifier = Modifier
                                        .size(12.dp)
                                        .clip(androidx.compose.foundation.shape.CircleShape)
                                        .background(parseHexColor(hex)),
                                )
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun SelectionActionBar(
    selectedCount: Int,
    onMove: () -> Unit,
    onCopy: () -> Unit,
    onFavorite: () -> Unit,
    onDelete: () -> Unit,
    onClose: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Row(
        modifier = modifier
            .fillMaxWidth()
            .padding(12.dp)
            .clip(RoundedCornerShape(18.dp))
            .background(CyberObsidian.SurfaceRaised)
            .padding(horizontal = 12.dp, vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(4.dp),
    ) {
        Text(
            text = "$selectedCount выбрано",
            modifier = Modifier.weight(1f),
            color = CyberObsidian.TextPrimary,
            fontWeight = FontWeight.SemiBold,
        )
        IconButton(onClick = onMove) {
            Icon(Icons.Filled.DriveFileMove, contentDescription = "Переместить", tint = CyberObsidian.Sky)
        }
        IconButton(onClick = onCopy) {
            Icon(Icons.Filled.ContentCopy, contentDescription = "Копировать", tint = CyberObsidian.Sky)
        }
        IconButton(onClick = onFavorite) {
            Icon(Icons.Filled.Favorite, contentDescription = "В избранное", tint = CyberObsidian.Danger)
        }
        IconButton(onClick = onDelete) {
            Icon(Icons.Filled.Delete, contentDescription = "Удалить", tint = CyberObsidian.Danger)
        }
        IconButton(onClick = onClose) {
            Icon(Icons.Filled.Close, contentDescription = "Снять выделение", tint = CyberObsidian.TextSecondary)
        }
    }
}

// ============================================================
// Диалоги папок
// ============================================================

@Composable
private fun FolderEditDialog(
    initial: VaultFolder?,
    firstMediaId: String? = null,
    onDismiss: () -> Unit,
    onConfirm: (
        name: String,
        colorHex: String,
        iconType: FolderIconType,
        policy: StoragePolicy,
        coverMediaId: String?,
        pinned: Boolean,
    ) -> Unit,
) {
    var name by remember(initial?.id) { mutableStateOf(initial?.name ?: "") }
    var colorHex by remember(initial?.id) { mutableStateOf(initial?.accentColorHex ?: "#10B981") }
    var iconType by remember(initial?.id) { mutableStateOf(initial?.iconType ?: FolderIconType.FOLDER) }
    var policy by remember(initial?.id) { mutableStateOf(initial?.storagePolicy ?: StoragePolicy.ALWAYS_OFFLINE) }
    var pinned by remember(initial?.id) { mutableStateOf(initial?.isPinned ?: false) }
    var autoCollage by remember(initial?.id) { mutableStateOf(initial?.coverMediaId == null) }
    var iconMenuExpanded by remember { mutableStateOf(false) }

    val palette = listOf(
        "#10B981", "#38BDF8", "#8B5CF6", "#F59E0B", "#EF4444", "#EC4899",
        "#14B8A6", "#84CC16", "#3B82F6", "#A78BFA", "#FBBF24", "#E5E7EB",
    )

    AlertDialog(
        onDismissRequest = onDismiss,
        confirmButton = {
            TextButton(
                onClick = {
                    val clean = name.trim()
                    if (clean.isEmpty()) return@TextButton
                    val cover = when {
                        autoCollage -> null
                        initial?.coverMediaId != null -> initial.coverMediaId
                        else -> firstMediaId
                    }
                    onConfirm(clean, colorHex, iconType, policy, cover, pinned)
                },
            ) {
                Text(
                    text = if (initial == null) "Создать" else "Сохранить",
                    color = CyberObsidian.Emerald,
                    fontWeight = FontWeight.Bold,
                )
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text("Отмена") }
        },
        title = { Text(if (initial == null) "Новая папка" else "Настройки папки") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                OutlinedTextField(
                    value = name,
                    onValueChange = { name = it },
                    modifier = Modifier.fillMaxWidth(),
                    label = { Text("Название папки") },
                    singleLine = true,
                )

                Text("Цвет маркера", style = MaterialTheme.typography.labelSmall, color = CyberObsidian.TextSecondary)
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    palette.take(6).forEach { hex ->
                        PaletteDot(hex = hex, selected = colorHex == hex) { colorHex = hex }
                    }
                }
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    palette.drop(6).forEach { hex ->
                        PaletteDot(hex = hex, selected = colorHex == hex) { colorHex = hex }
                    }
                }

                Text("Иконка", style = MaterialTheme.typography.labelSmall, color = CyberObsidian.TextSecondary)
                Box {
                    OutlinedButtonIcon(
                        label = iconType.labelRu,
                        onClick = { iconMenuExpanded = true },
                    )
                    DropdownMenu(
                        expanded = iconMenuExpanded,
                        onDismissRequest = { iconMenuExpanded = false },
                    ) {
                        FolderIconType.entries.forEach { type ->
                            DropdownMenuItem(
                                text = { Text(type.labelRu) },
                                onClick = {
                                    iconType = type
                                    iconMenuExpanded = false
                                },
                                trailingIcon = {
                                    if (type == iconType) {
                                        Icon(Icons.Filled.Check, contentDescription = null, tint = CyberObsidian.Emerald)
                                    }
                                },
                            )
                        }
                    }
                }

                Text("Хранение", style = MaterialTheme.typography.labelSmall, color = CyberObsidian.TextSecondary)
                StoragePolicy.entries.forEach { option ->
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable { policy = option }
                            .padding(vertical = 2.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        RadioButton(
                            selected = policy == option,
                            onClick = { policy = option },
                        )
                        Column(modifier = Modifier.padding(start = 8.dp)) {
                            Text(option.titleRu, style = MaterialTheme.typography.bodyMedium, color = CyberObsidian.TextPrimary)
                            Text(
                                option.subtitleRu,
                                style = MaterialTheme.typography.bodySmall,
                                color = CyberObsidian.TextSecondary,
                            )
                        }
                    }
                }

                if (initial != null) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable { autoCollage = !autoCollage },
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Switch(checked = autoCollage, onCheckedChange = { autoCollage = it })
                        Column(modifier = Modifier.padding(start = 10.dp)) {
                            Text("Автоколлаж 2×2", color = CyberObsidian.TextPrimary)
                            Text(
                                "Выкл — обложкой станет первое фото в папке",
                                style = MaterialTheme.typography.bodySmall,
                                color = CyberObsidian.TextSecondary,
                            )
                        }
                    }
                }

                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clickable { pinned = !pinned },
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Switch(checked = pinned, onCheckedChange = { pinned = it })
                    Text(
                        text = "Закрепить папку сверху",
                        color = CyberObsidian.TextPrimary,
                        modifier = Modifier.padding(start = 10.dp),
                    )
                }
            }
        },
    )
}

@Composable
private fun PaletteDot(
    hex: String,
    selected: Boolean,
    onClick: () -> Unit,
) {
    Box(
        modifier = Modifier
            .size(if (selected) 30.dp else 24.dp)
            .clip(androidx.compose.foundation.shape.CircleShape)
            .background(parseHexColor(hex))
            .clickable { onClick() },
    )
}

@Composable
private fun OutlinedButtonIcon(
    label: String,
    onClick: () -> Unit,
) {
    Row(
        modifier = Modifier
            .clip(RoundedCornerShape(10.dp))
            .background(CyberObsidian.SurfaceRaised)
            .clickable { onClick() }
            .padding(horizontal = 12.dp, vertical = 9.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Icon(Icons.Filled.ArrowDropDown, contentDescription = null, tint = CyberObsidian.TextSecondary)
        Text(
            text = label,
            color = CyberObsidian.TextPrimary,
            modifier = Modifier.padding(start = 6.dp),
        )
    }
}

@Composable
private fun FolderContextDialog(
    folder: VaultFolder,
    onDismiss: () -> Unit,
    onTogglePin: () -> Unit,
    onEdit: () -> Unit,
    onDelete: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        confirmButton = {
            TextButton(onClick = onDismiss) { Text("Закрыть") }
        },
        title = { Text(folder.name) },
        text = {
            Column {
                TextButton(onClick = onTogglePin, modifier = Modifier.fillMaxWidth()) {
                    Text(
                        text = if (folder.isPinned) "Открепить папку" else "Закрепить папку",
                        modifier = Modifier.fillMaxWidth(),
                        color = CyberObsidian.Sky,
                    )
                }
                TextButton(onClick = onEdit, modifier = Modifier.fillMaxWidth()) {
                    Text(
                        text = "Изменить…",
                        modifier = Modifier.fillMaxWidth(),
                        color = CyberObsidian.TextPrimary,
                    )
                }
                TextButton(onClick = onDelete, modifier = Modifier.fillMaxWidth()) {
                    Text(
                        text = "Удалить папку и всё содержимое…",
                        modifier = Modifier.fillMaxWidth(),
                        color = CyberObsidian.Danger,
                    )
                }
            }
        },
    )
}

@Composable
private fun FolderPickerDialog(
    folders: List<VaultFolder>,
    title: String,
    onDismiss: () -> Unit,
    onPick: (String?) -> Unit,
) {
    val byId = remember(folders) { folders.associateBy { it.id } }

    fun depthOf(folder: VaultFolder): Int {
        var depth = 0
        var cursor = folder.parentId
        val visited = HashSet<String>()
        while (cursor != null && visited.add(cursor)) {
            depth += 1
            cursor = byId[cursor]?.parentId
        }
        return depth.coerceAtMost(6)
    }

    val sorted = remember(folders) {
        folders.sortedWith(compareBy({ depthOf(it) }, { it.parentId ?: "" }, { it.name.lowercase(java.util.Locale.getDefault()) }))
    }

    AlertDialog(
        onDismissRequest = onDismiss,
        confirmButton = {
            TextButton(onClick = onDismiss) { Text("Отмена") }
        },
        title = { Text(title) },
        text = {
            androidx.compose.foundation.lazy.LazyColumn(
                modifier = Modifier.heightIn(max = 420.dp),
            ) {
                item(key = "__root__") {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clip(RoundedCornerShape(10.dp))
                            .clickable { onPick(null) }
                            .padding(horizontal = 10.dp, vertical = 10.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Icon(Icons.Filled.CreateNewFolder, contentDescription = null, tint = CyberObsidian.Emerald)
                        Text(
                            text = "Корень хранилища",
                            modifier = Modifier.padding(start = 10.dp),
                            color = CyberObsidian.TextPrimary,
                        )
                    }
                }
                items(sorted, key = { it.id }) { folder ->
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clip(RoundedCornerShape(10.dp))
                            .clickable { onPick(folder.id) }
                            .padding(start = 10.dp + (depthOf(folder) * 18).dp, top = 10.dp, end = 10.dp, bottom = 10.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Box(
                            modifier = Modifier
                                .size(10.dp)
                                .clip(androidx.compose.foundation.shape.CircleShape)
                                .background(parseHexColor(folder.accentColorHex)),
                        )
                        Text(
                            text = folder.name,
                            modifier = Modifier.padding(start = 10.dp),
                            color = CyberObsidian.TextPrimary,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                        )
                    }
                }
            }
        },
    )
}
