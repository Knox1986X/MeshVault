package com.meshvault.domain.model

import com.meshvault.domain.media.ColorInspector
import kotlinx.serialization.Serializable

@Serializable
enum class StoragePolicy(val titleRu: String, val subtitleRu: String) {
    ALWAYS_OFFLINE(
        titleRu = "Всегда офлайн",
        subtitleRu = "Зашифрованные оригиналы и миниатюры постоянно хранятся на устройстве",
    ),
    ON_DEMAND_SPACE_SAVER(
        titleRu = "Экономия места (On-Demand)",
        subtitleRu = "Локально только превью WebP и BlurHash (~20 КБ), оригинал подгружается из Dropbox по тапу",
    ),
}

@Serializable
enum class FolderIconType(val labelRu: String) {
    FOLDER("Папка"),
    PORTRAIT("Модели и позы"),
    LIGHTING("Свет и тень"),
    ANATOMY("Анатомия"),
    ARCHITECTURE("Окружение"),
    TEXTURE("Материалы и текстуры"),
    MOTION("Референсы движения"),
    ARCHIVE("Архив"),
}

@Serializable
data class VaultFolder(
    val id: String,
    val parentId: String? = null,
    val name: String,
    val accentColorHex: String = "#10B981",
    val iconType: FolderIconType = FolderIconType.FOLDER,
    val coverMediaId: String? = null, // null -> автоколлаж из 4 миниатюр внутри папки
    val isPinned: Boolean = false,
    val storagePolicy: StoragePolicy = StoragePolicy.ALWAYS_OFFLINE,
    val createdAtMs: Long,
    val updatedAtMs: Long,
)

data class BreadcrumbNode(
    val folderId: String?, // null = корень «Хранилище»
    val title: String,
)

object FolderTreeNavigator {
    const val ROOT_TITLE_RU = "Хранилище"

    /**
     * Строит хлебные крошки вида: Хранилище › Фото-референсы › Фото моделей.
     * Защищено от циклических ссылок при слиянии повреждённых деревьев.
     */
    fun buildBreadcrumbs(allFolders: List<VaultFolder>, currentFolderId: String?): List<BreadcrumbNode> {
        val rootNode = BreadcrumbNode(folderId = null, title = ROOT_TITLE_RU)
        if (currentFolderId == null) return listOf(rootNode)

        val byId = allFolders.associateBy { it.id }
        val chain = ArrayDeque<BreadcrumbNode>()
        val visited = hashSetOf<String>()
        var cursorId: String? = currentFolderId

        while (cursorId != null && visited.add(cursorId)) {
            val folder = byId[cursorId] ?: break
            chain.addFirst(BreadcrumbNode(folderId = folder.id, title = folder.name))
            cursorId = folder.parentId
        }
        chain.addFirst(rootNode)
        return chain.toList()
    }

    fun childFoldersOf(allFolders: List<VaultFolder>, parentId: String?): List<VaultFolder> =
        allFolders
            .filter { it.parentId == parentId }
            .sortedWith(compareByDescending<VaultFolder> { it.isPinned }.thenBy { it.name.lowercase() })

    fun descendantFolderIdsInclusive(allFolders: List<VaultFolder>, rootFolderId: String): Set<String> {
        val childrenByParent = allFolders.groupBy { it.parentId }
        val result = linkedSetOf<String>()
        val queue = ArrayDeque<String>()
        queue.add(rootFolderId)
        while (queue.isNotEmpty()) {
            val current = queue.removeFirst()
            if (result.add(current)) {
                childrenByParent[current].orEmpty().forEach { queue.add(it.id) }
            }
        }
        return result
    }

    fun fullPathLabel(allFolders: List<VaultFolder>, folderId: String?): String =
        buildBreadcrumbs(allFolders, folderId).joinToString(" › ") { it.title }
}

@Serializable
enum class MediaKind(val labelRu: String) {
    PHOTO("Фото"),
    VIDEO("Видео"),
}

@Serializable
enum class MediaOrientation(val labelRu: String) {
    PORTRAIT("Портрет"),
    LANDSCAPE("Пейзаж"),
    SQUARE("Квадрат"),
}

@Serializable
enum class SyncItemStatus(val labelRu: String) {
    LOCAL_ONLY("Локально"),
    QUEUED("В очереди"),
    SYNCED_DROPBOX("В Dropbox"),
    ON_DEMAND_CLOUD("Облако (On-Demand)"),
}

@Serializable
data class MediaItem(
    val id: String,
    val folderId: String? = null,
    val displayName: String,
    val mimeType: String,
    val kind: MediaKind,
    val width: Int,
    val height: Int,
    val durationMs: Long = 0L,
    val plaintextSizeBytes: Long,
    val encryptedSizeBytes: Long,
    val blurHash: String,
    val dominantPaletteHex: List<String>,
    val cryptoBlake3BlindHex: String,
    val dHash64: Long,
    val pHash64: Long,
    val tags: List<String> = emptyList(),
    val isFavorite: Boolean = false,
    val syncStatus: SyncItemStatus = SyncItemStatus.LOCAL_ONLY,
    val localBlobPresent: Boolean = true,
    val lastAccessedAtMs: Long = 0L,
    val createdAtMs: Long,
    val updatedAtMs: Long,
) {
    val aspectRatio: Float
        get() = if (width > 0 && height > 0) {
            (width.toFloat() / height.toFloat()).coerceIn(0.25f, 4.0f)
        } else {
            1.0f
        }

    val orientation: MediaOrientation
        get() = when {
            width <= 0 || height <= 0 -> MediaOrientation.SQUARE
            kotlin.math.abs(width - height).toFloat() / maxOf(width, height).toFloat() <= 0.06f -> MediaOrientation.SQUARE
            height > width -> MediaOrientation.PORTRAIT
            else -> MediaOrientation.LANDSCAPE
        }

    val resolutionLabel: String
        get() = "${width}×${height}"
}

enum class GalleryViewMode(val labelRu: String) {
    MASONRY("Masonry"),
    SQUARE_GRID("Квадраты"),
    DETAILED_LIST("Список"),
}

enum class MediaKindFilter(val labelRu: String) {
    ALL("Все"),
    PHOTOS("Фото"),
    VIDEOS("Видео"),
}

enum class OrientationFilter(val labelRu: String) {
    ALL("Любая"),
    PORTRAIT("Портрет"),
    LANDSCAPE("Пейзаж"),
    SQUARE("Квадрат"),
}

data class MediaSmartFilter(
    val searchQuery: String = "",
    val kindFilter: MediaKindFilter = MediaKindFilter.ALL,
    val orientationFilter: OrientationFilter = OrientationFilter.ALL,
    val selectedTag: String? = null,
    val targetPaletteHex: String? = null,
    val colorToleranceDeltaE: Double = 28.0,
    val favoritesOnly: Boolean = false,
) {
    val isActive: Boolean
        get() = searchQuery.isNotBlank() ||
            kindFilter != MediaKindFilter.ALL ||
            orientationFilter != OrientationFilter.ALL ||
            selectedTag != null ||
            targetPaletteHex != null ||
            favoritesOnly

    fun matches(item: MediaItem): Boolean {
        if (favoritesOnly && !item.isFavorite) return false
        when (kindFilter) {
            MediaKindFilter.PHOTOS -> if (item.kind != MediaKind.PHOTO) return false
            MediaKindFilter.VIDEOS -> if (item.kind != MediaKind.VIDEO) return false
            MediaKindFilter.ALL -> Unit
        }
        when (orientationFilter) {
            OrientationFilter.PORTRAIT -> if (item.orientation != MediaOrientation.PORTRAIT) return false
            OrientationFilter.LANDSCAPE -> if (item.orientation != MediaOrientation.LANDSCAPE) return false
            OrientationFilter.SQUARE -> if (item.orientation != MediaOrientation.SQUARE) return false
            OrientationFilter.ALL -> Unit
        }
        if (selectedTag != null && item.tags.none { it.equals(selectedTag, ignoreCase = true) }) {
            return false
        }
        if (searchQuery.isNotBlank()) {
            val q = searchQuery.trim().lowercase()
            val nameMatch = item.displayName.lowercase().contains(q)
            val tagMatch = item.tags.any { it.lowercase().contains(q) }
            if (!nameMatch && !tagMatch) return false
        }
        if (targetPaletteHex != null) {
            val targetArgb = ColorInspector.parseHexColorOrNull(targetPaletteHex) ?: return false
            val matchesPalette = item.dominantPaletteHex.any { swatchHex ->
                val swatchArgb = ColorInspector.parseHexColorOrNull(swatchHex) ?: return@any false
                ColorInspector.cieLabDeltaE(targetArgb, swatchArgb) <= colorToleranceDeltaE
            }
            if (!matchesPalette) return false
        }
        return true
    }
}

enum class CompareLayoutMode(val labelRu: String, val paneCount: Int) {
    SINGLE("Одиночный холст", 1),
    SPLIT_HORIZONTAL("Сравнение 2× рядом", 2),
    SPLIT_VERTICAL("Сравнение 2× сверху/снизу", 2),
    QUAD_GRID("Сравнение 4× сетка", 4),
}

enum class CompositionGridType(val labelRu: String) {
    NONE("Без сетки"),
    RULE_OF_THIRDS("Правило третей"),
    GOLDEN_RATIO("Золотое сечение"),
    DIAGONALS("Диагонали"),
    CUSTOM_SQUARES("Клетка срисовки"),
}

enum class SketchTimerInterval(val seconds: Int, val labelRu: String) {
    SEC_30(30, "30 сек"),
    MIN_1(60, "1 мин"),
    MIN_2(120, "2 мин"),
    MIN_5(300, "5 мин"),
    MIN_10(600, "10 мин"),
}
