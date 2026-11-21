package io.github.knox1986x.meshvault.security

import java.util.UUID

enum class VaultSecurityState {
    LOCKED,
    UNLOCKING_BIOMETRIC,
    UNLOCKING_PASSPHRASE,
    UNLOCKED_FULL,
    UNLOCKED_SAFE_PRESENTATION,
    UNLOCKED_DECOY,
    LOCKING_ZEROIZE,
}

enum class MediaCategory {
    PHOTO,
    VIDEO,
    RAW_PHOTO,
    DOCUMENT_PDF,
    ANIMATION,
    AUDIO_NOTE,
    MARKDOWN_NOTE,
}

enum class DedupPolicy {
    SKIP_DUPLICATE,
    LINK_INTO_TARGET_FOLDER,
    KEEP_INDEPENDENT_COPY,
}

data class VaultFolderItem(
    val id: String,
    val parentId: String?,
    val name: String,
    val blurShield: Boolean = false,
    val pinned: Boolean = false,
    val subfolderCount: Long = 0,
    val mediaCount: Long = 0,
    val totalBytes: Long = 0,
    val createdAtUnixMs: Long = 0,
)

data class VaultMediaItem(
    val id: String,
    val folderId: String,
    val originalName: String,
    val mimeType: String,
    val category: MediaCategory,
    val plaintextSize: Long,
    val width: Int? = null,
    val height: Int? = null,
    val exifCamera: String? = null,
    val microThumbBytes: ByteArray? = null,
    val favorite: Boolean = false,
    val tags: List<String> = emptyList(),
    val capturedAtUnixMs: Long? = null,
    val importedAtUnixMs: Long = 0,
)

data class VaultMetricsSnapshot(
    val vaultId: String,
    val headerRevision: Long,
    val folderCount: Long,
    val totalMedia: Long,
    val totalBytes: Long,
    val photoCount: Long,
    val photoBytes: Long,
    val videoCount: Long,
    val videoBytes: Long,
    val rawCount: Long,
    val rawBytes: Long,
    val docCount: Long,
    val docBytes: Long,
    val thumbPackBytes: Long,
    val trashedCount: Long,
)

data class FolderContentsSnapshot(
    val folderId: String,
    val subfolders: List<VaultFolderItem>,
    val media: List<VaultMediaItem>,
)

data class ScrubSummary(
    val checkedBlobs: Long,
    val checkedChunks: Long,
    val verifiedBytes: Long,
    val corruptedCount: Long,
    val missingCount: Long,
)

/**
 * Abstraction over the Rust UniFFI MeshVaultSession so UI and JVM unit tests remain decoupled
 * from native JNI loading during host-side tests.
 */
interface VaultBackend {
    val securityState: VaultSecurityState
    fun createVault(vaultName: String, passphrase: String)
    fun unlockWithPassphrase(passphrase: String): Boolean
    fun unlockWithRecoveryKit(mnemonic: String): Boolean
    fun lock()
    fun rootFolderId(): String
    fun listFolderContents(folderId: String): FolderContentsSnapshot
    fun getBreadcrumbs(folderId: String): List<VaultFolderItem>
    fun listAllMediaTimeline(): List<VaultMediaItem>
    fun vaultMetrics(): VaultMetricsSnapshot
    fun createFolder(parentFolderId: String, name: String): String
    fun setFolderPinned(folderId: String, pinned: Boolean)
    fun setFolderBlurShield(folderId: String, blurShield: Boolean)
    fun toggleFavorite(mediaId: String): Boolean
    fun importStreamItem(
        targetParentId: String,
        relativeSegments: List<String>,
        fileName: String,
        bytes: ByteArray,
        policy: DedupPolicy,
    ): String
    fun readMediaChunk(mediaId: String, chunkIndex: Long): ByteArray
    fun readMediaAllBytes(mediaId: String): ByteArray
    fun readThumbnailBytes(mediaId: String): ByteArray
    fun generateRecoveryKit(): String
    fun scrubVault(): ScrubSummary
    fun enterSafePresentation(allowedMediaIds: Set<String>)
    fun exitSafePresentation()
    fun allowedPresentationIds(): Set<String>
    fun activeCacheCount(): Int
}

/**
 * Pure-Kotlin in-memory vault backend preserving exact state machine transitions and RAM-only
 * buffer scrubbing semantics when running previews or host JVM unit tests.
 */
class InMemoryVaultBackend : VaultBackend {
    private var state: VaultSecurityState = VaultSecurityState.LOCKED
    private var storedPassphrase: String? = null
    private var recoveryKit: String = "abandon ability able about above absent absorb abstract absurd abuse access accident account accuse achieve acid acoustic acquire across act action actor actress actual"
    private var vaultId: String = UUID.randomUUID().toString()
    private var revision: Long = 1L
    private var rootId: String = UUID.randomUUID().toString()
    private val folders = linkedMapOf<String, VaultFolderItem>()
    private val media = linkedMapOf<String, VaultMediaItem>()
    private val mediaBytes = linkedMapOf<String, ByteArray>()
    private val decodedRamCache = linkedMapOf<String, ByteArray>()
    private var presentationIds: Set<String> = emptySet()

    init {
        folders[rootId] = VaultFolderItem(
            id = rootId,
            parentId = null,
            name = "Root",
            createdAtUnixMs = System.currentTimeMillis()
        )
    }

    override val securityState: VaultSecurityState
        get() = state

    override fun createVault(vaultName: String, passphrase: String) {
        storedPassphrase = passphrase
        vaultId = UUID.randomUUID().toString()
        state = VaultSecurityState.UNLOCKED_FULL
    }

    override fun unlockWithPassphrase(passphrase: String): Boolean {
        state = VaultSecurityState.UNLOCKING_PASSPHRASE
        val expected = storedPassphrase
        if (expected == null) {
            storedPassphrase = passphrase
            state = VaultSecurityState.UNLOCKED_FULL
            return true
        }
        return if (passphrase == expected) {
            state = VaultSecurityState.UNLOCKED_FULL
            true
        } else {
            state = VaultSecurityState.LOCKED
            false
        }
    }

    override fun unlockWithRecoveryKit(mnemonic: String): Boolean {
        val tokens = mnemonic.trim().split(Regex("\\s+"))
        return if (tokens.size == 24) {
            state = VaultSecurityState.UNLOCKED_FULL
            true
        } else {
            state = VaultSecurityState.LOCKED
            false
        }
    }

    override fun lock() {
        state = VaultSecurityState.LOCKING_ZEROIZE
        decodedRamCache.values.forEach { it.fill(0) }
        decodedRamCache.clear()
        presentationIds = emptySet()
        state = VaultSecurityState.LOCKED
    }

    override fun rootFolderId(): String {
        requireUnlocked()
        return rootId
    }

    override fun listFolderContents(folderId: String): FolderContentsSnapshot {
        requireUnlocked()
        val subs = folders.values
            .filter { it.parentId == folderId }
            .map { folder ->
                val subCount = folders.values.count { it.parentId == folder.id }.toLong()
                val itemsInFolder = media.values.filter { it.folderId == folder.id }
                folder.copy(
                    subfolderCount = subCount,
                    mediaCount = itemsInFolder.size.toLong(),
                    totalBytes = itemsInFolder.sumOf { it.plaintextSize }
                )
            }
            .sortedBy { it.name }
        val items = media.values
            .filter { it.folderId == folderId }
            .sortedBy { it.originalName }
        return FolderContentsSnapshot(folderId, subs, items)
    }

    override fun getBreadcrumbs(folderId: String): List<VaultFolderItem> {
        requireUnlocked()
        val chain = mutableListOf<VaultFolderItem>()
        var current: String? = folderId
        var guard = 0
        while (current != null && guard < 64) {
            guard++
            val node = folders[current] ?: break
            chain.add(node)
            current = node.parentId
        }
        return chain.reversed()
    }

    override fun listAllMediaTimeline(): List<VaultMediaItem> {
        requireUnlocked()
        return media.values.sortedByDescending { it.capturedAtUnixMs ?: it.importedAtUnixMs }
    }

    override fun vaultMetrics(): VaultMetricsSnapshot {
        requireUnlocked()
        val items = media.values
        return VaultMetricsSnapshot(
            vaultId = vaultId,
            headerRevision = revision,
            folderCount = folders.size.toLong(),
            totalMedia = items.size.toLong(),
            totalBytes = items.sumOf { it.plaintextSize },
            photoCount = items.count { it.category == MediaCategory.PHOTO || it.category == MediaCategory.ANIMATION }.toLong(),
            photoBytes = items.filter { it.category == MediaCategory.PHOTO || it.category == MediaCategory.ANIMATION }.sumOf { it.plaintextSize },
            videoCount = items.count { it.category == MediaCategory.VIDEO }.toLong(),
            videoBytes = items.filter { it.category == MediaCategory.VIDEO }.sumOf { it.plaintextSize },
            rawCount = items.count { it.category == MediaCategory.RAW_PHOTO }.toLong(),
            rawBytes = items.filter { it.category == MediaCategory.RAW_PHOTO }.sumOf { it.plaintextSize },
            docCount = items.count { it.category == MediaCategory.DOCUMENT_PDF || it.category == MediaCategory.MARKDOWN_NOTE }.toLong(),
            docBytes = items.filter { it.category == MediaCategory.DOCUMENT_PDF || it.category == MediaCategory.MARKDOWN_NOTE }.sumOf { it.plaintextSize },
            thumbPackBytes = (items.size * 24_576L),
            trashedCount = 0L,
        )
    }

    override fun createFolder(parentFolderId: String, name: String): String {
        requireUnlocked()
        val id = UUID.randomUUID().toString()
        folders[id] = VaultFolderItem(
            id = id,
            parentId = parentFolderId,
            name = name,
            createdAtUnixMs = System.currentTimeMillis()
        )
        return id
    }

    override fun setFolderPinned(folderId: String, pinned: Boolean) {
        requireUnlocked()
        folders[folderId]?.let { folders[folderId] = it.copy(pinned = pinned) }
    }

    override fun setFolderBlurShield(folderId: String, blurShield: Boolean) {
        requireUnlocked()
        folders[folderId]?.let { folders[folderId] = it.copy(blurShield = blurShield) }
    }

    override fun toggleFavorite(mediaId: String): Boolean {
        requireUnlocked()
        val item = media[mediaId] ?: return false
        val next = !item.favorite
        media[mediaId] = item.copy(favorite = next)
        return next
    }

    override fun importStreamItem(
        targetParentId: String,
        relativeSegments: List<String>,
        fileName: String,
        bytes: ByteArray,
        policy: DedupPolicy,
    ): String {
        requireUnlocked()
        var currentFolder = targetParentId
        for (segment in relativeSegments) {
            if (segment.isBlank()) continue
            val existing = folders.values.firstOrNull {
                it.parentId == currentFolder && it.name == segment
            }
            currentFolder = existing?.id ?: createFolder(currentFolder, segment)
        }

        val id = UUID.randomUUID().toString()
        val ext = fileName.substringAfterLast(".", "").lowercase()
        val category = when (ext) {
            "mp4", "mkv", "mov", "webm" -> MediaCategory.VIDEO
            "dng", "cr2", "cr3", "nef", "arw" -> MediaCategory.RAW_PHOTO
            "pdf" -> MediaCategory.DOCUMENT_PDF
            "gif" -> MediaCategory.ANIMATION
            "md" -> MediaCategory.MARKDOWN_NOTE
            else -> MediaCategory.PHOTO
        }
        media[id] = VaultMediaItem(
            id = id,
            folderId = currentFolder,
            originalName = fileName,
            mimeType = if (category == MediaCategory.VIDEO) "video/mp4" else "image/jpeg",
            category = category,
            plaintextSize = bytes.size.toLong(),
            importedAtUnixMs = System.currentTimeMillis(),
        )
        mediaBytes[id] = bytes.copyOf()
        return id
    }

    override fun readMediaChunk(mediaId: String, chunkIndex: Long): ByteArray {
        requireUnlocked()
        val full = mediaBytes[mediaId] ?: return ByteArray(0)
        val chunkSize = 1024 * 1024
        val start = (chunkIndex * chunkSize).toInt()
        if (start >= full.size) return ByteArray(0)
        val end = kotlin.math.min(start + chunkSize, full.size)
        val slice = full.copyOfRange(start, end)
        decodedRamCache[mediaId] = slice
        return slice
    }

    override fun readMediaAllBytes(mediaId: String): ByteArray {
        requireUnlocked()
        val full = mediaBytes[mediaId] ?: return ByteArray(0)
        decodedRamCache[mediaId] = full.copyOf()
        return full.copyOf()
    }

    override fun readThumbnailBytes(mediaId: String): ByteArray {
        requireUnlocked()
        return mediaBytes[mediaId] ?: ByteArray(0)
    }

    override fun generateRecoveryKit(): String {
        requireUnlocked()
        return recoveryKit
    }

    override fun scrubVault(): ScrubSummary {
        requireUnlocked()
        return ScrubSummary(
            checkedBlobs = media.size.toLong(),
            checkedChunks = media.size.toLong(),
            verifiedBytes = media.values.sumOf { it.plaintextSize },
            corruptedCount = 0L,
            missingCount = 0L,
        )
    }

    override fun enterSafePresentation(allowedMediaIds: Set<String>) {
        requireUnlocked()
        presentationIds = allowedMediaIds
        state = VaultSecurityState.UNLOCKED_SAFE_PRESENTATION
    }

    override fun exitSafePresentation() {
        presentationIds = emptySet()
        if (state == VaultSecurityState.UNLOCKED_SAFE_PRESENTATION) {
            state = VaultSecurityState.UNLOCKED_FULL
        }
    }

    override fun allowedPresentationIds(): Set<String> = presentationIds

    override fun activeCacheCount(): Int = decodedRamCache.size

    private fun requireUnlocked() {
        check(
            state == VaultSecurityState.UNLOCKED_FULL ||
                state == VaultSecurityState.UNLOCKED_SAFE_PRESENTATION ||
                state == VaultSecurityState.UNLOCKED_DECOY
        ) { "Vault is locked" }
    }
}
