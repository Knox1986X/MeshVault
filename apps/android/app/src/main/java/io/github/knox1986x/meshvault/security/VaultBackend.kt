package io.github.knox1986x.meshvault.security

import java.security.MessageDigest
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
    val trashedAtUnixMs: Long? = null,
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

data class DoctorSnapshot(
    val primaryHeaderValid: Boolean,
    val backupHeaderValid: Boolean,
    val headerRevision: Long,
    val keySlotCount: Int,
    val decoyConfigured: Boolean,
    val mediaCount: Long,
    val trashedCount: Long,
    val missingBlobsCount: Long,
    val walPending: Boolean,
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
    ): String?
    fun readMediaChunk(mediaId: String, chunkIndex: Long): ByteArray
    fun readMediaAllBytes(mediaId: String): ByteArray
    fun readThumbnailBytes(mediaId: String): ByteArray
    fun generateRecoveryKit(): String
    fun scrubVault(): ScrubSummary
    fun enterSafePresentation(allowedMediaIds: Set<String>)
    fun exitSafePresentation()
    fun exitSafePresentationWithPassphrase(passphrase: String): Boolean
    fun configureDecoyVault(decoyPassphrase: String)
    fun moveToTrash(mediaId: String, nowUnixMs: Long = System.currentTimeMillis())
    fun restoreFromTrash(mediaId: String)
    fun listTrashedMedia(): List<VaultMediaItem>
    fun shredMedia(mediaId: String)
    fun purgeExpiredTrash(retentionDays: Int = 30, nowUnixMs: Long = System.currentTimeMillis()): Long
    fun cleanExportBytes(mediaId: String): ByteArray
    fun doctorReport(): DoctorSnapshot
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
    private var decoyPassphrase: String? = null
    private var recoveryKit: String = "abandon ability able about above absent absorb abstract absurd abuse access accident account accuse achieve acid acoustic acquire across act action actor actress actual"
    private var vaultId: String = UUID.randomUUID().toString()
    private var revision: Long = 1L
    private var rootId: String = UUID.randomUUID().toString()
    private var decoyRootId: String = UUID.randomUUID().toString()
    private val folders = linkedMapOf<String, VaultFolderItem>()
    private val media = linkedMapOf<String, VaultMediaItem>()
    private val mediaBytes = linkedMapOf<String, ByteArray>()
    private val decoyFolders = linkedMapOf<String, VaultFolderItem>()
    private val decoyMedia = linkedMapOf<String, VaultMediaItem>()
    private val decoyMediaBytes = linkedMapOf<String, ByteArray>()
    private val dedupHashes = linkedMapOf<String, String>()
    private val decodedRamCache = linkedMapOf<String, ByteArray>()
    private var presentationIds: Set<String> = emptySet()

    init {
        val now = System.currentTimeMillis()
        folders[rootId] = VaultFolderItem(
            id = rootId,
            parentId = null,
            name = "Root",
            createdAtUnixMs = now
        )
        decoyFolders[decoyRootId] = VaultFolderItem(
            id = decoyRootId,
            parentId = null,
            name = "Root",
            createdAtUnixMs = now
        )
    }

    private fun activeFolders(): MutableMap<String, VaultFolderItem> =
        if (state == VaultSecurityState.UNLOCKED_DECOY) decoyFolders else folders

    private fun activeMedia(): MutableMap<String, VaultMediaItem> =
        if (state == VaultSecurityState.UNLOCKED_DECOY) decoyMedia else media

    private fun activeMediaBytes(): MutableMap<String, ByteArray> =
        if (state == VaultSecurityState.UNLOCKED_DECOY) decoyMediaBytes else mediaBytes

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
        return when (passphrase) {
            expected -> {
                state = VaultSecurityState.UNLOCKED_FULL
                true
            }
            decoyPassphrase -> {
                state = VaultSecurityState.UNLOCKED_DECOY
                true
            }
            else -> {
                state = VaultSecurityState.LOCKED
                false
            }
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
        return if (state == VaultSecurityState.UNLOCKED_DECOY) decoyRootId else rootId
    }

    override fun listFolderContents(folderId: String): FolderContentsSnapshot {
        requireUnlocked()
        val fMap = activeFolders()
        val mMap = activeMedia()
        val subs = fMap.values
            .filter { it.parentId == folderId }
            .map { folder ->
                val subCount = fMap.values.count { it.parentId == folder.id }.toLong()
                val itemsInFolder = mMap.values.filter {
                    it.folderId == folder.id && it.trashedAtUnixMs == null
                }
                folder.copy(
                    subfolderCount = subCount,
                    mediaCount = itemsInFolder.size.toLong(),
                    totalBytes = itemsInFolder.sumOf { it.plaintextSize }
                )
            }
            .sortedBy { it.name }
        val items = mMap.values
            .filter { it.folderId == folderId && it.trashedAtUnixMs == null }
            .sortedBy { it.originalName }
        return FolderContentsSnapshot(folderId, subs, items)
    }

    override fun getBreadcrumbs(folderId: String): List<VaultFolderItem> {
        requireUnlocked()
        val fMap = activeFolders()
        val chain = mutableListOf<VaultFolderItem>()
        var current: String? = folderId
        var guard = 0
        while (current != null && guard < 64) {
            guard++
            val node = fMap[current] ?: break
            chain.add(node)
            current = node.parentId
        }
        return chain.reversed()
    }

    override fun listAllMediaTimeline(): List<VaultMediaItem> {
        requireUnlocked()
        return activeMedia().values
            .filter { it.trashedAtUnixMs == null }
            .sortedByDescending { it.capturedAtUnixMs ?: it.importedAtUnixMs }
    }

    override fun vaultMetrics(): VaultMetricsSnapshot {
        requireUnlocked()
        val activeItems = activeMedia().values.filter { it.trashedAtUnixMs == null }
        val trashedItems = activeMedia().values.filter { it.trashedAtUnixMs != null }
        return VaultMetricsSnapshot(
            vaultId = vaultId,
            headerRevision = revision,
            folderCount = activeFolders().size.toLong(),
            totalMedia = activeItems.size.toLong(),
            totalBytes = activeItems.sumOf { it.plaintextSize },
            photoCount = activeItems.count { it.category == MediaCategory.PHOTO || it.category == MediaCategory.ANIMATION }.toLong(),
            photoBytes = activeItems.filter { it.category == MediaCategory.PHOTO || it.category == MediaCategory.ANIMATION }.sumOf { it.plaintextSize },
            videoCount = activeItems.count { it.category == MediaCategory.VIDEO }.toLong(),
            videoBytes = activeItems.filter { it.category == MediaCategory.VIDEO }.sumOf { it.plaintextSize },
            rawCount = activeItems.count { it.category == MediaCategory.RAW_PHOTO }.toLong(),
            rawBytes = activeItems.filter { it.category == MediaCategory.RAW_PHOTO }.sumOf { it.plaintextSize },
            docCount = activeItems.count { it.category == MediaCategory.DOCUMENT_PDF || it.category == MediaCategory.MARKDOWN_NOTE }.toLong(),
            docBytes = activeItems.filter { it.category == MediaCategory.DOCUMENT_PDF || it.category == MediaCategory.MARKDOWN_NOTE }.sumOf { it.plaintextSize },
            thumbPackBytes = (activeItems.size * 24_576L),
            trashedCount = trashedItems.size.toLong(),
        )
    }

    override fun createFolder(parentFolderId: String, name: String): String {
        requireUnlocked()
        val id = UUID.randomUUID().toString()
        activeFolders()[id] = VaultFolderItem(
            id = id,
            parentId = parentFolderId,
            name = name,
            createdAtUnixMs = System.currentTimeMillis()
        )
        return id
    }

    override fun setFolderPinned(folderId: String, pinned: Boolean) {
        requireUnlocked()
        val fMap = activeFolders()
        fMap[folderId]?.let { fMap[folderId] = it.copy(pinned = pinned) }
    }

    override fun setFolderBlurShield(folderId: String, blurShield: Boolean) {
        requireUnlocked()
        val fMap = activeFolders()
        fMap[folderId]?.let { fMap[folderId] = it.copy(blurShield = blurShield) }
    }

    override fun toggleFavorite(mediaId: String): Boolean {
        requireUnlocked()
        val mMap = activeMedia()
        val item = mMap[mediaId] ?: return false
        val next = !item.favorite
        mMap[mediaId] = item.copy(favorite = next)
        return next
    }

    override fun importStreamItem(
        targetParentId: String,
        relativeSegments: List<String>,
        fileName: String,
        bytes: ByteArray,
        policy: DedupPolicy,
    ): String? {
        requireUnlocked()
        val scopePrefix = if (state == VaultSecurityState.UNLOCKED_DECOY) "d:" else "r:"
        val digestHex = scopePrefix + MessageDigest.getInstance("SHA-256")
            .digest(bytes)
            .joinToString("") { "%02x".format(it) }
        val existingMediaId = dedupHashes[digestHex]
        if (existingMediaId != null) {
            when (policy) {
                DedupPolicy.SKIP_DUPLICATE -> return null
                DedupPolicy.LINK_INTO_TARGET_FOLDER -> return existingMediaId
                DedupPolicy.KEEP_INDEPENDENT_COPY -> Unit
            }
        }

        val fMap = activeFolders()
        var currentFolder = targetParentId
        for (segment in relativeSegments) {
            if (segment.isBlank()) continue
            val existing = fMap.values.firstOrNull {
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
        activeMedia()[id] = VaultMediaItem(
            id = id,
            folderId = currentFolder,
            originalName = fileName,
            mimeType = if (category == MediaCategory.VIDEO) "video/mp4" else "image/jpeg",
            category = category,
            plaintextSize = bytes.size.toLong(),
            importedAtUnixMs = System.currentTimeMillis(),
        )
        activeMediaBytes()[id] = bytes.copyOf()
        dedupHashes.putIfAbsent(digestHex, id)
        return id
    }

    override fun readMediaChunk(mediaId: String, chunkIndex: Long): ByteArray {
        requireUnlocked()
        val full = activeMediaBytes()[mediaId] ?: return ByteArray(0)
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
        val full = activeMediaBytes()[mediaId] ?: return ByteArray(0)
        decodedRamCache[mediaId] = full.copyOf()
        return full.copyOf()
    }

    override fun readThumbnailBytes(mediaId: String): ByteArray {
        requireUnlocked()
        return activeMediaBytes()[mediaId] ?: ByteArray(0)
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

    override fun exitSafePresentationWithPassphrase(passphrase: String): Boolean {
        if (passphrase.isBlank()) return false
        if (storedPassphrase == null || passphrase == storedPassphrase) {
            exitSafePresentation()
            return true
        }
        return false
    }

    override fun configureDecoyVault(decoyPassphrase: String) {
        requireUnlocked()
        this.decoyPassphrase = decoyPassphrase
        revision += 1
    }

    override fun moveToTrash(mediaId: String, nowUnixMs: Long) {
        requireUnlocked()
        val mMap = activeMedia()
        mMap[mediaId]?.let { mMap[mediaId] = it.copy(trashedAtUnixMs = nowUnixMs) }
    }

    override fun restoreFromTrash(mediaId: String) {
        requireUnlocked()
        val mMap = activeMedia()
        mMap[mediaId]?.let { mMap[mediaId] = it.copy(trashedAtUnixMs = null) }
    }

    override fun listTrashedMedia(): List<VaultMediaItem> {
        requireUnlocked()
        return activeMedia().values
            .filter { it.trashedAtUnixMs != null }
            .sortedByDescending { it.trashedAtUnixMs }
    }

    override fun shredMedia(mediaId: String) {
        requireUnlocked()
        activeMedia().remove(mediaId)
        activeMediaBytes().remove(mediaId)?.fill(0)
        decodedRamCache.remove(mediaId)?.fill(0)
    }

    override fun purgeExpiredTrash(retentionDays: Int, nowUnixMs: Long): Long {
        requireUnlocked()
        val retentionMs = retentionDays.toLong() * 86_400_000L
        val expiredIds = activeMedia().values
            .filter { item ->
                val trashedAt = item.trashedAtUnixMs ?: return@filter false
                (nowUnixMs - trashedAt) >= retentionMs
            }
            .map { it.id }
        expiredIds.forEach { shredMedia(it) }
        return expiredIds.size.toLong()
    }

    override fun cleanExportBytes(mediaId: String): ByteArray {
        requireUnlocked()
        val raw = activeMediaBytes()[mediaId] ?: return ByteArray(0)
        if (raw.size >= 4 && raw[0] == 0xFF.toByte() && raw[1] == 0xD8.toByte()) {
            // Strip APP1..APP15 / COM segments in RAM.
            val out = mutableListOf<Byte>(0xFF.toByte(), 0xD8.toByte())
            var pos = 2
            while (pos + 1 < raw.size) {
                if (raw[pos] != 0xFF.toByte()) return raw.copyOf()
                while (pos < raw.size && raw[pos] == 0xFF.toByte()) pos++
                if (pos >= raw.size) break
                val marker = raw[pos].toInt() and 0xFF
                pos++
                if (marker == 0xD9) {
                    out.add(0xFF.toByte())
                    out.add(0xD9.toByte())
                    return out.toByteArray()
                }
                if (marker == 0xDA) {
                    out.add(0xFF.toByte())
                    out.add(0xDA.toByte())
                    for (k in pos until raw.size) out.add(raw[k])
                    return out.toByteArray()
                }
                if (pos + 2 > raw.size) break
                val segLen = ((raw[pos].toInt() and 0xFF) shl 8) or (raw[pos + 1].toInt() and 0xFF)
                if (segLen < 2 || pos + segLen > raw.size) break
                val strip = (marker in 0xE1..0xEF) || marker == 0xFE
                if (!strip) {
                    out.add(0xFF.toByte())
                    out.add(marker.toByte())
                    for (k in pos until (pos + segLen)) out.add(raw[k])
                }
                pos += segLen
            }
            return out.toByteArray()
        }
        return raw.copyOf()
    }

    override fun doctorReport(): DoctorSnapshot {
        requireUnlocked()
        val activeItems = activeMedia().values.filter { it.trashedAtUnixMs == null }
        val trashedItems = activeMedia().values.filter { it.trashedAtUnixMs != null }
        return DoctorSnapshot(
            primaryHeaderValid = true,
            backupHeaderValid = true,
            headerRevision = revision,
            keySlotCount = if (decoyPassphrase != null) 2 else 1,
            decoyConfigured = decoyPassphrase != null,
            mediaCount = activeItems.size.toLong(),
            trashedCount = trashedItems.size.toLong(),
            missingBlobsCount = 0L,
            walPending = false,
        )
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
