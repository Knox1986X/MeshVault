package io.github.knox1986x.meshvault.saf

import android.content.ContentResolver
import android.net.Uri
import android.provider.DocumentsContract
import io.github.knox1986x.meshvault.security.MediaCategory

data class SafSourceFile(
    val documentUri: Uri,
    val relativeFolderSegments: List<String>,
    val fileName: String,
    val mimeType: String,
    val sizeBytes: Long,
    val category: MediaCategory,
)

data class SafFolderBranch(
    val relativePath: String,
    val displayName: String,
    val depth: Int,
    val fileCount: Int,
    val totalBytes: Long,
    val selected: Boolean = true,
)

data class SafTreePreview(
    val rootFolderName: String,
    val branches: List<SafFolderBranch>,
    val files: List<SafSourceFile>,
    val totalBytes: Long,
    val photoCount: Int,
    val videoCount: Int,
    val rawCount: Int,
    val documentCount: Int,
)

/**
 * Fast SAF tree scanner using direct ContentResolver + DocumentsContract queries
 * instead of slow DocumentFile.listFiles(), with symlink/cycle protection and depth guard.
 */
object SafTreeScanner {

    private const val MAX_DEPTH = 64

    private val PROJECTION = arrayOf(
        DocumentsContract.Document.COLUMN_DOCUMENT_ID,
        DocumentsContract.Document.COLUMN_DISPLAY_NAME,
        DocumentsContract.Document.COLUMN_MIME_TYPE,
        DocumentsContract.Document.COLUMN_SIZE,
    )

    fun scanTree(resolver: ContentResolver, treeUri: Uri): SafTreePreview {
        val rootDocId = DocumentsContract.getTreeDocumentId(treeUri)
        val rootName = queryRootName(resolver, treeUri, rootDocId) ?: "ImportedFolder"

        val visitedDocIds = HashSet<String>()
        val branchMap = LinkedHashMap<String, SafFolderBranch>()
        val files = ArrayList<SafSourceFile>()

        var photoCount = 0
        var videoCount = 0
        var rawCount = 0
        var documentCount = 0
        var totalBytes = 0L

        fun walk(docId: String, segments: List<String>, depth: Int) {
            if (depth > MAX_DEPTH || !visitedDocIds.add(docId)) {
                return
            }

            val relPath = segments.joinToString("/")
            var branchFiles = 0
            var branchBytes = 0L

            val childrenUri = DocumentsContract.buildChildDocumentsUriUsingTree(treeUri, docId)
            resolver.query(childrenUri, PROJECTION, null, null, null)?.use { cursor ->
                val idxId = cursor.getColumnIndex(DocumentsContract.Document.COLUMN_DOCUMENT_ID)
                val idxName = cursor.getColumnIndex(DocumentsContract.Document.COLUMN_DISPLAY_NAME)
                val idxMime = cursor.getColumnIndex(DocumentsContract.Document.COLUMN_MIME_TYPE)
                val idxSize = cursor.getColumnIndex(DocumentsContract.Document.COLUMN_SIZE)

                while (cursor.moveToNext()) {
                    val childId = if (idxId >= 0) cursor.getString(idxId) else continue
                    val name = if (idxName >= 0) cursor.getString(idxName) ?: "unnamed" else "unnamed"
                    val mime = if (idxMime >= 0) cursor.getString(idxMime) ?: "application/octet-stream" else "application/octet-stream"
                    val size = if (idxSize >= 0 && !cursor.isNull(idxSize)) cursor.getLong(idxSize) else 0L

                    if (mime == DocumentsContract.Document.MIME_TYPE_DIR) {
                        walk(childId, segments + name, depth + 1)
                    } else {
                        val category = classify(name, mime)
                        when (category) {
                            MediaCategory.PHOTO, MediaCategory.ANIMATION -> photoCount++
                            MediaCategory.VIDEO -> videoCount++
                            MediaCategory.RAW_PHOTO -> rawCount++
                            MediaCategory.DOCUMENT_PDF, MediaCategory.MARKDOWN_NOTE -> documentCount++
                            MediaCategory.AUDIO_NOTE -> {}
                        }
                        val docUri = DocumentsContract.buildDocumentUriUsingTree(treeUri, childId)
                        files.add(
                            SafSourceFile(
                                documentUri = docUri,
                                relativeFolderSegments = segments,
                                fileName = name,
                                mimeType = mime,
                                sizeBytes = size,
                                category = category,
                            )
                        )
                        branchFiles++
                        branchBytes += size
                        totalBytes += size
                    }
                }
            }

            branchMap[relPath] = SafFolderBranch(
                relativePath = relPath,
                displayName = segments.lastOrNull() ?: rootName,
                depth = depth,
                fileCount = branchFiles,
                totalBytes = branchBytes,
                selected = true,
            )
        }

        walk(rootDocId, listOf(rootName), 0)

        return SafTreePreview(
            rootFolderName = rootName,
            branches = branchMap.values.toList(),
            files = files,
            totalBytes = totalBytes,
            photoCount = photoCount,
            videoCount = videoCount,
            rawCount = rawCount,
            documentCount = documentCount,
        )
    }

    private fun queryRootName(resolver: ContentResolver, treeUri: Uri, rootDocId: String): String? {
        val docUri = DocumentsContract.buildDocumentUriUsingTree(treeUri, rootDocId)
        resolver.query(
            docUri,
            arrayOf(DocumentsContract.Document.COLUMN_DISPLAY_NAME),
            null,
            null,
            null
        )?.use { c ->
            if (c.moveToFirst()) {
                return c.getString(0)
            }
        }
        return null
    }

    private fun classify(fileName: String, mimeType: String): MediaCategory {
        val ext = fileName.substringAfterLast(".", "").lowercase()
        return when {
            ext in setOf("dng", "cr2", "cr3", "nef", "arw") -> MediaCategory.RAW_PHOTO
            ext == "gif" || mimeType == "image/gif" -> MediaCategory.ANIMATION
            ext == "pdf" || mimeType == "application/pdf" -> MediaCategory.DOCUMENT_PDF
            ext == "md" -> MediaCategory.MARKDOWN_NOTE
            mimeType.startsWith("video/") || ext in setOf("mp4", "mkv", "mov", "webm") -> MediaCategory.VIDEO
            mimeType.startsWith("audio/") || ext in setOf("m4a", "ogg", "opus", "wav", "mp3") -> MediaCategory.AUDIO_NOTE
            else -> MediaCategory.PHOTO
        }
    }
}
