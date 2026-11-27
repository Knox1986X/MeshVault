package com.meshvault.data.sync.dropbox

import android.content.Context
import com.meshvault.domain.repository.DropboxQuotaInfo
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.longOrNull
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.io.RandomAccessFile

@Serializable
data class ResumableUploadCursor(
    val sessionId: String,
    val confirmedOffset: Long,
    val fileLength: Long,
)

/**
 * Низкоуровневый клиент Dropbox HTTP API v2 для обезличенной Content-Addressed структуры `/MeshVault/`:
 *  - `/MeshVault/vault_header.json`
 *  - `/MeshVault/oplog/<id>.mvop`
 *  - `/MeshVault/snapshots/manifest.mvenc`
 *  - `/MeshVault/thumbs/<hmac2>/<id>.mvthumb`
 *  - `/MeshVault/blobs/<hmac2>/<id>.mvbin` (с потоковой докачкой чанками по 4 МБ для файлов > 8 МБ).
 */
class DropboxHttpApiClient(
    context: Context,
    private val authManager: DropboxPkceAuthManager,
    private val httpClient: OkHttpClient,
) {
    private val json = Json {
        ignoreUnknownKeys = true
        encodeDefaults = true
    }
    private val resumeStateFile = File(context.filesDir, "dropbox_upload_sessions.json")

    suspend fun getSpaceUsage(): DropboxQuotaInfo = withContext(Dispatchers.IO) {
        val token = authManager.getValidAccessToken()
        val quotaReq = Request.Builder()
            .url("https://api.dropboxapi.com/2/users/get_space_usage")
            .header("Authorization", "Bearer $token")
            .post("null".toRequestBody(JSON_MEDIA))
            .build()

        var used = 0L
        var allocated = 0L
        httpClient.newCall(quotaReq).execute().use { resp ->
            val raw = resp.body?.string().orEmpty()
            if (!resp.isSuccessful) throw IOException("Ошибка запроса квоты Dropbox (${resp.code})")
            val obj = json.parseToJsonElement(raw).jsonObject
            used = obj["used"]?.jsonPrimitive?.longOrNull ?: 0L
            allocated = obj["allocation"]?.jsonObject?.get("allocated")?.jsonPrimitive?.longOrNull ?: 0L
        }

        val nameReq = Request.Builder()
            .url("https://api.dropboxapi.com/2/users/get_current_account")
            .header("Authorization", "Bearer $token")
            .post("null".toRequestBody(JSON_MEDIA))
            .build()

        val displayName = runCatching {
            httpClient.newCall(nameReq).execute().use { resp ->
                if (!resp.isSuccessful) ""
                else {
                    val obj = json.parseToJsonElement(resp.body?.string().orEmpty()).jsonObject
                    obj["name"]?.jsonObject?.get("display_name")?.jsonPrimitive?.contentOrNull.orEmpty()
                }
            }
        }.getOrDefault("")

        DropboxQuotaInfo(
            usedBytes = used,
            allocatedBytes = allocated,
            accountDisplayName = displayName,
        )
    }

    suspend fun listFileNamesInFolder(dropboxFolderPath: String): List<String> = withContext(Dispatchers.IO) {
        val token = authManager.getValidAccessToken()
        val names = mutableListOf<String>()

        val startArg = """{"path":"$dropboxFolderPath","recursive":false}"""
        val startReq = Request.Builder()
            .url("https://api.dropboxapi.com/2/files/list_folder")
            .header("Authorization", "Bearer $token")
            .post(startArg.toRequestBody(JSON_MEDIA))
            .build()

        var cursor: String?
        var hasMore: Boolean

        httpClient.newCall(startReq).execute().use { resp ->
            val body = resp.body?.string().orEmpty()
            if (resp.code == 409 && body.contains("not_found")) {
                return@withContext emptyList()
            }
            if (!resp.isSuccessful) throw IOException("Ошибка чтения каталога Dropbox (${resp.code})")
            val parsed = json.parseToJsonElement(body).jsonObject
            parsed["entries"]?.jsonArray?.forEach { entry ->
                val obj = entry.jsonObject
                if (obj[".tag"]?.jsonPrimitive?.contentOrNull == "file") {
                    obj["name"]?.jsonPrimitive?.contentOrNull?.let(names::add)
                }
            }
            hasMore = parsed["has_more"]?.jsonPrimitive?.booleanOrNull == true
            cursor = parsed["cursor"]?.jsonPrimitive?.contentOrNull
        }

        while (hasMore && cursor != null) {
            val contReq = Request.Builder()
                .url("https://api.dropboxapi.com/2/files/list_folder/continue")
                .header("Authorization", "Bearer $token")
                .post("""{"cursor":"$cursor"}""".toRequestBody(JSON_MEDIA))
                .build()
            httpClient.newCall(contReq).execute().use { resp ->
                if (!resp.isSuccessful) throw IOException("Ошибка пагинации каталога Dropbox (${resp.code})")
                val parsed = json.parseToJsonElement(resp.body?.string().orEmpty()).jsonObject
                parsed["entries"]?.jsonArray?.forEach { entry ->
                    val obj = entry.jsonObject
                    if (obj[".tag"]?.jsonPrimitive?.contentOrNull == "file") {
                        obj["name"]?.jsonPrimitive?.contentOrNull?.let(names::add)
                    }
                }
                hasMore = parsed["has_more"]?.jsonPrimitive?.booleanOrNull == true
                cursor = parsed["cursor"]?.jsonPrimitive?.contentOrNull
            }
        }
        names
    }

    suspend fun uploadSmallBytes(dropboxPath: String, bytes: ByteArray) = withContext(Dispatchers.IO) {
        val token = authManager.getValidAccessToken()
        val apiArg = """{"path":"$dropboxPath","mode":"overwrite","autorename":false,"mute":true}"""
        val req = Request.Builder()
            .url("https://content.dropboxapi.com/2/files/upload")
            .header("Authorization", "Bearer $token")
            .header("Dropbox-API-Arg", apiArg)
            .post(bytes.toRequestBody(OCTET_MEDIA))
            .build()

        httpClient.newCall(req).execute().use { resp ->
            if (!resp.isSuccessful) {
                throw IOException("Ошибка выгрузки $dropboxPath (${resp.code}): ${resp.body?.string().orEmpty()}")
            }
        }
    }

    /**
     * Выгружает зашифрованный файл `.mvbin`:
     *  - До 8 МБ — за один запрос `/2/files/upload`;
     *  - Свыше 8 МБ — через `/2/files/upload_session/start|append_v2|finish` чанками по 4 МБ с докачкой!
     */
    suspend fun uploadFileResumable(
        dropboxPath: String,
        localFile: File,
        onBytesUploaded: (uploaded: Long, total: Long) -> Unit = { _, _ -> },
    ) = withContext(Dispatchers.IO) {
        val totalLen = localFile.length()
        if (totalLen <= MULTIPART_THRESHOLD_BYTES) {
            uploadSmallBytes(dropboxPath, localFile.readBytes())
            onBytesUploaded(totalLen, totalLen)
            return@withContext
        }

        val token = authManager.getValidAccessToken()
        val resumeMap = readResumeMap()
        val existingCursor = resumeMap[dropboxPath]?.takeIf { it.fileLength == totalLen }

        RandomAccessFile(localFile, "r").use { raf ->
            var sessionId: String
            var offset: Long

            if (existingCursor != null && existingCursor.confirmedOffset in 1 until totalLen) {
                sessionId = existingCursor.sessionId
                offset = existingCursor.confirmedOffset
            } else {
                val firstChunkLen = minOf(SESSION_CHUNK_BYTES.toLong(), totalLen).toInt()
                val firstChunk = ByteArray(firstChunkLen)
                raf.seek(0L)
                raf.readFully(firstChunk)

                val startReq = Request.Builder()
                    .url("https://content.dropboxapi.com/2/files/upload_session/start")
                    .header("Authorization", "Bearer $token")
                    .header("Dropbox-API-Arg", """{"close":false}""")
                    .post(firstChunk.toRequestBody(OCTET_MEDIA))
                    .build()

                sessionId = httpClient.newCall(startReq).execute().use { resp ->
                    val raw = resp.body?.string().orEmpty()
                    if (!resp.isSuccessful) throw IOException("Ошибка старта сессии выгрузки (${resp.code}): $raw")
                    json.parseToJsonElement(raw).jsonObject["session_id"]?.jsonPrimitive?.contentOrNull
                        ?: throw IOException("Dropbox не вернул session_id")
                }
                offset = firstChunkLen.toLong()
                saveResumeCursor(dropboxPath, ResumableUploadCursor(sessionId, offset, totalLen))
                onBytesUploaded(offset, totalLen)
            }

            while (offset < totalLen) {
                val remaining = totalLen - offset
                val chunkLen = minOf(SESSION_CHUNK_BYTES.toLong(), remaining).toInt()
                val chunk = ByteArray(chunkLen)
                raf.seek(offset)
                raf.readFully(chunk)

                val isLast = (offset + chunkLen == totalLen)
                if (!isLast) {
                    val appendArg = """{"cursor":{"session_id":"$sessionId","offset":$offset},"close":false}"""
                    val appendReq = Request.Builder()
                        .url("https://content.dropboxapi.com/2/files/upload_session/append_v2")
                        .header("Authorization", "Bearer $token")
                        .header("Dropbox-API-Arg", appendArg)
                        .post(chunk.toRequestBody(OCTET_MEDIA))
                        .build()

                    httpClient.newCall(appendReq).execute().use { resp ->
                        if (!resp.isSuccessful) {
                            throw IOException("Обрыв дозагрузки чанка на $offset (${resp.code})")
                        }
                    }
                    offset += chunkLen
                    saveResumeCursor(dropboxPath, ResumableUploadCursor(sessionId, offset, totalLen))
                    onBytesUploaded(offset, totalLen)
                } else {
                    val finishArg =
                        """{"cursor":{"session_id":"$sessionId","offset":$offset},"commit":{"path":"$dropboxPath","mode":"overwrite","autorename":false,"mute":true}}"""
                    val finishReq = Request.Builder()
                        .url("https://content.dropboxapi.com/2/files/upload_session/finish")
                        .header("Authorization", "Bearer $token")
                        .header("Dropbox-API-Arg", finishArg)
                        .post(chunk.toRequestBody(OCTET_MEDIA))
                        .build()

                    httpClient.newCall(finishReq).execute().use { resp ->
                        if (!resp.isSuccessful) {
                            throw IOException("Ошибка завершения сессии выгрузки (${resp.code}): ${resp.body?.string().orEmpty()}")
                        }
                    }
                    offset += chunkLen
                    removeResumeCursor(dropboxPath)
                    onBytesUploaded(totalLen, totalLen)
                }
            }
        }
    }

    suspend fun downloadBytesOrNull(dropboxPath: String): ByteArray? = withContext(Dispatchers.IO) {
        val token = authManager.getValidAccessToken()
        val req = Request.Builder()
            .url("https://content.dropboxapi.com/2/files/download")
            .header("Authorization", "Bearer $token")
            .header("Dropbox-API-Arg", """{"path":"$dropboxPath"}""")
            .post(ByteArray(0).toRequestBody(OCTET_MEDIA))
            .build()

        httpClient.newCall(req).execute().use { resp ->
            if (resp.code == 409) return@withContext null
            if (!resp.isSuccessful) throw IOException("Ошибка скачивания $dropboxPath (${resp.code})")
            resp.body?.bytes()
        }
    }

    suspend fun downloadToFile(
        dropboxPath: String,
        targetFile: File,
        onProgress: (Float) -> Unit = {},
    ): Boolean = withContext(Dispatchers.IO) {
        val token = authManager.getValidAccessToken()
        val req = Request.Builder()
            .url("https://content.dropboxapi.com/2/files/download")
            .header("Authorization", "Bearer $token")
            .header("Dropbox-API-Arg", """{"path":"$dropboxPath"}""")
            .post(ByteArray(0).toRequestBody(OCTET_MEDIA))
            .build()

        val tempFile = File(targetFile.parentFile, "${targetFile.name}.part")
        tempFile.parentFile?.mkdirs()

        httpClient.newCall(req).execute().use { resp ->
            if (resp.code == 409) return@withContext false
            if (!resp.isSuccessful) throw IOException("Ошибка скачивания $dropboxPath (${resp.code})")
            val body = resp.body ?: return@withContext false
            val total = body.contentLength()

            body.byteStream().use { input ->
                FileOutputStream(tempFile).use { out ->
                    val buf = ByteArray(32_768)
                    var downloaded = 0L
                    while (true) {
                        val n = input.read(buf)
                        if (n <= 0) break
                        out.write(buf, 0, n)
                        downloaded += n
                        if (total > 0L) {
                            onProgress((downloaded.toFloat() / total.toFloat()).coerceIn(0f, 1f))
                        }
                    }
                }
            }
        }
        if (targetFile.exists()) targetFile.delete()
        tempFile.renameTo(targetFile)
        onProgress(1f)
        true
    }

    suspend fun deletePathIfExists(dropboxPath: String) = withContext(Dispatchers.IO) {
        val token = authManager.getValidAccessToken()
        val req = Request.Builder()
            .url("https://api.dropboxapi.com/2/files/delete_v2")
            .header("Authorization", "Bearer $token")
            .post("""{"path":"$dropboxPath"}""".toRequestBody(JSON_MEDIA))
            .build()
        httpClient.newCall(req).execute().use { /* 409 path_lookup/not_found допустим */ }
    }

    private fun readResumeMap(): MutableMap<String, ResumableUploadCursor> {
        if (!resumeStateFile.exists()) return mutableMapOf()
        return runCatching {
            json.decodeFromString<Map<String, ResumableUploadCursor>>(resumeStateFile.readText(Charsets.UTF_8))
                .toMutableMap()
        }.getOrDefault(mutableMapOf())
    }

    private fun saveResumeCursor(path: String, cursor: ResumableUploadCursor) {
        synchronized(this) {
            val map = readResumeMap()
            map[path] = cursor
            resumeStateFile.writeText(json.encodeToString(map), Charsets.UTF_8)
        }
    }

    private fun removeResumeCursor(path: String) {
        synchronized(this) {
            val map = readResumeMap()
            if (map.remove(path) != null) {
                resumeStateFile.writeText(json.encodeToString(map), Charsets.UTF_8)
            }
        }
    }

    companion object {
        const val CLOUD_ROOT = "/MeshVault"
        const val HEADER_PATH = "$CLOUD_ROOT/vault_header.json"
        const val MANIFEST_PATH = "$CLOUD_ROOT/snapshots/manifest.mvenc"
        const val OPLOG_DIR = "$CLOUD_ROOT/oplog"
        const val THUMBS_DIR = "$CLOUD_ROOT/thumbs"
        const val BLOBS_DIR = "$CLOUD_ROOT/blobs"

        private const val MULTIPART_THRESHOLD_BYTES = 8L * 1024L * 1024L // 8 МБ
        private const val SESSION_CHUNK_BYTES = 4 * 1024 * 1024 // 4 МБ

        private val JSON_MEDIA = "application/json; charset=utf-8".toMediaType()
        private val OCTET_MEDIA = "application/octet-stream".toMediaType()
    }
}
