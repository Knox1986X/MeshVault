package com.meshvault.data.media

import android.media.MediaDataSource
import android.net.Uri
import androidx.annotation.OptIn
import androidx.media3.common.C
import androidx.media3.common.util.UnstableApi
import androidx.media3.datasource.BaseDataSource
import androidx.media3.datasource.DataSource
import androidx.media3.datasource.DataSpec
import com.meshvault.crypto.MvchHeader
import com.meshvault.crypto.MvchStreamCipher
import com.meshvault.crypto.VaultSessionKeys
import com.meshvault.crypto.wipe
import java.io.File
import java.io.IOException
import java.nio.channels.FileChannel
import java.nio.file.StandardOpenOption
import kotlin.math.min

/**
 * Кастомный потоковый источник Media3 (ExoPlayer) для зашифрованных контейнеров MVCH v2.
 *
 * Ключевое преимущество над Cryptomator:
 * При перемотке 500-мегабайтного видео на любую секунду ExoPlayer передаёт смещение в [open],
 * а [MvchExoPlayerDataSource] мгновенно за O(1) вычисляет индекс нужного 64 КБ чанка и расшифровывает
 * ТОЛЬКО его прямо в оперативной памяти — ни одного временного расшифрованного файла во флеш-памяти!
 */
@OptIn(UnstableApi::class)
class MvchExoPlayerDataSource(
    private val session: VaultSessionKeys,
    private val resolveEncryptedFile: (mediaId: String) -> File,
) : BaseDataSource(false) {

    private var currentUri: Uri? = null
    private var currentMediaId: String? = null
    private var channel: FileChannel? = null
    private var header: MvchHeader? = null

    private var currentPlainPosition: Long = 0L
    private var bytesRemaining: Long = 0L

    // Одночанковый буфер в ОЗУ (64 КБ), зануляемый при смене чанка или закрытии потока
    private var cachedChunkIndex: Int = -1
    private var cachedChunkPlaintext: ByteArray? = null

    override fun open(dataSpec: DataSpec): Long {
        val uri = dataSpec.uri
        val mediaId = extractMediaId(uri)
        currentUri = uri
        currentMediaId = mediaId

        transferInitializing(dataSpec)

        val encFile = resolveEncryptedFile(mediaId)
        if (!encFile.exists()) {
            throw IOException("Зашифрованный медиафайл не найден локально: $mediaId")
        }

        val fc = FileChannel.open(encFile.toPath(), StandardOpenOption.READ)
        val parsedHeader = try {
            session.withBlobKey { kBlob ->
                MvchStreamCipher.readHeader(fc, kBlob, mediaId)
            }
        } catch (t: Throwable) {
            fc.close()
            throw IOException("Ошибка проверки заголовка MVCH: ${t.message}", t)
        }

        if (dataSpec.position > parsedHeader.totalPlaintextSize) {
            fc.close()
            throw IOException("Смещение за пределами зашифрованного потока MVCH")
        }

        channel = fc
        header = parsedHeader
        currentPlainPosition = dataSpec.position
        bytesRemaining = if (dataSpec.length != C.LENGTH_UNSET.toLong()) {
            dataSpec.length
        } else {
            parsedHeader.totalPlaintextSize - dataSpec.position
        }

        transferStarted(dataSpec)
        return bytesRemaining
    }

    override fun read(buffer: ByteArray, offset: Int, length: Int): Int {
        if (length == 0) return 0
        if (bytesRemaining == 0L) return C.RESULT_END_OF_INPUT

        val hdr = header ?: throw IOException("Поток MVCH не открыт")
        val fc = channel ?: throw IOException("Канал файла MVCH закрыт")
        val mediaId = currentMediaId ?: throw IOException("Отсутствует идентификатор медиафайла")

        if (currentPlainPosition >= hdr.totalPlaintextSize) {
            bytesRemaining = 0L
            return C.RESULT_END_OF_INPUT
        }

        val toReadMax = min(length.toLong(), bytesRemaining).toInt()
        val targetChunkIdx = (currentPlainPosition / hdr.chunkSize).toInt()
        val inChunkOffset = (currentPlainPosition % hdr.chunkSize).toInt()

        val plainChunk = try {
            getOrDecryptChunk(fc, hdr, mediaId, targetChunkIdx)
        } catch (t: Throwable) {
            throw IOException("Ошибка аутентификации чанка #$targetChunkIdx: ${t.message}", t)
        }

        val availableInChunk = plainChunk.size - inChunkOffset
        if (availableInChunk <= 0) return C.RESULT_END_OF_INPUT

        val copied = min(toReadMax, availableInChunk)
        System.arraycopy(plainChunk, inChunkOffset, buffer, offset, copied)

        currentPlainPosition += copied
        bytesRemaining -= copied
        bytesTransferred(copied)
        return copied
    }

    override fun getUri(): Uri? = currentUri

    override fun close() {
        currentUri = null
        currentMediaId = null
        header = null
        cachedChunkIndex = -1
        cachedChunkPlaintext?.wipe()
        cachedChunkPlaintext = null

        val fc = channel
        channel = null
        try {
            fc?.close()
        } finally {
            if (fc != null) {
                transferEnded()
            }
        }
    }

    private fun getOrDecryptChunk(
        fc: FileChannel,
        hdr: MvchHeader,
        mediaId: String,
        chunkIndex: Int,
    ): ByteArray {
        val existing = cachedChunkPlaintext
        if (cachedChunkIndex == chunkIndex && existing != null) {
            return existing
        }
        existing?.wipe()
        val decrypted = session.withBlobKey { kBlob ->
            MvchStreamCipher.decryptChunkAtIndex(fc, hdr, kBlob, mediaId, chunkIndex)
        }
        cachedChunkIndex = chunkIndex
        cachedChunkPlaintext = decrypted
        return decrypted
    }

    @OptIn(UnstableApi::class)
    class Factory(
        private val session: VaultSessionKeys,
        private val resolveEncryptedFile: (mediaId: String) -> File,
    ) : DataSource.Factory {
        override fun createDataSource(): DataSource =
            MvchExoPlayerDataSource(session, resolveEncryptedFile)
    }

    companion object {
        const val SCHEME = "mvch"

        fun buildUri(mediaId: String): Uri = Uri.parse("$SCHEME://media/$mediaId")

        private fun extractMediaId(uri: Uri): String =
            uri.lastPathSegment?.takeIf { it.isNotBlank() }
                ?: throw IOException("Некорректный URI зашифрованного потока: $uri")
    }
}

/**
 * Потоковый `android.media.MediaDataSource` поверх MVCH v2 для `MediaMetadataRetriever`:
 * позволяет извлекать точные стоп-кадры видео и метаданные FPS/длительности прямо в ОЗУ без временных файлов.
 */
class MvchAndroidMediaDataSource(
    encryptedFile: File,
    private val session: VaultSessionKeys,
    private val mediaId: String,
) : MediaDataSource() {

    private val channel: FileChannel = FileChannel.open(encryptedFile.toPath(), StandardOpenOption.READ)
    private val header: MvchHeader = session.withBlobKey { kBlob ->
        MvchStreamCipher.readHeader(channel, kBlob, mediaId)
    }

    private var cachedIdx: Int = -1
    private var cachedChunk: ByteArray? = null

    @Synchronized
    override fun readAt(position: Long, buffer: ByteArray, offset: Int, size: Int): Int {
        if (size == 0) return 0
        if (position < 0L || position >= header.totalPlaintextSize) return -1

        val maxLen = min(size.toLong(), header.totalPlaintextSize - position).toInt()
        var totalCopied = 0
        var pos = position

        while (totalCopied < maxLen) {
            val chunkIdx = (pos / header.chunkSize).toInt()
            val inChunk = (pos % header.chunkSize).toInt()
            val chunk = if (chunkIdx == cachedIdx && cachedChunk != null) {
                cachedChunk!!
            } else {
                cachedChunk?.wipe()
                val dec = session.withBlobKey { kBlob ->
                    MvchStreamCipher.decryptChunkAtIndex(channel, header, kBlob, mediaId, chunkIdx)
                }
                cachedIdx = chunkIdx
                cachedChunk = dec
                dec
            }
            val take = min(chunk.size - inChunk, maxLen - totalCopied)
            if (take <= 0) break
            System.arraycopy(chunk, inChunk, buffer, offset + totalCopied, take)
            totalCopied += take
            pos += take
        }
        return if (totalCopied == 0) -1 else totalCopied
    }

    override fun getSize(): Long = header.totalPlaintextSize

    @Synchronized
    override fun close() {
        cachedIdx = -1
        cachedChunk?.wipe()
        cachedChunk = null
        channel.close()
    }
}
