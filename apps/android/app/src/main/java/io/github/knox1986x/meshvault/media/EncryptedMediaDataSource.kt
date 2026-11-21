package io.github.knox1986x.meshvault.media

import android.net.Uri
import androidx.media3.common.C
import androidx.media3.common.util.UnstableApi
import androidx.media3.datasource.BaseDataSource
import androidx.media3.datasource.DataSpec
import io.github.knox1986x.meshvault.security.VaultBackend
import java.io.IOException
import kotlin.math.min

/**
 * Custom Media3 DataSource streaming decrypted 1 MiB chunks directly from RAM
 * with O(1) random seek and zero plaintext temporary files on flash storage.
 */
@UnstableApi
class EncryptedMediaDataSource(
    private val backend: VaultBackend,
    private val mediaId: String,
    private val totalPlaintextBytes: Long,
    private val chunkSizeBytes: Long = 1024L * 1024L,
) : BaseDataSource(/* isNetwork = */ false) {

    private var currentUri: Uri? = null
    private var position: Long = 0L
    private var bytesRemaining: Long = 0L
    private var cachedChunkIndex: Long = -1L
    private var cachedChunkData: ByteArray = ByteArray(0)
    private var opened: Boolean = false

    override fun open(dataSpec: DataSpec): Long {
        currentUri = dataSpec.uri
        transferInitializing(dataSpec)

        if (dataSpec.position < 0 || dataSpec.position > totalPlaintextBytes) {
            throw IOException("Seek position out of range")
        }

        position = dataSpec.position
        val available = totalPlaintextBytes - position
        bytesRemaining = if (dataSpec.length == C.LENGTH_UNSET.toLong()) {
            available
        } else {
            min(dataSpec.length, available)
        }
        opened = true
        transferStarted(dataSpec)
        return bytesRemaining
    }

    override fun read(buffer: ByteArray, offset: Int, length: Int): Int {
        if (length == 0) return 0
        if (bytesRemaining <= 0) return C.RESULT_END_OF_INPUT

        val targetChunkIndex = position / chunkSizeBytes
        if (targetChunkIndex != cachedChunkIndex) {
            cachedChunkData.fill(0)
            cachedChunkData = backend.readMediaChunk(mediaId, targetChunkIndex)
            cachedChunkIndex = targetChunkIndex
        }

        val inChunkOffset = (position % chunkSizeBytes).toInt()
        if (inChunkOffset >= cachedChunkData.size) {
            return C.RESULT_END_OF_INPUT
        }

        val toCopy = min(
            min(length.toLong(), bytesRemaining),
            (cachedChunkData.size - inChunkOffset).toLong()
        ).toInt()

        System.arraycopy(cachedChunkData, inChunkOffset, buffer, offset, toCopy)
        position += toCopy
        bytesRemaining -= toCopy
        bytesTransferred(toCopy)
        return toCopy
    }

    override fun getUri(): Uri? = currentUri

    override fun close() {
        cachedChunkData.fill(0)
        cachedChunkData = ByteArray(0)
        cachedChunkIndex = -1L
        currentUri = null
        if (opened) {
            opened = false
            transferEnded()
        }
    }
}
