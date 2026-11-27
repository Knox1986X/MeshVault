package com.meshvault.crypto

import java.io.File
import java.io.InputStream
import java.io.OutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.channels.FileChannel
import java.nio.channels.SeekableByteChannel
import java.nio.file.StandardOpenOption

data class MvchHeader(
    val version: Int,
    val chunkSize: Int,
    val totalPlaintextSize: Long,
    val fileNoncePrefix: ByteArray,
) {
    val totalChunks: Int
        get() = if (totalPlaintextSize == 0L) {
            1
        } else {
            ((totalPlaintextSize + chunkSize - 1L) / chunkSize).toInt()
        }

    fun expectedEncryptedFileSize(): Long {
        if (totalPlaintextSize == 0L) {
            return (MvchStreamCipher.HEADER_BYTES + EnvelopeCiphers.TAG_BYTES).toLong()
        }
        return MvchStreamCipher.HEADER_BYTES.toLong() +
            totalPlaintextSize +
            totalChunks.toLong() * EnvelopeCiphers.TAG_BYTES
    }
}

data class MvchEncryptResult(
    val header: MvchHeader,
    val plaintextSize: Long,
    val encryptedSize: Long,
    val blake3Hash: ByteArray,
)

/**
 * Потоковый шифратор медиафайлов формата MVCH v2 с произвольным доступом O(1).
 *
 * Структура файла:
 *  - Заголовок 32 байта:
 *      [0..3]   Magic "MVCH" (0x4D 0x56 0x43 0x48)
 *      [4]      Версия = 2
 *      [5]      Степень двойки размера чанка (16 -> 64 КБ, 18 -> 256 КБ)
 *      [6..7]   Резерв (0x0000)
 *      [8..15]  Общий размер открытых данных (uint64 Big-Endian)
 *      [16..23] Случайный 64-битный префикс nonce файла
 *      [24..31] Усечённый HMAC-SHA256(K_blob, header[0..23] || fileUuid)
 *  - Последовательность чанков AES-256-GCM:
 *      IV (12 байт) = fileNoncePrefix (8 байт) || uint32BigEndian(chunkIndex)
 *      AAD          = "MVCHv2:" || fileUuid || uint32BigEndian(chunkIndex) || byte(isFinalChunk)
 */
object MvchStreamCipher {
    const val HEADER_BYTES = 32
    const val CHUNK_SIZE_64K = 65_536
    const val CHUNK_SIZE_256K = 262_144
    private const val CURRENT_VERSION = 2
    private val MAGIC = byteArrayOf(0x4D, 0x56, 0x43, 0x48) // "MVCH"

    fun encryptToFile(
        input: InputStream,
        targetFile: File,
        kBlob: ByteArray,
        fileUuid: String,
        chunkSize: Int = CHUNK_SIZE_64K,
    ): MvchEncryptResult {
        require(kBlob.size == 32) { "Ключ K_blob должен быть 32 байта" }
        val chunkShift = validateChunkShift(chunkSize)
        val noncePrefix = CryptoRandom.nextBytes(8)
        val blake3 = Blake3Hasher()

        targetFile.parentFile?.mkdirs()
        FileChannel.open(
            targetFile.toPath(),
            StandardOpenOption.CREATE,
            StandardOpenOption.WRITE,
            StandardOpenOption.TRUNCATE_EXISTING,
        ).use { channel ->
            // Резервируем 32 байта под заголовок (запишем финальный размер и HMAC после прохода)
            channel.write(ByteBuffer.allocate(HEADER_BYTES))

            var currBuf = ByteArray(chunkSize)
            var nextBuf = ByteArray(chunkSize)
            var totalPlaintext = 0L
            var totalEncrypted = HEADER_BYTES.toLong()
            var chunkIndex = 0

            try {
                var currLen = fillBuffer(input, currBuf)
                if (currLen == 0) {
                    // Пустой файл — один финальный аутентифицированный чанк нулевой длины
                    val encryptedEmpty = encryptSingleChunk(
                        kBlob = kBlob,
                        noncePrefix = noncePrefix,
                        fileUuid = fileUuid,
                        chunkIndex = 0,
                        isFinal = true,
                        plaintext = ByteArray(0),
                        plaintextLen = 0,
                    )
                    writeAll(channel, encryptedEmpty)
                    totalEncrypted += encryptedEmpty.size
                } else {
                    while (currLen > 0) {
                        blake3.update(currBuf, 0, currLen)
                        totalPlaintext += currLen
                        val nextLen = if (currLen == chunkSize) fillBuffer(input, nextBuf) else 0
                        val isFinal = (nextLen == 0)

                        val encryptedChunk = encryptSingleChunk(
                            kBlob = kBlob,
                            noncePrefix = noncePrefix,
                            fileUuid = fileUuid,
                            chunkIndex = chunkIndex,
                            isFinal = isFinal,
                            plaintext = currBuf,
                            plaintextLen = currLen,
                        )
                        writeAll(channel, encryptedChunk)
                        totalEncrypted += encryptedChunk.size
                        chunkIndex++

                        val swap = currBuf
                        currBuf = nextBuf
                        nextBuf = swap
                        currLen = nextLen
                    }
                }

                val header = MvchHeader(
                    version = CURRENT_VERSION,
                    chunkSize = 1 shl chunkShift,
                    totalPlaintextSize = totalPlaintext,
                    fileNoncePrefix = noncePrefix,
                )
                val headerBytes = encodeHeader(header, chunkShift, kBlob, fileUuid)
                channel.position(0L)
                writeAll(channel, headerBytes)

                return MvchEncryptResult(
                    header = header,
                    plaintextSize = totalPlaintext,
                    encryptedSize = totalEncrypted,
                    blake3Hash = blake3.digest(),
                )
            } finally {
                currBuf.wipe()
                nextBuf.wipe()
            }
        }
    }

    /**
     * Потоковое шифрование в произвольный [OutputStream], когда размер открытых данных известен заранее
     * (или в буфер памяти в модульных тестах).
     */
    fun encryptBytes(
        plaintext: ByteArray,
        kBlob: ByteArray,
        fileUuid: String,
        chunkSize: Int = CHUNK_SIZE_64K,
    ): ByteArray {
        require(kBlob.size == 32) { "Ключ K_blob должен быть 32 байта" }
        val chunkShift = validateChunkShift(chunkSize)
        val noncePrefix = CryptoRandom.nextBytes(8)
        val header = MvchHeader(
            version = CURRENT_VERSION,
            chunkSize = chunkSize,
            totalPlaintextSize = plaintext.size.toLong(),
            fileNoncePrefix = noncePrefix,
        )
        val out = ByteArray(header.expectedEncryptedFileSize().toInt())
        val headerBytes = encodeHeader(header, chunkShift, kBlob, fileUuid)
        System.arraycopy(headerBytes, 0, out, 0, HEADER_BYTES)
        var writePos = HEADER_BYTES

        if (plaintext.isEmpty()) {
            val enc = encryptSingleChunk(kBlob, noncePrefix, fileUuid, 0, isFinal = true, ByteArray(0), 0)
            System.arraycopy(enc, 0, out, writePos, enc.size)
            return out
        }

        val totalChunks = header.totalChunks
        for (i in 0 until totalChunks) {
            val start = i * chunkSize
            val len = minOf(chunkSize, plaintext.size - start)
            val slice = plaintext.copyOfRange(start, start + len)
            val enc = try {
                encryptSingleChunk(
                    kBlob = kBlob,
                    noncePrefix = noncePrefix,
                    fileUuid = fileUuid,
                    chunkIndex = i,
                    isFinal = (i == totalChunks - 1),
                    plaintext = slice,
                    plaintextLen = len,
                )
            } finally {
                slice.wipe()
            }
            System.arraycopy(enc, 0, out, writePos, enc.size)
            writePos += enc.size
        }
        return out
    }

    fun readHeader(channel: SeekableByteChannel, kBlob: ByteArray, fileUuid: String): MvchHeader {
        if (channel.size() < HEADER_BYTES + EnvelopeCiphers.TAG_BYTES) {
            throw CryptoAuthException("Файл MVCH повреждён или усечён")
        }
        val raw = ByteArray(HEADER_BYTES)
        channel.position(0L)
        readFully(channel, raw)
        val parsed = parseAndVerifyHeader(raw, kBlob, fileUuid)
        if (channel.size() != parsed.expectedEncryptedFileSize()) {
            throw CryptoAuthException(
                "Обнаружено усечение или дописывание файла MVCH (ожидалось ${parsed.expectedEncryptedFileSize()}, на диске ${channel.size()})",
            )
        }
        return parsed
    }

    /**
     * Мгновенно расшифровывает один чанк по индексу [chunkIndex] за O(1) без чтения предыдущих чанков.
     */
    fun decryptChunkAtIndex(
        channel: SeekableByteChannel,
        header: MvchHeader,
        kBlob: ByteArray,
        fileUuid: String,
        chunkIndex: Int,
    ): ByteArray {
        val totalChunks = header.totalChunks
        require(chunkIndex in 0 until totalChunks) {
            "Индекс чанка $chunkIndex вне диапазона 0 until $totalChunks"
        }

        val isFinal = (chunkIndex == totalChunks - 1)
        val expectedPlainLen = if (header.totalPlaintextSize == 0L) {
            0
        } else if (isFinal) {
            (header.totalPlaintextSize - chunkIndex.toLong() * header.chunkSize).toInt()
        } else {
            header.chunkSize
        }

        val encryptedFrameLen = expectedPlainLen + EnvelopeCiphers.TAG_BYTES
        val fileOffset = HEADER_BYTES.toLong() +
            chunkIndex.toLong() * (header.chunkSize + EnvelopeCiphers.TAG_BYTES).toLong()

        val encryptedFrame = ByteArray(encryptedFrameLen)
        synchronized(channel) {
            channel.position(fileOffset)
            readFully(channel, encryptedFrame)
        }

        val iv = buildChunkIv(header.fileNoncePrefix, chunkIndex)
        val aad = buildChunkAad(fileUuid, chunkIndex, isFinal)
        return try {
            EnvelopeCiphers.decryptAes256Gcm(kBlob, iv, encryptedFrame, aad)
        } finally {
            iv.wipe()
        }
    }

    /**
     * Произвольное чтение любого диапазона открытых байт [plaintextOffset .. plaintextOffset + length) в ОЗУ.
     * Используется кастомным ExoPlayer DataSource при мгновенной перемотке больших видео.
     */
    fun readPlaintextRange(
        channel: SeekableByteChannel,
        header: MvchHeader,
        kBlob: ByteArray,
        fileUuid: String,
        plaintextOffset: Long,
        target: ByteArray,
        targetOffset: Int,
        length: Int,
    ): Int {
        require(plaintextOffset >= 0L) { "Отрицательное смещение чтения: $plaintextOffset" }
        if (length == 0) return 0
        if (header.totalPlaintextSize == 0L) {
            // Всё равно проверяем целостность пустого чанка 0
            decryptChunkAtIndex(channel, header, kBlob, fileUuid, 0)
            return -1
        }
        if (plaintextOffset >= header.totalPlaintextSize) return -1

        val maxReadable = minOf(length.toLong(), header.totalPlaintextSize - plaintextOffset).toInt()
        var copied = 0
        var currPlainPos = plaintextOffset

        while (copied < maxReadable) {
            val chunkIdx = (currPlainPos / header.chunkSize).toInt()
            val inChunkOffset = (currPlainPos % header.chunkSize).toInt()
            val plainChunk = decryptChunkAtIndex(channel, header, kBlob, fileUuid, chunkIdx)
            try {
                val available = plainChunk.size - inChunkOffset
                val toCopy = minOf(available, maxReadable - copied)
                System.arraycopy(plainChunk, inChunkOffset, target, targetOffset + copied, toCopy)
                copied += toCopy
                currPlainPos += toCopy
            } finally {
                plainChunk.wipe()
            }
        }
        return copied
    }

    private fun encryptSingleChunk(
        kBlob: ByteArray,
        noncePrefix: ByteArray,
        fileUuid: String,
        chunkIndex: Int,
        isFinal: Boolean,
        plaintext: ByteArray,
        plaintextLen: Int,
    ): ByteArray {
        val slice = if (plaintextLen == plaintext.size) plaintext else plaintext.copyOf(plaintextLen)
        val iv = buildChunkIv(noncePrefix, chunkIndex)
        val aad = buildChunkAad(fileUuid, chunkIndex, isFinal)
        return try {
            EnvelopeCiphers.encryptAes256Gcm(kBlob, iv, slice, aad)
        } finally {
            iv.wipe()
            if (slice !== plaintext) slice.wipe()
        }
    }

    private fun encodeHeader(
        header: MvchHeader,
        chunkShift: Int,
        kBlob: ByteArray,
        fileUuid: String,
    ): ByteArray {
        val raw = ByteArray(HEADER_BYTES)
        val bb = ByteBuffer.wrap(raw).order(ByteOrder.BIG_ENDIAN)
        bb.put(MAGIC)
        bb.put(header.version.toByte())
        bb.put(chunkShift.toByte())
        bb.putShort(0)
        bb.putLong(header.totalPlaintextSize)
        bb.put(header.fileNoncePrefix)
        val tag8 = computeHeaderMac8(raw, kBlob, fileUuid)
        bb.put(tag8)
        return raw
    }

    private fun parseAndVerifyHeader(raw: ByteArray, kBlob: ByteArray, fileUuid: String): MvchHeader {
        if (raw.size != HEADER_BYTES) throw CryptoAuthException("Неверная длина заголовка MVCH")
        for (i in MAGIC.indices) {
            if (raw[i] != MAGIC[i]) throw CryptoAuthException("Неверная сигнатура файла (ожидался MVCH)")
        }
        val expectedMac8 = computeHeaderMac8(raw, kBlob, fileUuid)
        val actualMac8 = raw.copyOfRange(24, 32)
        if (!constantTimeEquals(expectedMac8, actualMac8)) {
            throw CryptoAuthException("Нарушена целостность заголовка MVCH или подменён идентификатор файла")
        }

        val bb = ByteBuffer.wrap(raw).order(ByteOrder.BIG_ENDIAN)
        bb.position(4)
        val version = bb.get().toInt() and 0xFF
        if (version != CURRENT_VERSION) {
            throw CryptoAuthException("Неподдерживаемая версия контейнера MVCH: $version")
        }
        val chunkShift = bb.get().toInt() and 0xFF
        if (chunkShift !in 12..22) {
            throw CryptoAuthException("Некорректный размер чанка в заголовке MVCH")
        }
        bb.short // reserved
        val totalPlaintextSize = bb.long
        if (totalPlaintextSize < 0L) {
            throw CryptoAuthException("Отрицательный размер файла в заголовке MVCH")
        }
        val noncePrefix = ByteArray(8)
        bb.get(noncePrefix)

        return MvchHeader(
            version = version,
            chunkSize = 1 shl chunkShift,
            totalPlaintextSize = totalPlaintextSize,
            fileNoncePrefix = noncePrefix,
        )
    }

    private fun computeHeaderMac8(headerRaw: ByteArray, kBlob: ByteArray, fileUuid: String): ByteArray {
        val uuidBytes = fileUuid.toByteArray(Charsets.UTF_8)
        val macInput = ByteArray(24 + uuidBytes.size)
        System.arraycopy(headerRaw, 0, macInput, 0, 24)
        System.arraycopy(uuidBytes, 0, macInput, 24, uuidBytes.size)
        val fullMac = HkdfSha256.hmacSha256(kBlob, macInput)
        val truncated = fullMac.copyOf(8)
        fullMac.wipe()
        return truncated
    }

    private fun buildChunkIv(noncePrefix8: ByteArray, chunkIndex: Int): ByteArray {
        val iv = ByteArray(12)
        System.arraycopy(noncePrefix8, 0, iv, 0, 8)
        iv[8] = ((chunkIndex ushr 24) and 0xFF).toByte()
        iv[9] = ((chunkIndex ushr 16) and 0xFF).toByte()
        iv[10] = ((chunkIndex ushr 8) and 0xFF).toByte()
        iv[11] = (chunkIndex and 0xFF).toByte()
        return iv
    }

    private fun buildChunkAad(fileUuid: String, chunkIndex: Int, isFinal: Boolean): ByteArray {
        val uuidBytes = fileUuid.toByteArray(Charsets.UTF_8)
        val prefix = "MVCHv2:".toByteArray(Charsets.UTF_8)
        val buf = ByteBuffer.allocate(prefix.size + uuidBytes.size + 4 + 1).order(ByteOrder.BIG_ENDIAN)
        buf.put(prefix)
        buf.put(uuidBytes)
        buf.putInt(chunkIndex)
        buf.put(if (isFinal) 1.toByte() else 0.toByte())
        return buf.array()
    }

    private fun validateChunkShift(chunkSize: Int): Int {
        require(chunkSize > 0 && (chunkSize and (chunkSize - 1)) == 0) {
            "Размер чанка должен быть степенью двойки: $chunkSize"
        }
        val shift = Integer.numberOfTrailingZeros(chunkSize)
        require(shift in 12..22) { "Размер чанка должен быть в пределах 4 КБ .. 4 МБ" }
        return shift
    }

    private fun fillBuffer(input: InputStream, target: ByteArray): Int {
        var total = 0
        while (total < target.size) {
            val read = input.read(target, total, target.size - total)
            if (read < 0) break
            total += read
        }
        return total
    }

    private fun writeAll(channel: FileChannel, bytes: ByteArray) {
        val buf = ByteBuffer.wrap(bytes)
        while (buf.hasRemaining()) {
            channel.write(buf)
        }
    }

    private fun readFully(channel: SeekableByteChannel, dst: ByteArray) {
        val buf = ByteBuffer.wrap(dst)
        while (buf.hasRemaining()) {
            val n = channel.read(buf)
            if (n < 0) throw CryptoAuthException("Неожиданный конец зашифрованного контейнера MVCH")
        }
    }
}
