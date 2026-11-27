package com.meshvault.crypto

import java.io.InputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * RFC 5869 HKDF-SHA256 для строго изолированного вывода подключей из Vault Master Key (VMK).
 */
object HkdfSha256 {
    private const val HASH_LEN = 32
    private const val HMAC_ALGO = "HmacSHA256"

    private val DOMAIN_SALT = "MeshVault-HKDF-Salt-v2".toByteArray(Charsets.UTF_8)
    private val INFO_DB = "meshvault/v2/sqlcipher-db".toByteArray(Charsets.UTF_8)
    private val INFO_META = "meshvault/v2/meta-aead".toByteArray(Charsets.UTF_8)
    private val INFO_BLOB = "meshvault/v2/blob-mvch".toByteArray(Charsets.UTF_8)
    private val INFO_THUMB = "meshvault/v2/thumb-webp".toByteArray(Charsets.UTF_8)
    private val INFO_MAC = "meshvault/v2/blind-hmac".toByteArray(Charsets.UTF_8)

    fun extract(salt: ByteArray?, ikm: ByteArray): ByteArray {
        val actualSalt = if (salt == null || salt.isEmpty()) ByteArray(HASH_LEN) else salt
        return hmacSha256(actualSalt, ikm)
    }

    fun expand(prk: ByteArray, info: ByteArray, length: Int): ByteArray {
        require(prk.size >= HASH_LEN) { "PRK слишком короткий для HKDF-SHA256" }
        require(length in 1..(255 * HASH_LEN)) { "Некорректная длина выходного ключа HKDF: $length" }

        val n = (length + HASH_LEN - 1) / HASH_LEN
        val okm = ByteArray(length)
        var tPrev = ByteArray(0)
        var generated = 0

        try {
            for (i in 1..n) {
                val mac = Mac.getInstance(HMAC_ALGO)
                mac.init(SecretKeySpec(prk, HMAC_ALGO))
                mac.update(tPrev)
                mac.update(info)
                mac.update(i.toByte())
                val tNext = mac.doFinal()
                tPrev.wipe()
                tPrev = tNext

                val toCopy = minOf(HASH_LEN, length - generated)
                System.arraycopy(tPrev, 0, okm, generated, toCopy)
                generated += toCopy
            }
            return okm
        } finally {
            tPrev.wipe()
        }
    }

    fun deriveSubkey(ikm: ByteArray, salt: ByteArray? = DOMAIN_SALT, info: ByteArray, length: Int = 32): ByteArray {
        val prk = extract(salt, ikm)
        return try {
            expand(prk, info, length)
        } finally {
            prk.wipe()
        }
    }

    fun deriveSessionHierarchy(contour: VaultContour, vmkBytes: ByteArray): VaultSessionKeys {
        require(vmkBytes.size == 32) { "VMK должен быть ровно 256 бит (32 байта)" }
        val prk = extract(DOMAIN_SALT, vmkBytes)
        try {
            val kDb = expand(prk, INFO_DB, 32)
            val kMeta = expand(prk, INFO_META, 32)
            val kBlob = expand(prk, INFO_BLOB, 32)
            val kThumb = expand(prk, INFO_THUMB, 32)
            val kMac = expand(prk, INFO_MAC, 32)
            return VaultSessionKeys(
                contour = contour,
                vmk = SecureBytes.copyFrom(vmkBytes),
                kDb = SecureBytes.wrapTakingOwnership(kDb),
                kMeta = SecureBytes.wrapTakingOwnership(kMeta),
                kBlob = SecureBytes.wrapTakingOwnership(kBlob),
                kThumb = SecureBytes.wrapTakingOwnership(kThumb),
                kMac = SecureBytes.wrapTakingOwnership(kMac),
            )
        } finally {
            prk.wipe()
        }
    }

    fun hmacSha256(key: ByteArray, message: ByteArray): ByteArray {
        val mac = Mac.getInstance(HMAC_ALGO)
        val keySpec = SecretKeySpec(key, HMAC_ALGO)
        mac.init(keySpec)
        return mac.doFinal(message)
    }
}

/**
 * Слепое HMAC-индексирование (K_mac): позволяет искать точные побайтовые дубликаты
 * и формировать префиксы шардов в Dropbox без раскрытия оригинального BLAKE3/SHA-256 облаку.
 */
object BlindIndex {
    fun computeBlindHex(kMac: ByteArray, domain: String, rawValue: ByteArray): String {
        val domainBytes = "$domain:".toByteArray(Charsets.UTF_8)
        val combined = ByteArray(domainBytes.size + rawValue.size)
        System.arraycopy(domainBytes, 0, combined, 0, domainBytes.size)
        System.arraycopy(rawValue, 0, combined, domainBytes.size, rawValue.size)
        return try {
            val tag = HkdfSha256.hmacSha256(kMac, combined)
            val hex = HexCodec.encode(tag)
            tag.wipe()
            hex
        } finally {
            combined.wipe()
        }
    }

    fun cloudShardPrefix(kMac: ByteArray, objectId: String): String {
        val tag = HkdfSha256.hmacSha256(kMac, objectId.toByteArray(Charsets.UTF_8))
        val prefix = HexCodec.encode(tag, 0, 1) // 2 hex-символа (256 бакетов: 00..ff)
        tag.wipe()
        return prefix
    }
}

object HexCodec {
    private val HEX_CHARS = "0123456789abcdef".toCharArray()

    fun encode(bytes: ByteArray, offset: Int = 0, length: Int = bytes.size - offset): String {
        val out = CharArray(length * 2)
        for (i in 0 until length) {
            val v = bytes[offset + i].toInt() and 0xFF
            out[i * 2] = HEX_CHARS[v ushr 4]
            out[i * 2 + 1] = HEX_CHARS[v and 0x0F]
        }
        return String(out)
    }

    fun decode(hex: String): ByteArray {
        val clean = hex.trim()
        require(clean.length % 2 == 0) { "Нечётная длина hex-строки" }
        val out = ByteArray(clean.length / 2)
        for (i in out.indices) {
            val hi = Character.digit(clean[i * 2], 16)
            val lo = Character.digit(clean[i * 2 + 1], 16)
            require(hi >= 0 && lo >= 0) { "Недопустимый hex-символ" }
            out[i] = ((hi shl 4) or lo).toByte()
        }
        return out
    }
}

/**
 * Криптографический хэш BLAKE3 (256-бит) на чистом Kotlin (совместим со спецификацией BLAKE3,
 * потоковая обработка чанков по 1024 байта и редукция бинарного дерева Меркла).
 */
class Blake3Hasher {
    private val cvStack = Array(54) { IntArray(8) }
    private var cvStackLen = 0
    private var chunkState = ChunkState(IV, 0L)

    fun update(input: ByteArray, offset: Int = 0, length: Int = input.size - offset): Blake3Hasher {
        var currOffset = offset
        var remaining = length
        while (remaining > 0) {
            if (chunkState.len() == CHUNK_LEN) {
                val chunkCv = chunkState.output().chainingValue()
                val totalChunks = chunkState.chunkCounter + 1L
                addChunkChainingValue(chunkCv, totalChunks)
                chunkState = ChunkState(IV, totalChunks)
            }
            val want = CHUNK_LEN - chunkState.len()
            val take = minOf(want, remaining)
            chunkState.update(input, currOffset, take)
            currOffset += take
            remaining -= take
        }
        return this
    }

    fun digest(): ByteArray {
        var output = chunkState.output()
        var parentNodesRemaining = cvStackLen
        while (parentNodesRemaining > 0) {
            parentNodesRemaining--
            output = parentOutput(cvStack[parentNodesRemaining], output.chainingValue())
        }
        return output.rootOutputBytes(32)
    }

    private fun addChunkChainingValue(firstCv: IntArray, totalChunksInit: Long) {
        var newCv = firstCv
        var totalChunks = totalChunksInit
        while ((totalChunks and 1L) == 0L) {
            cvStackLen--
            newCv = parentOutput(cvStack[cvStackLen], newCv).chainingValue()
            totalChunks = totalChunks ushr 1
        }
        System.arraycopy(newCv, 0, cvStack[cvStackLen], 0, 8)
        cvStackLen++
    }

    private class Output(
        val inputChainingValue: IntArray,
        val blockWords: IntArray,
        val counter: Long,
        val blockLen: Int,
        val flags: Int,
    ) {
        fun chainingValue(): IntArray {
            val out16 = compress(inputChainingValue, blockWords, counter, blockLen, flags)
            return out16.copyOf(8)
        }

        fun rootOutputBytes(outLen: Int): ByteArray {
            val out = ByteArray(outLen)
            var outputBlockCounter = 0L
            var pos = 0
            while (pos < outLen) {
                val words = compress(inputChainingValue, blockWords, outputBlockCounter, blockLen, flags or FLAG_ROOT)
                val bb = ByteBuffer.allocate(64).order(ByteOrder.LITTLE_ENDIAN)
                for (w in words) bb.putInt(w)
                val blockBytes = bb.array()
                val take = minOf(64, outLen - pos)
                System.arraycopy(blockBytes, 0, out, pos, take)
                pos += take
                outputBlockCounter++
            }
            return out
        }
    }

    private class ChunkState(keyWords: IntArray, val chunkCounter: Long) {
        private var chainingValue = keyWords.copyOf()
        private val block = ByteArray(BLOCK_LEN)
        private var blockLen = 0
        private var blocksCompressed = 0

        fun len(): Int = BLOCK_LEN * blocksCompressed + blockLen

        private fun startFlag(): Int = if (blocksCompressed == 0) FLAG_CHUNK_START else 0

        fun update(input: ByteArray, offset: Int, length: Int) {
            var pos = offset
            var rem = length
            while (rem > 0) {
                if (blockLen == BLOCK_LEN) {
                    val words = bytesToWords(block)
                    chainingValue = compress(
                        chainingValue,
                        words,
                        chunkCounter,
                        BLOCK_LEN,
                        startFlag(),
                    ).copyOf(8)
                    blocksCompressed++
                    block.wipe()
                    blockLen = 0
                }
                val want = BLOCK_LEN - blockLen
                val take = minOf(want, rem)
                System.arraycopy(input, pos, block, blockLen, take)
                blockLen += take
                pos += take
                rem -= take
            }
        }

        fun output(): Output {
            val words = bytesToWords(block)
            return Output(
                inputChainingValue = chainingValue,
                blockWords = words,
                counter = chunkCounter,
                blockLen = blockLen,
                flags = startFlag() or FLAG_CHUNK_END,
            )
        }
    }

    companion object {
        private const val BLOCK_LEN = 64
        private const val CHUNK_LEN = 1024
        private const val FLAG_CHUNK_START = 1
        private const val FLAG_CHUNK_END = 2
        private const val FLAG_PARENT = 4
        private const val FLAG_ROOT = 8

        private val IV = intArrayOf(
            0x6A09E667,
            -0x4498517B, // 0xBB67AE85
            0x3C6EF372,
            -0x5AB00AC6, // 0xA54FF53A
            0x510E527F,
            -0x64FA9774, // 0x9B05688C
            0x1F83D9AB,
            0x5BE0CD19,
        )

        private val MSG_PERMUTATION = intArrayOf(2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8)

        fun hash(bytes: ByteArray): ByteArray = Blake3Hasher().update(bytes).digest()

        fun hashStream(stream: InputStream): ByteArray {
            val hasher = Blake3Hasher()
            val buf = ByteArray(16_384)
            while (true) {
                val n = stream.read(buf)
                if (n <= 0) break
                hasher.update(buf, 0, n)
            }
            buf.wipe()
            return hasher.digest()
        }

        private fun parentOutput(leftChildCv: IntArray, rightChildCv: IntArray): Output {
            val blockWords = IntArray(16)
            System.arraycopy(leftChildCv, 0, blockWords, 0, 8)
            System.arraycopy(rightChildCv, 0, blockWords, 8, 8)
            return Output(
                inputChainingValue = IV,
                blockWords = blockWords,
                counter = 0L,
                blockLen = BLOCK_LEN,
                flags = FLAG_PARENT,
            )
        }

        private fun bytesToWords(block: ByteArray): IntArray {
            val out = IntArray(16)
            val bb = ByteBuffer.wrap(block).order(ByteOrder.LITTLE_ENDIAN)
            for (i in 0 until 16) out[i] = bb.int
            return out
        }

        private fun compress(
            cv: IntArray,
            blockWords: IntArray,
            counter: Long,
            blockLen: Int,
            flags: Int,
        ): IntArray {
            val state = intArrayOf(
                cv[0], cv[1], cv[2], cv[3],
                cv[4], cv[5], cv[6], cv[7],
                IV[0], IV[1], IV[2], IV[3],
                counter.toInt(),
                (counter ushr 32).toInt(),
                blockLen,
                flags,
            )
            var m = blockWords.copyOf()
            for (r in 0 until 7) {
                round(state, m)
                if (r < 6) {
                    val permuted = IntArray(16)
                    for (i in 0 until 16) permuted[i] = m[MSG_PERMUTATION[i]]
                    m = permuted
                }
            }
            for (i in 0 until 8) {
                state[i] = state[i] xor state[i + 8]
                state[i + 8] = state[i + 8] xor cv[i]
            }
            return state
        }

        private fun round(state: IntArray, m: IntArray) {
            g(state, 0, 4, 8, 12, m[0], m[1])
            g(state, 1, 5, 9, 13, m[2], m[3])
            g(state, 2, 6, 10, 14, m[4], m[5])
            g(state, 3, 7, 11, 15, m[6], m[7])
            g(state, 0, 5, 10, 15, m[8], m[9])
            g(state, 1, 6, 11, 12, m[10], m[11])
            g(state, 2, 7, 8, 13, m[12], m[13])
            g(state, 3, 4, 9, 14, m[14], m[15])
        }

        private fun g(state: IntArray, a: Int, b: Int, c: Int, d: Int, mx: Int, my: Int) {
            state[a] = state[a] + state[b] + mx
            state[d] = (state[d] xor state[a]).rotateRight(16)
            state[c] = state[c] + state[d]
            state[b] = (state[b] xor state[c]).rotateRight(12)
            state[a] = state[a] + state[b] + my
            state[d] = (state[d] xor state[a]).rotateRight(8)
            state[c] = state[c] + state[d]
            state[b] = (state[b] xor state[c]).rotateRight(7)
        }
    }
}
