package com.meshvault.crypto

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.Serializable
import java.nio.ByteBuffer
import java.nio.ByteOrder
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

@Serializable
enum class KdfAlgorithm {
    ARGON2ID,
    PBKDF2_HMAC_SHA256,
}

@Serializable
data class KdfConfig(
    val algorithm: KdfAlgorithm = KdfAlgorithm.ARGON2ID,
    val memoryKiB: Int = 65_536, // 64 МБ RAM по умолчанию
    val iterations: Int = 3,
    val parallelism: Int = 4,
    val pbkdf2Iterations: Int = 600_000,
) {
    companion object {
        val PRODUCTION_DEFAULT = KdfConfig(
            algorithm = KdfAlgorithm.ARGON2ID,
            memoryKiB = 65_536,
            iterations = 3,
            parallelism = 4,
        )
        val BALANCED_MOBILE = KdfConfig(
            algorithm = KdfAlgorithm.ARGON2ID,
            memoryKiB = 32_768,
            iterations = 3,
            parallelism = 4,
        )
        val FAST_TEST = KdfConfig(
            algorithm = KdfAlgorithm.ARGON2ID,
            memoryKiB = 4_096,
            iterations = 2,
            parallelism = 2,
        )
    }
}

/**
 * Полноценная реализация RFC 9106 Argon2id (v=0x13, type=2) с параллельной обработкой сегментов
 * и гарантированным занулением всей матрицы памяти (anti-forensics) сразу после вывода KEK,
 * а также резервным контуром PBKDF2-HMAC-SHA256.
 */
object Argon2idKdf {
    private const val ARGON2_VERSION = 0x13
    private const val ARGON2_TYPE_ID = 2
    private const val BLOCK_LONGS = 128 // 1024 байта = 128 * 8
    private const val SYNC_POINTS = 4

    fun deriveKek(
        password: CharArray,
        salt: ByteArray,
        config: KdfConfig,
        outputLength: Int = 32,
    ): ByteArray {
        require(salt.size >= 8) { "Соль должна быть не короче 8 байт (рекомендуется 32 байта)" }
        require(outputLength in 16..64) { "Длина KEK должна быть от 16 до 64 байт" }

        if (config.algorithm == KdfAlgorithm.PBKDF2_HMAC_SHA256) {
            return derivePbkdf2(password, salt, config.pbkdf2Iterations, outputLength)
        }

        val pwdBytes = charArrayToUtf8Bytes(password)
        return try {
            deriveArgon2idRaw(
                password = pwdBytes,
                salt = salt,
                secret = ByteArray(0),
                associatedData = ByteArray(0),
                iterations = config.iterations,
                memoryKiB = config.memoryKiB,
                parallelism = config.parallelism,
                tagLength = outputLength,
            )
        } catch (_: OutOfMemoryError) {
            // Защитный откат при критической нехватке кучи на экстремально слабом устройстве
            if (config.memoryKiB > 16_384) {
                deriveArgon2idRaw(
                    password = pwdBytes,
                    salt = salt,
                    secret = ByteArray(0),
                    associatedData = ByteArray(0),
                    iterations = maxOf(config.iterations, 4),
                    memoryKiB = 16_384,
                    parallelism = config.parallelism,
                    tagLength = outputLength,
                )
            } else {
                derivePbkdf2(password, salt, config.pbkdf2Iterations, outputLength)
            }
        } finally {
            pwdBytes.wipe()
        }
    }

    fun derivePbkdf2(
        password: CharArray,
        salt: ByteArray,
        iterations: Int = 600_000,
        outputLength: Int = 32,
    ): ByteArray {
        val spec = PBEKeySpec(password, salt, iterations, outputLength * 8)
        return try {
            val skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
            skf.generateSecret(spec).encoded
        } finally {
            spec.clearPassword()
        }
    }

    /**
     * Низкоуровневая функция RFC 9106 Argon2id (поддерживает secret и associatedData для векторного тестирования RFC 9106).
     */
    fun deriveArgon2idRaw(
        password: ByteArray,
        salt: ByteArray,
        secret: ByteArray = ByteArray(0),
        associatedData: ByteArray = ByteArray(0),
        iterations: Int,
        memoryKiB: Int,
        parallelism: Int,
        tagLength: Int = 32,
    ): ByteArray {
        require(parallelism >= 1) { "parallelism >= 1" }
        require(iterations >= 1) { "iterations >= 1" }
        require(memoryKiB >= 8 * parallelism) { "memoryKiB должно быть >= 8 * parallelism" }
        require(tagLength >= 4) { "tagLength >= 4" }

        val lanes = parallelism
        val memoryBlocks = 4 * lanes * (memoryKiB / (4 * lanes))
        val laneLength = memoryBlocks / lanes
        val segmentLength = laneLength / SYNC_POINTS

        // Плоский массив всех 1024-байтных блоков: blocks[blockIndex * 128 + word]
        val slab = LongArray(memoryBlocks * BLOCK_LONGS)
        val h0 = computeInitialHashH0(
            parallelism = lanes,
            tagLength = tagLength,
            memoryKiB = memoryKiB,
            iterations = iterations,
            password = password,
            salt = salt,
            secret = secret,
            associatedData = associatedData,
        )

        try {
            // Инициализация первых двух столбцов каждой полосы B[i][0] и B[i][1]
            val seedInput = ByteArray(72)
            System.arraycopy(h0, 0, seedInput, 0, 64)
            for (lane in 0 until lanes) {
                writeLeInt(seedInput, 64, 0)
                writeLeInt(seedInput, 68, lane)
                val b0 = variableLengthHashHPrime(1024, seedInput)
                bytesToBlock(b0, slab, (lane * laneLength + 0) * BLOCK_LONGS)
                b0.wipe()

                writeLeInt(seedInput, 64, 1)
                writeLeInt(seedInput, 68, lane)
                val b1 = variableLengthHashHPrime(1024, seedInput)
                bytesToBlock(b1, slab, (lane * laneLength + 1) * BLOCK_LONGS)
                b1.wipe()
            }
            seedInput.wipe()

            // Проходы по матрице памяти с барьерной синхронизацией каждые slice (0..3)
            for (pass in 0 until iterations) {
                for (slice in 0 until SYNC_POINTS) {
                    if (lanes == 1) {
                        fillSegment(
                            slab = slab,
                            pass = pass,
                            lane = 0,
                            slice = slice,
                            lanes = lanes,
                            memoryBlocks = memoryBlocks,
                            iterations = iterations,
                            laneLength = laneLength,
                            segmentLength = segmentLength,
                        )
                    } else {
                        runBlocking(Dispatchers.Default) {
                            (0 until lanes).map { lane ->
                                async {
                                    fillSegment(
                                        slab = slab,
                                        pass = pass,
                                        lane = lane,
                                        slice = slice,
                                        lanes = lanes,
                                        memoryBlocks = memoryBlocks,
                                        iterations = iterations,
                                        laneLength = laneLength,
                                        segmentLength = segmentLength,
                                    )
                                }
                            }.awaitAll()
                        }
                    }
                }
            }

            // Финализация: C = XOR последних блоков каждой полосы B[lane][laneLength - 1]
            val finalBlock = LongArray(BLOCK_LONGS)
            val finalBytes = ByteArray(1024)
            try {
                for (lane in 0 until lanes) {
                    val lastOffset = (lane * laneLength + (laneLength - 1)) * BLOCK_LONGS
                    for (w in 0 until BLOCK_LONGS) {
                        finalBlock[w] = finalBlock[w] xor slab[lastOffset + w]
                    }
                }
                blockToBytes(finalBlock, finalBytes)
                return variableLengthHashHPrime(tagLength, finalBytes)
            } finally {
                finalBlock.wipe()
                finalBytes.wipe()
            }
        } finally {
            h0.wipe()
            slab.wipe()
        }
    }

    private fun fillSegment(
        slab: LongArray,
        pass: Int,
        lane: Int,
        slice: Int,
        lanes: Int,
        memoryBlocks: Int,
        iterations: Int,
        laneLength: Int,
        segmentLength: Int,
    ) {
        val dataIndependent = (pass == 0 && slice < 2)
        val zeroBlock = LongArray(BLOCK_LONGS)
        val inputBlock = LongArray(BLOCK_LONGS)
        val addressBlock = LongArray(BLOCK_LONGS)
        val tmpBlock = LongArray(BLOCK_LONGS)
        val stateR = LongArray(BLOCK_LONGS)
        val stateZ = LongArray(BLOCK_LONGS)

        try {
            if (dataIndependent) {
                inputBlock[0] = pass.toLong()
                inputBlock[1] = lane.toLong()
                inputBlock[2] = slice.toLong()
                inputBlock[3] = memoryBlocks.toLong()
                inputBlock[4] = iterations.toLong()
                inputBlock[5] = ARGON2_TYPE_ID.toLong()
                inputBlock[6] = 0L
            }

            val startIdx = if (pass == 0 && slice == 0) 2 else 0
            if (dataIndependent && startIdx > 0) {
                inputBlock[6]++
                nextAddresses(zeroBlock, inputBlock, tmpBlock, addressBlock, stateR, stateZ)
            }

            for (indexInSegment in startIdx until segmentLength) {
                if (dataIndependent && indexInSegment % BLOCK_LONGS == 0) {
                    inputBlock[6]++
                    nextAddresses(zeroBlock, inputBlock, tmpBlock, addressBlock, stateR, stateZ)
                }

                val currCol = slice * segmentLength + indexInSegment
                val prevCol = if (currCol == 0) laneLength - 1 else currCol - 1
                val prevOffset = (lane * laneLength + prevCol) * BLOCK_LONGS

                val pseudoRand = if (dataIndependent) {
                    addressBlock[indexInSegment % BLOCK_LONGS]
                } else {
                    slab[prevOffset]
                }

                val j1 = pseudoRand and 0xFFFFFFFFL
                val j2 = pseudoRand ushr 32

                val refLane = if (pass == 0 && slice == 0) {
                    lane
                } else {
                    (j2 % lanes.toLong()).toInt()
                }

                val refAreaSize = if (pass == 0) {
                    if (slice == 0) {
                        indexInSegment - 1
                    } else if (refLane == lane) {
                        slice * segmentLength + indexInSegment - 1
                    } else {
                        slice * segmentLength - if (indexInSegment == 0) 1 else 0
                    }
                } else {
                    if (refLane == lane) {
                        laneLength - segmentLength + indexInSegment - 1
                    } else {
                        laneLength - segmentLength - if (indexInSegment == 0) 1 else 0
                    }
                }

                val x = (j1 * j1) ushr 32
                val y = (refAreaSize.toLong() * x) ushr 32
                val relativePos = refAreaSize - 1 - y.toInt()
                val startPos = if (pass == 0) 0 else ((slice + 1) % SYNC_POINTS) * segmentLength
                val refCol = (startPos + relativePos) % laneLength

                val refOffset = (refLane * laneLength + refCol) * BLOCK_LONGS
                val dstOffset = (lane * laneLength + currCol) * BLOCK_LONGS

                compressG(
                    srcX = slab,
                    offsetX = prevOffset,
                    srcY = slab,
                    offsetY = refOffset,
                    dst = slab,
                    offsetDst = dstOffset,
                    xorWithDst = pass > 0,
                    r = stateR,
                    z = stateZ,
                )
            }
        } finally {
            inputBlock.wipe()
            addressBlock.wipe()
            tmpBlock.wipe()
            stateR.wipe()
            stateZ.wipe()
        }
    }

    private fun nextAddresses(
        zeroBlock: LongArray,
        inputBlock: LongArray,
        tmpBlock: LongArray,
        addressBlock: LongArray,
        stateR: LongArray,
        stateZ: LongArray,
    ) {
        compressG(zeroBlock, 0, inputBlock, 0, tmpBlock, 0, xorWithDst = false, r = stateR, z = stateZ)
        compressG(zeroBlock, 0, tmpBlock, 0, addressBlock, 0, xorWithDst = false, r = stateR, z = stateZ)
    }

    private fun compressG(
        srcX: LongArray,
        offsetX: Int,
        srcY: LongArray,
        offsetY: Int,
        dst: LongArray,
        offsetDst: Int,
        xorWithDst: Boolean,
        r: LongArray,
        z: LongArray,
    ) {
        for (i in 0 until BLOCK_LONGS) {
            val v = srcX[offsetX + i] xor srcY[offsetY + i]
            r[i] = v
            z[i] = v
        }

        // Построчная перестановка P (8 строк по 16 64-битных слов)
        for (row in 0 until 8) {
            val b = row * 16
            permuteP(
                z,
                b + 0, b + 1, b + 2, b + 3,
                b + 4, b + 5, b + 6, b + 7,
                b + 8, b + 9, b + 10, b + 11,
                b + 12, b + 13, b + 14, b + 15,
            )
        }

        // Постолбцовая перестановка P (8 столбцов по 8 16-байтных регистров = 16 64-битных слов)
        for (col in 0 until 8) {
            val c = col * 2
            permuteP(
                z,
                c + 0, c + 1,
                c + 16, c + 17,
                c + 32, c + 33,
                c + 48, c + 49,
                c + 64, c + 65,
                c + 80, c + 81,
                c + 96, c + 97,
                c + 112, c + 113,
            )
        }

        if (xorWithDst) {
            for (i in 0 until BLOCK_LONGS) {
                dst[offsetDst + i] = dst[offsetDst + i] xor z[i] xor r[i]
            }
        } else {
            for (i in 0 until BLOCK_LONGS) {
                dst[offsetDst + i] = z[i] xor r[i]
            }
        }
    }

    private fun permuteP(
        z: LongArray,
        i0: Int, i1: Int, i2: Int, i3: Int,
        i4: Int, i5: Int, i6: Int, i7: Int,
        i8: Int, i9: Int, i10: Int, i11: Int,
        i12: Int, i13: Int, i14: Int, i15: Int,
    ) {
        gb(z, i0, i4, i8, i12)
        gb(z, i1, i5, i9, i13)
        gb(z, i2, i6, i10, i14)
        gb(z, i3, i7, i11, i15)

        gb(z, i0, i5, i10, i15)
        gb(z, i1, i6, i11, i12)
        gb(z, i2, i7, i8, i13)
        gb(z, i3, i4, i9, i14)
    }

    private fun gb(z: LongArray, ia: Int, ib: Int, ic: Int, id: Int) {
        var a = z[ia]
        var b = z[ib]
        var c = z[ic]
        var d = z[id]

        a = a + b + 2L * (a and 0xFFFFFFFFL) * (b and 0xFFFFFFFFL)
        d = (d xor a).rotateRight(32)
        c = c + d + 2L * (c and 0xFFFFFFFFL) * (d and 0xFFFFFFFFL)
        b = (b xor c).rotateRight(24)

        a = a + b + 2L * (a and 0xFFFFFFFFL) * (b and 0xFFFFFFFFL)
        d = (d xor a).rotateRight(16)
        c = c + d + 2L * (c and 0xFFFFFFFFL) * (d and 0xFFFFFFFFL)
        b = (b xor c).rotateRight(63)

        z[ia] = a
        z[ib] = b
        z[ic] = c
        z[id] = d
    }

    private fun computeInitialHashH0(
        parallelism: Int,
        tagLength: Int,
        memoryKiB: Int,
        iterations: Int,
        password: ByteArray,
        salt: ByteArray,
        secret: ByteArray,
        associatedData: ByteArray,
    ): ByteArray {
        val totalLen = 40 + password.size + salt.size + secret.size + associatedData.size
        val buf = ByteBuffer.allocate(totalLen).order(ByteOrder.LITTLE_ENDIAN)
        return try {
            buf.putInt(parallelism)
            buf.putInt(tagLength)
            buf.putInt(memoryKiB)
            buf.putInt(iterations)
            buf.putInt(ARGON2_VERSION)
            buf.putInt(ARGON2_TYPE_ID)
            buf.putInt(password.size)
            buf.put(password)
            buf.putInt(salt.size)
            buf.put(salt)
            buf.putInt(secret.size)
            buf.put(secret)
            buf.putInt(associatedData.size)
            buf.put(associatedData)
            Blake2b.digest(64, buf.array())
        } finally {
            buf.array().wipe()
        }
    }

    internal fun variableLengthHashHPrime(tagLength: Int, message: ByteArray): ByteArray {
        val prefixed = ByteArray(4 + message.size)
        writeLeInt(prefixed, 0, tagLength)
        System.arraycopy(message, 0, prefixed, 4, message.size)
        try {
            if (tagLength <= 64) {
                return Blake2b.digest(tagLength, prefixed)
            }
            val out = ByteArray(tagLength)
            val r = ((tagLength + 31) / 32) - 2
            var v = Blake2b.digest(64, prefixed)
            System.arraycopy(v, 0, out, 0, 32)
            for (i in 2..r) {
                val next = Blake2b.digest(64, v)
                v.wipe()
                v = next
                System.arraycopy(v, 0, out, (i - 1) * 32, 32)
            }
            val remaining = tagLength - 32 * r
            val last = Blake2b.digest(remaining, v)
            v.wipe()
            System.arraycopy(last, 0, out, 32 * r, remaining)
            last.wipe()
            return out
        } finally {
            prefixed.wipe()
        }
    }

    private fun bytesToBlock(bytes: ByteArray, slab: LongArray, slabOffset: Int) {
        val bb = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
        for (i in 0 until BLOCK_LONGS) {
            slab[slabOffset + i] = bb.long
        }
    }

    private fun blockToBytes(block: LongArray, out: ByteArray) {
        val bb = ByteBuffer.wrap(out).order(ByteOrder.LITTLE_ENDIAN)
        for (i in 0 until BLOCK_LONGS) {
            bb.putLong(block[i])
        }
    }

    private fun writeLeInt(dst: ByteArray, offset: Int, value: Int) {
        dst[offset] = (value and 0xFF).toByte()
        dst[offset + 1] = ((value ushr 8) and 0xFF).toByte()
        dst[offset + 2] = ((value ushr 16) and 0xFF).toByte()
        dst[offset + 3] = ((value ushr 24) and 0xFF).toByte()
    }

    internal fun charArrayToUtf8Bytes(chars: CharArray): ByteArray {
        val cb = java.nio.CharBuffer.wrap(chars)
        val bb = Charsets.UTF_8.encode(cb)
        val out = ByteArray(bb.remaining())
        bb.get(out)
        if (bb.hasArray()) {
            bb.array().wipe()
        }
        return out
    }
}

/**
 * RFC 7693 BLAKE2b (1..64 байт дайджеста) для Argon2id и криптографических примитивов.
 */
internal object Blake2b {
    private val IV = longArrayOf(
        0x6a09e667f3bcc908L,
        -0x4498517a7b3558c5L, // 0xbb67ae8584caa73bUL
        0x3c6ef372fe94f82bL,
        -0x5ab00ac5a0e2c90fL, // 0xa54ff53a5f1d36f1UL
        0x510e527fade682d1L,
        -0x64fa9773d4c193e1L, // 0x9b05688c2b3e6c1fUL
        0x1f83d9abfb41bd6bL,
        0x5be0cd19137e2179L,
    )

    private val SIGMA = arrayOf(
        intArrayOf(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15),
        intArrayOf(14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3),
        intArrayOf(11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4),
        intArrayOf(7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8),
        intArrayOf(9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13),
        intArrayOf(2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9),
        intArrayOf(12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11),
        intArrayOf(13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10),
        intArrayOf(6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5),
        intArrayOf(10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0),
    )

    fun digest(outLen: Int, data: ByteArray): ByteArray {
        require(outLen in 1..64) { "outLen должен быть в диапазоне 1..64" }
        val h = IV.copyOf()
        h[0] = h[0] xor (0x01010000L or outLen.toLong())

        val block = ByteArray(128)
        val m = LongArray(16)
        val v = LongArray(16)
        var t0 = 0L
        var t1 = 0L

        try {
            var offset = 0
            while (data.size - offset > 128) {
                System.arraycopy(data, offset, block, 0, 128)
                t0 += 128L
                if (java.lang.Long.compareUnsigned(t0, 128L) < 0) t1++
                compress(h, block, m, v, t0, t1, isFinal = false)
                offset += 128
            }

            val remaining = data.size - offset
            block.wipe()
            if (remaining > 0) {
                System.arraycopy(data, offset, block, 0, remaining)
            }
            t0 += remaining.toLong()
            if (java.lang.Long.compareUnsigned(t0, remaining.toLong()) < 0) t1++
            compress(h, block, m, v, t0, t1, isFinal = true)

            val full = ByteArray(64)
            val bb = ByteBuffer.wrap(full).order(ByteOrder.LITTLE_ENDIAN)
            for (i in 0 until 8) bb.putLong(h[i])
            val out = full.copyOf(outLen)
            full.wipe()
            return out
        } finally {
            h.wipe()
            block.wipe()
            m.wipe()
            v.wipe()
        }
    }

    private fun compress(
        h: LongArray,
        block: ByteArray,
        m: LongArray,
        v: LongArray,
        t0: Long,
        t1: Long,
        isFinal: Boolean,
    ) {
        val bb = ByteBuffer.wrap(block).order(ByteOrder.LITTLE_ENDIAN)
        for (i in 0 until 16) m[i] = bb.long
        for (i in 0 until 8) {
            v[i] = h[i]
            v[i + 8] = IV[i]
        }
        v[12] = v[12] xor t0
        v[13] = v[13] xor t1
        if (isFinal) v[14] = v[14].inv()

        for (round in 0 until 12) {
            val s = SIGMA[round % 10]
            g(v, 0, 4, 8, 12, m[s[0]], m[s[1]])
            g(v, 1, 5, 9, 13, m[s[2]], m[s[3]])
            g(v, 2, 6, 10, 14, m[s[4]], m[s[5]])
            g(v, 3, 7, 11, 15, m[s[6]], m[s[7]])
            g(v, 0, 5, 10, 15, m[s[8]], m[s[9]])
            g(v, 1, 6, 11, 12, m[s[10]], m[s[11]])
            g(v, 2, 7, 8, 13, m[s[12]], m[s[13]])
            g(v, 3, 4, 9, 14, m[s[14]], m[s[15]])
        }

        for (i in 0 until 8) {
            h[i] = h[i] xor v[i] xor v[i + 8]
        }
    }

    private fun g(v: LongArray, a: Int, b: Int, c: Int, d: Int, x: Long, y: Long) {
        v[a] = v[a] + v[b] + x
        v[d] = (v[d] xor v[a]).rotateRight(32)
        v[c] = v[c] + v[d]
        v[b] = (v[b] xor v[c]).rotateRight(24)
        v[a] = v[a] + v[b] + y
        v[d] = (v[d] xor v[a]).rotateRight(16)
        v[c] = v[c] + v[d]
        v[b] = (v[b] xor v[c]).rotateRight(63)
    }
}
