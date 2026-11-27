package com.meshvault.crypto

import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Arrays
import java.util.concurrent.atomic.AtomicBoolean

class VaultLockedException(message: String = "Хранилище заблокировано: ключи сессии очищены из ОЗУ") :
    IllegalStateException(message)

class CryptoAuthException(message: String = "Ошибка аутентификации шифротекста или неверный мастер-пароль") :
    SecurityException(message)

enum class VaultContour(val slotIndex: Int, val dbFileName: String, val mediaNamespace: String) {
    PRIMARY(slotIndex = 0, dbFileName = "meshvault_c0.mvdb", mediaNamespace = "c0"),
    DECOY(slotIndex = 1, dbFileName = "meshvault_c1.mvdb", mediaNamespace = "c1"),
}

object CryptoRandom {
    private val rng = SecureRandom()

    fun nextBytes(size: Int): ByteArray = ByteArray(size).also { rng.nextBytes(it) }

    fun nextLong(): Long = rng.nextLong()

    fun nextInt(bound: Int): Int = rng.nextInt(bound)
}

fun ByteArray.wipe() {
    Arrays.fill(this, 0.toByte())
}

fun CharArray.wipe() {
    Arrays.fill(this, '\u0000')
}

fun LongArray.wipe() {
    Arrays.fill(this, 0L)
}

fun IntArray.wipe() {
    Arrays.fill(this, 0)
}

fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean = MessageDigest.isEqual(a, b)

class SecureBytes private constructor(
    private val buffer: ByteArray,
) : AutoCloseable {
    private val wiped = AtomicBoolean(false)

    val size: Int
        get() = buffer.size

    val isWiped: Boolean
        get() = wiped.get()

    fun <R> useBytes(block: (ByteArray) -> R): R {
        if (wiped.get()) throw VaultLockedException()
        return block(buffer)
    }

    fun copyBytes(): ByteArray {
        if (wiped.get()) throw VaultLockedException()
        return buffer.copyOf()
    }

    fun wipe() {
        if (wiped.compareAndSet(false, true)) {
            buffer.wipe()
        }
    }

    override fun close() = wipe()

    override fun toString(): String = "SecureBytes(size=${buffer.size}, wiped=${wiped.get()})"

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is SecureBytes) return false
        if (wiped.get() || other.wiped.get()) return false
        return constantTimeEquals(buffer, other.buffer)
    }

    override fun hashCode(): Int = buffer.size

    companion object {
        fun wrapTakingOwnership(raw: ByteArray): SecureBytes = SecureBytes(raw)
        fun copyFrom(raw: ByteArray): SecureBytes = SecureBytes(raw.copyOf())
    }
}

/**
 * Держит изолированную иерархию ключей открытой сессии в ОЗУ.
 * При экстренной блокировке (Panic Lock) или сворачивании приложения
 * вызов [wipeAll] принудительно зануляет VMK и все подключи HKDF.
 */
class VaultSessionKeys(
    val contour: VaultContour,
    private val vmk: SecureBytes,
    private val kDb: SecureBytes,
    private val kMeta: SecureBytes,
    private val kBlob: SecureBytes,
    private val kThumb: SecureBytes,
    private val kMac: SecureBytes,
) : AutoCloseable {
    private val closed = AtomicBoolean(false)

    val isLocked: Boolean
        get() = closed.get()

    private fun ensureActive() {
        if (closed.get()) throw VaultLockedException()
    }

    fun <R> withVmk(block: (ByteArray) -> R): R {
        ensureActive()
        return vmk.useBytes(block)
    }

    fun <R> withDbKey(block: (ByteArray) -> R): R {
        ensureActive()
        return kDb.useBytes(block)
    }

    fun <R> withMetaKey(block: (ByteArray) -> R): R {
        ensureActive()
        return kMeta.useBytes(block)
    }

    fun <R> withBlobKey(block: (ByteArray) -> R): R {
        ensureActive()
        return kBlob.useBytes(block)
    }

    fun <R> withThumbKey(block: (ByteArray) -> R): R {
        ensureActive()
        return kThumb.useBytes(block)
    }

    fun <R> withMacKey(block: (ByteArray) -> R): R {
        ensureActive()
        return kMac.useBytes(block)
    }

    fun wipeAll() {
        closed.set(true)
        vmk.wipe()
        kDb.wipe()
        kMeta.wipe()
        kBlob.wipe()
        kThumb.wipe()
        kMac.wipe()
    }

    override fun close() = wipeAll()
}
