package com.meshvault.crypto

import kotlinx.serialization.Serializable
import java.nio.ByteBuffer
import java.nio.ByteOrder
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

@Serializable
enum class AeadCipherSuite {
    AES_256_GCM,
    XCHACHA20_POLY1305,
}

/**
 * Единый фасад AEAD-шифрования конвертов и метаданных (AES-256-GCM и XChaCha20-Poly1305).
 */
object EnvelopeCiphers {
    const val AES_GCM_NONCE_BYTES = 12
    const val XCHACHA_NONCE_BYTES = 24
    const val TAG_BITS = 128
    const val TAG_BYTES = 16

    fun nonceSizeFor(suite: AeadCipherSuite): Int = when (suite) {
        AeadCipherSuite.AES_256_GCM -> AES_GCM_NONCE_BYTES
        AeadCipherSuite.XCHACHA20_POLY1305 -> XCHACHA_NONCE_BYTES
    }

    fun encrypt(
        suite: AeadCipherSuite,
        key: ByteArray,
        nonce: ByteArray,
        plaintext: ByteArray,
        aad: ByteArray = ByteArray(0),
    ): ByteArray = when (suite) {
        AeadCipherSuite.AES_256_GCM -> encryptAes256Gcm(key, nonce, plaintext, aad)
        AeadCipherSuite.XCHACHA20_POLY1305 -> encryptXChaCha20Poly1305(key, nonce, plaintext, aad)
    }

    fun decrypt(
        suite: AeadCipherSuite,
        key: ByteArray,
        nonce: ByteArray,
        ciphertextWithTag: ByteArray,
        aad: ByteArray = ByteArray(0),
    ): ByteArray = when (suite) {
        AeadCipherSuite.AES_256_GCM -> decryptAes256Gcm(key, nonce, ciphertextWithTag, aad)
        AeadCipherSuite.XCHACHA20_POLY1305 -> decryptXChaCha20Poly1305(key, nonce, ciphertextWithTag, aad)
    }

    /**
     * Формат упакованного поля: [1 байт suiteId] || [nonce] || [ciphertext + 16-байтный тег].
     */
    fun sealEnvelopeField(
        key: ByteArray,
        plaintext: ByteArray,
        aad: ByteArray,
        suite: AeadCipherSuite = AeadCipherSuite.AES_256_GCM,
    ): ByteArray {
        val nonceLen = nonceSizeFor(suite)
        val nonce = CryptoRandom.nextBytes(nonceLen)
        val ct = encrypt(suite, key, nonce, plaintext, aad)
        val packed = ByteArray(1 + nonceLen + ct.size)
        packed[0] = suite.ordinal.toByte()
        System.arraycopy(nonce, 0, packed, 1, nonceLen)
        System.arraycopy(ct, 0, packed, 1 + nonceLen, ct.size)
        return packed
    }

    fun openEnvelopeField(
        key: ByteArray,
        packed: ByteArray,
        aad: ByteArray,
    ): ByteArray {
        if (packed.size < 1 + AES_GCM_NONCE_BYTES + TAG_BYTES) {
            throw CryptoAuthException("Повреждённый зашифрованный блок поля")
        }
        val suite = AeadCipherSuite.entries.getOrNull(packed[0].toInt() and 0xFF)
            ?: throw CryptoAuthException("Неизвестный шифронабор AEAD")
        val nonceLen = nonceSizeFor(suite)
        if (packed.size < 1 + nonceLen + TAG_BYTES) {
            throw CryptoAuthException("Недостаточная длина зашифрованного конверта")
        }
        val nonce = packed.copyOfRange(1, 1 + nonceLen)
        val ct = packed.copyOfRange(1 + nonceLen, packed.size)
        return decrypt(suite, key, nonce, ct, aad)
    }

    fun encryptAes256Gcm(
        key: ByteArray,
        iv12: ByteArray,
        plaintext: ByteArray,
        aad: ByteArray,
    ): ByteArray {
        require(key.size == 32) { "Ключ AES-256-GCM должен быть 32 байта" }
        require(iv12.size == AES_GCM_NONCE_BYTES) { "IV AES-256-GCM должен быть 12 байт" }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(TAG_BITS, iv12))
        if (aad.isNotEmpty()) cipher.updateAAD(aad)
        return cipher.doFinal(plaintext)
    }

    fun decryptAes256Gcm(
        key: ByteArray,
        iv12: ByteArray,
        ciphertextWithTag: ByteArray,
        aad: ByteArray,
    ): ByteArray {
        require(key.size == 32) { "Ключ AES-256-GCM должен быть 32 байта" }
        require(iv12.size == AES_GCM_NONCE_BYTES) { "IV AES-256-GCM должен быть 12 байт" }
        if (ciphertextWithTag.size < TAG_BYTES) throw CryptoAuthException("Тег AES-GCM усечён")
        return try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(TAG_BITS, iv12))
            if (aad.isNotEmpty()) cipher.updateAAD(aad)
            cipher.doFinal(ciphertextWithTag)
        } catch (e: AEADBadTagException) {
            throw CryptoAuthException("Нарушена целостность AES-256-GCM или неверный ключ")
        } catch (e: Exception) {
            throw CryptoAuthException("Ошибка расшифровки AES-256-GCM: ${e.message}")
        }
    }

    /**
     * draft-irtf-cfrg-xchacha: 24-байтный nonce -> HChaCha20(key, nonce[0..15]) -> subkey,
     * затем IETF ChaCha20-Poly1305(subkey, 0x00000000 || nonce[16..23]).
     */
    fun encryptXChaCha20Poly1305(
        key: ByteArray,
        nonce24: ByteArray,
        plaintext: ByteArray,
        aad: ByteArray,
    ): ByteArray {
        require(key.size == 32) { "Ключ XChaCha20-Poly1305 должен быть 32 байта" }
        require(nonce24.size == XCHACHA_NONCE_BYTES) { "Nonce XChaCha20-Poly1305 должен быть 24 байта" }

        val subKey = hChaCha20(key, nonce24)
        val chachaNonce = ByteArray(12)
        System.arraycopy(nonce24, 16, chachaNonce, 4, 8)
        return try {
            val cipher = Cipher.getInstance("ChaCha20-Poly1305")
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(subKey, "ChaCha20"), IvParameterSpec(chachaNonce))
            if (aad.isNotEmpty()) cipher.updateAAD(aad)
            cipher.doFinal(plaintext)
        } finally {
            subKey.wipe()
            chachaNonce.wipe()
        }
    }

    fun decryptXChaCha20Poly1305(
        key: ByteArray,
        nonce24: ByteArray,
        ciphertextWithTag: ByteArray,
        aad: ByteArray,
    ): ByteArray {
        require(key.size == 32) { "Ключ XChaCha20-Poly1305 должен быть 32 байта" }
        require(nonce24.size == XCHACHA_NONCE_BYTES) { "Nonce XChaCha20-Poly1305 должен быть 24 байта" }
        if (ciphertextWithTag.size < TAG_BYTES) throw CryptoAuthException("Тег Poly1305 усечён")

        val subKey = hChaCha20(key, nonce24)
        val chachaNonce = ByteArray(12)
        System.arraycopy(nonce24, 16, chachaNonce, 4, 8)
        return try {
            val cipher = Cipher.getInstance("ChaCha20-Poly1305")
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(subKey, "ChaCha20"), IvParameterSpec(chachaNonce))
            if (aad.isNotEmpty()) cipher.updateAAD(aad)
            cipher.doFinal(ciphertextWithTag)
        } catch (e: AEADBadTagException) {
            throw CryptoAuthException("Нарушена целостность XChaCha20-Poly1305 или неверный ключ")
        } catch (e: Exception) {
            throw CryptoAuthException("Ошибка расшифровки XChaCha20-Poly1305: ${e.message}")
        } finally {
            subKey.wipe()
            chachaNonce.wipe()
        }
    }

    internal fun hChaCha20(key32: ByteArray, noncePrefix16: ByteArray): ByteArray {
        val state = IntArray(16)
        // "expand 32-byte k"
        state[0] = 0x61707865
        state[1] = 0x3320646e
        state[2] = 0x79622d32
        state[3] = 0x6b206574

        val keyBuf = ByteBuffer.wrap(key32, 0, 32).order(ByteOrder.LITTLE_ENDIAN)
        for (i in 0 until 8) state[4 + i] = keyBuf.int

        val nonceBuf = ByteBuffer.wrap(noncePrefix16, 0, 16).order(ByteOrder.LITTLE_ENDIAN)
        for (i in 0 until 4) state[12 + i] = nonceBuf.int

        try {
            repeat(10) {
                quarterRound(state, 0, 4, 8, 12)
                quarterRound(state, 1, 5, 9, 13)
                quarterRound(state, 2, 6, 10, 14)
                quarterRound(state, 3, 7, 11, 15)

                quarterRound(state, 0, 5, 10, 15)
                quarterRound(state, 1, 6, 11, 12)
                quarterRound(state, 2, 7, 8, 13)
                quarterRound(state, 3, 4, 9, 14)
            }

            val out = ByteArray(32)
            val outBuf = ByteBuffer.wrap(out).order(ByteOrder.LITTLE_ENDIAN)
            for (i in 0 until 4) outBuf.putInt(state[i])
            for (i in 12 until 16) outBuf.putInt(state[i])
            return out
        } finally {
            state.wipe()
        }
    }

    private fun quarterRound(x: IntArray, a: Int, b: Int, c: Int, d: Int) {
        x[a] += x[b]; x[d] = (x[d] xor x[a]).rotateLeft(16)
        x[c] += x[d]; x[b] = (x[b] xor x[c]).rotateLeft(12)
        x[a] += x[b]; x[d] = (x[d] xor x[a]).rotateLeft(8)
        x[c] += x[d]; x[b] = (x[b] xor x[c]).rotateLeft(7)
    }
}
