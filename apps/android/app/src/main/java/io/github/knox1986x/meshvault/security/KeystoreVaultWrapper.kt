package io.github.knox1986x.meshvault.security

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Hardware-backed Android Keystore wrapper for the 32-byte KEK wrapping MVK.
 * Automatically falls back to master passphrase when system biometrics are reset or altered.
 */
class KeystoreVaultWrapper(
    private val context: Context,
    private val vaultId: String,
) {
    private val alias: String = "meshvault_bio_kek_$vaultId"
    private val prefs = context.getSharedPreferences("meshvault_keystore_slots", Context.MODE_PRIVATE)

    sealed interface BiometricPrepareResult {
        data class Ready(val cipher: Cipher) : BiometricPrepareResult
        data object BiometricsInvalidatedFallbackRequired : BiometricPrepareResult
        data object NotEnrolled : BiometricPrepareResult
    }

    fun hasEnrolledSlot(): Boolean = prefs.contains(slotKey()) && prefs.contains(wrappedKey())

    fun clearSlot() {
        prefs.edit()
            .remove(slotKey())
            .remove(wrappedKey())
            .remove(ivKey())
            .apply()
        runCatching {
            val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
            if (ks.containsAlias(alias)) {
                ks.deleteEntry(alias)
            }
        }
    }

    fun prepareEncryptCipher(): BiometricPrepareResult {
        return try {
            val secretKey = getOrCreateKey()
            val cipher = Cipher.getInstance(AES_GCM_TRANSFORMATION)
            cipher.init(Cipher.ENCRYPT_MODE, secretKey)
            BiometricPrepareResult.Ready(cipher)
        } catch (_: KeyPermanentlyInvalidatedException) {
            clearSlot()
            BiometricPrepareResult.BiometricsInvalidatedFallbackRequired
        } catch (_: Exception) {
            BiometricPrepareResult.BiometricsInvalidatedFallbackRequired
        }
    }

    fun prepareDecryptCipher(): BiometricPrepareResult {
        val ivB64 = prefs.getString(ivKey(), null) ?: return BiometricPrepareResult.NotEnrolled
        return try {
            val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
            val key = ks.getKey(alias, null) as? SecretKey ?: return BiometricPrepareResult.NotEnrolled
            val cipher = Cipher.getInstance(AES_GCM_TRANSFORMATION)
            val iv = Base64.decode(ivB64, Base64.NO_WRAP)
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, iv))
            BiometricPrepareResult.Ready(cipher)
        } catch (_: KeyPermanentlyInvalidatedException) {
            // Biometrics changed on device: safely force fallback to master passphrase.
            clearSlot()
            BiometricPrepareResult.BiometricsInvalidatedFallbackRequired
        } catch (_: Exception) {
            BiometricPrepareResult.BiometricsInvalidatedFallbackRequired
        }
    }

    fun saveWrappedHardwareKek(slotId: String, rawKek32: ByteArray, authenticatedCipher: Cipher) {
        val encrypted = authenticatedCipher.doFinal(rawKek32)
        val iv = authenticatedCipher.iv
        prefs.edit()
            .putString(slotKey(), slotId)
            .putString(wrappedKey(), Base64.encodeToString(encrypted, Base64.NO_WRAP))
            .putString(ivKey(), Base64.encodeToString(iv, Base64.NO_WRAP))
            .apply()
    }

    fun unwrapHardwareKek(authenticatedCipher: Cipher): Pair<String, ByteArray>? {
        val slotId = prefs.getString(slotKey(), null) ?: return null
        val wrappedB64 = prefs.getString(wrappedKey(), null) ?: return null
        val ciphertext = Base64.decode(wrappedB64, Base64.NO_WRAP)
        val raw = authenticatedCipher.doFinal(ciphertext)
        return slotId to raw
    }

    private fun getOrCreateKey(): SecretKey {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        if (ks.containsAlias(alias)) {
            ks.deleteEntry(alias)
        }
        val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        val spec = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setUserAuthenticationRequired(true)
            .setInvalidatedByBiometricEnrollment(true)
            .build()
        keyGenerator.init(spec)
        return keyGenerator.generateKey()
    }

    private fun slotKey() = "slot_$vaultId"
    private fun wrappedKey() = "kek_$vaultId"
    private fun ivKey() = "iv_$vaultId"

    companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val AES_GCM_TRANSFORMATION = "AES/GCM/NoPadding"
    }
}
