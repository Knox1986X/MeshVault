package com.meshvault.app.crypto

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import java.io.InputStream
import java.io.OutputStream
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.CipherInputStream
import javax.crypto.CipherOutputStream
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

object CryptoManager {
    private const val PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA256"
    private const val PBKDF2_ITERATIONS = 600_000
    private const val KEY_LENGTH_BITS = 256
    private const val AES_MODE = "AES/GCM/NoPadding"
    private const val GCM_TAG_LENGTH_BITS = 128
    private const val IV_SIZE_BYTES = 12
    private const val SALT_SIZE_BYTES = 32

    private const val PREFS_NAME = "meshvault_secure_prefs"
    private const val KEY_SALT = "master_salt"
    private const val KEY_VERIFIER = "master_verifier"
    private const val KEY_BIO_WRAPPED = "bio_wrapped_key"
    private const val KEY_BIOMETRIC_ENABLED = "biometric_enabled"
    private const val KEY_AUTO_LOCK_SECONDS = "auto_lock_seconds"

    private val secureRandom = SecureRandom()

    private fun getPrefs(context: Context) = EncryptedSharedPreferences.create(
        context,
        PREFS_NAME,
        MasterKey.Builder(context)
            .setKeyGenParameterSpec(
                KeyGenParameterSpec.Builder(
                    MasterKey.DEFAULT_MASTER_KEY_ALIAS,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
                )
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setKeySize(256)
                    .build()
            )
            .build(),
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
    )

    fun isVaultInitialized(context: Context): Boolean {
        val prefs = getPrefs(context)
        return prefs.contains(KEY_SALT) && prefs.contains(KEY_VERIFIER)
    }

    fun isBiometricEnabled(context: Context): Boolean {
        return getPrefs(context).getBoolean(KEY_BIOMETRIC_ENABLED, false)
    }

    fun setBiometricEnabled(context: Context, enabled: Boolean, activeKey: SecretKey? = null) {
        val prefs = getPrefs(context)
        if (enabled && activeKey != null) {
            val encodedKey = Base64.encodeToString(activeKey.encoded, Base64.NO_WRAP)
            prefs.edit()
                .putString(KEY_BIO_WRAPPED, encodedKey)
                .putBoolean(KEY_BIOMETRIC_ENABLED, true)
                .apply()
        } else {
            prefs.edit()
                .remove(KEY_BIO_WRAPPED)
                .putBoolean(KEY_BIOMETRIC_ENABLED, false)
                .apply()
        }
    }

    fun getBiometricKey(context: Context): SecretKey? {
        val prefs = getPrefs(context)
        if (!prefs.getBoolean(KEY_BIOMETRIC_ENABLED, false)) return null
        val encoded = prefs.getString(KEY_BIO_WRAPPED, null) ?: return null
        val bytes = Base64.decode(encoded, Base64.NO_WRAP)
        return SecretKeySpec(bytes, "AES")
    }

    fun getAutoLockSeconds(context: Context): Int {
        return getPrefs(context).getInt(KEY_AUTO_LOCK_SECONDS, 60)
    }

    fun setAutoLockSeconds(context: Context, seconds: Int) {
        getPrefs(context).edit().putInt(KEY_AUTO_LOCK_SECONDS, seconds).apply()
    }

    fun initializeVault(context: Context, masterPassword: CharArray): SecretKey {
        val salt = ByteArray(SALT_SIZE_BYTES).also { secureRandom.nextBytes(it) }
        val key = deriveKey(masterPassword, salt)
        val verifier = encryptBytes("MESHVAULT_VERIFIED_V1".toByteArray(Charsets.UTF_8), key)

        getPrefs(context).edit()
            .putString(KEY_SALT, Base64.encodeToString(salt, Base64.NO_WRAP))
            .putString(KEY_VERIFIER, Base64.encodeToString(verifier, Base64.NO_WRAP))
            .apply()

        return key
    }

    fun verifyAndDeriveKey(context: Context, masterPassword: CharArray): SecretKey? {
        val prefs = getPrefs(context)
        val saltB64 = prefs.getString(KEY_SALT, null) ?: return null
        val verifierB64 = prefs.getString(KEY_VERIFIER, null) ?: return null

        val salt = Base64.decode(saltB64, Base64.NO_WRAP)
        val verifier = Base64.decode(verifierB64, Base64.NO_WRAP)
        val candidateKey = deriveKey(masterPassword, salt)

        return try {
            val decrypted = decryptBytes(verifier, candidateKey)
            if (decrypted.toString(Charsets.UTF_8) == "MESHVAULT_VERIFIED_V1") {
                candidateKey
            } else {
                null
            }
        } catch (_: Exception) {
            null
        }
    }

    private fun deriveKey(password: CharArray, salt: ByteArray): SecretKey {
        val factory = SecretKeyFactory.getInstance(PBKDF2_ALGORITHM)
        val spec = PBEKeySpec(password, salt, PBKDF2_ITERATIONS, KEY_LENGTH_BITS)
        val secret = factory.generateSecret(spec)
        spec.clearPassword()
        return SecretKeySpec(secret.encoded, "AES")
    }

    fun encryptBytes(plain: ByteArray, key: SecretKey): ByteArray {
        val iv = ByteArray(IV_SIZE_BYTES).also { secureRandom.nextBytes(it) }
        val cipher = Cipher.getInstance(AES_MODE)
        cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv))
        val encrypted = cipher.doFinal(plain)
        return iv + encrypted
    }

    fun decryptBytes(cipherData: ByteArray, key: SecretKey): ByteArray {
        require(cipherData.size > IV_SIZE_BYTES) { "Invalid encrypted payload" }
        val iv = cipherData.copyOfRange(0, IV_SIZE_BYTES)
        val payload = cipherData.copyOfRange(IV_SIZE_BYTES, cipherData.size)
        val cipher = Cipher.getInstance(AES_MODE)
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv))
        return cipher.doFinal(payload)
    }

    fun encryptStream(input: InputStream, output: OutputStream, key: SecretKey) {
        val iv = ByteArray(IV_SIZE_BYTES).also { secureRandom.nextBytes(it) }
        output.write(iv)
        val cipher = Cipher.getInstance(AES_MODE)
        cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv))
        CipherOutputStream(output, cipher).use { cos ->
            input.copyTo(cos, bufferSize = 32 * 1024)
        }
    }

    fun decryptToStream(input: InputStream, output: OutputStream, key: SecretKey) {
        val iv = ByteArray(IV_SIZE_BYTES)
        var read = 0
        while (read < IV_SIZE_BYTES) {
            val r = input.read(iv, read, IV_SIZE_BYTES - read)
            if (r == -1) throw IllegalStateException("Unexpected EOF reading IV")
            read += r
        }
        val cipher = Cipher.getInstance(AES_MODE)
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv))
        CipherInputStream(input, cipher).use { cis ->
            cis.copyTo(output, bufferSize = 32 * 1024)
        }
    }
}
