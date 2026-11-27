package com.meshvault.data.db

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import com.meshvault.crypto.VaultContour
import com.meshvault.domain.repository.AppSecuritySettings
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.io.File
import java.security.KeyStore
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

data class BiometricWrappedVmk(
    val contour: VaultContour,
    val ivBase64: String,
    val ciphertextBase64: String,
)

/**
 * Аппаратный менеджер ключей Android Keystore (TEE / StrongBox):
 *  - Оборачивает VMK ключом с обязательной аутентификацией BIOMETRIC_STRONG
 *    и автоматической инвалидацией при добавлении нового отпечатка (`setInvalidatedByBiometricEnrollment(true)`);
 *  - Шифрует OAuth-токены Dropbox и локальные настройки безопасности на флеш-памяти.
 */
class HardwareKeystoreManager(private val context: Context) {

    private val json = Json {
        ignoreUnknownKeys = true
        encodeDefaults = true
    }

    private val settingsFile = File(context.filesDir, "meshvault_security_prefs.mvenc")
    private val bioBlobFile = File(context.filesDir, "meshvault_bio_vmk.bin")
    private val dropboxTokenFile = File(context.filesDir, "meshvault_dropbox_tokens.mvenc")
    private val vaultHeaderFile = File(context.filesDir, "vault_header.json")
    private val nodeIdFile = File(context.filesDir, "meshvault_node_id.txt")

    private val _settingsFlow = MutableStateFlow(loadSettingsInternal())
    val settingsFlow: StateFlow<AppSecuritySettings> = _settingsFlow.asStateFlow()

    fun hasVaultHeader(): Boolean = vaultHeaderFile.exists() && vaultHeaderFile.length() > 32

    fun readVaultHeaderRaw(): String? =
        if (vaultHeaderFile.exists()) vaultHeaderFile.readText(Charsets.UTF_8) else null

    fun saveVaultHeaderRaw(rawJson: String) {
        vaultHeaderFile.parentFile?.mkdirs()
        vaultHeaderFile.writeText(rawJson, Charsets.UTF_8)
    }

    fun getOrCreateDeviceNodeId(): String {
        if (nodeIdFile.exists()) {
            val existing = nodeIdFile.readText(Charsets.UTF_8).trim()
            if (existing.isNotEmpty()) return existing
        }
        val fresh = java.util.UUID.randomUUID().toString().replace("-", "").take(12)
        nodeIdFile.writeText(fresh, Charsets.UTF_8)
        return fresh
    }

    fun updateSettings(transform: (AppSecuritySettings) -> AppSecuritySettings) {
        val next = transform(_settingsFlow.value)
        saveSettingsInternal(next)
        _settingsFlow.value = next
    }

    fun createBiometricEncryptCipher(): Cipher {
        val key = getOrCreateBiometricKey(recreate = true)
        val cipher = Cipher.getInstance(AES_GCM_TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, key)
        return cipher
    }

    fun createBiometricDecryptCipher(): Pair<Cipher, VaultContour>? {
        if (!bioBlobFile.exists()) return null
        val lines = bioBlobFile.readLines(Charsets.UTF_8)
        if (lines.size < 3) return null
        val contour = runCatching { VaultContour.valueOf(lines[0]) }.getOrNull() ?: return null
        val iv = Base64.getDecoder().decode(lines[1])

        return try {
            val key = getBiometricKeyOrNull() ?: return null
            val cipher = Cipher.getInstance(AES_GCM_TRANSFORMATION)
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, iv))
            cipher to contour
        } catch (_: KeyPermanentlyInvalidatedException) {
            clearBiometricEnrollment()
            null
        } catch (_: Exception) {
            null
        }
    }

    fun finalizeBiometricEnrollment(authenticatedCipher: Cipher, contour: VaultContour, vmkBytes: ByteArray) {
        val ct = authenticatedCipher.doFinal(vmkBytes)
        val ivB64 = Base64.getEncoder().withoutPadding().encodeToString(authenticatedCipher.iv)
        val ctB64 = Base64.getEncoder().withoutPadding().encodeToString(ct)
        bioBlobFile.writeText("${contour.name}\n$ivB64\n$ctB64", Charsets.UTF_8)
        updateSettings { it.copy(biometricUnlockEnabled = true) }
    }

    fun decryptVmkWithAuthenticatedCipher(authenticatedCipher: Cipher): ByteArray {
        val lines = bioBlobFile.readLines(Charsets.UTF_8)
        require(lines.size >= 3) { "Отсутствует зашифрованный биометрический конверт" }
        val ct = Base64.getDecoder().decode(lines[2])
        return authenticatedCipher.doFinal(ct)
    }

    fun clearBiometricEnrollment() {
        if (bioBlobFile.exists()) bioBlobFile.delete()
        runCatching {
            val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
            if (ks.containsAlias(BIOMETRIC_KEY_ALIAS)) {
                ks.deleteEntry(BIOMETRIC_KEY_ALIAS)
            }
        }
        updateSettings { it.copy(biometricUnlockEnabled = false) }
    }

    fun saveEncryptedDropboxTokenBlob(rawJson: String) {
        val enc = encryptWithStorageKey(rawJson.toByteArray(Charsets.UTF_8), "dropbox_oauth_v2")
        dropboxTokenFile.writeBytes(enc)
    }

    fun readEncryptedDropboxTokenBlob(): String? {
        if (!dropboxTokenFile.exists()) return null
        return runCatching {
            val dec = decryptWithStorageKey(dropboxTokenFile.readBytes(), "dropbox_oauth_v2")
            String(dec, Charsets.UTF_8)
        }.getOrNull()
    }

    fun wipeEncryptedDropboxTokenBlob() {
        if (dropboxTokenFile.exists()) {
            dropboxTokenFile.writeBytes(ByteArray(dropboxTokenFile.length().toInt().coerceAtMost(4096)))
            dropboxTokenFile.delete()
        }
    }

    private fun loadSettingsInternal(): AppSecuritySettings {
        if (!settingsFile.exists()) return AppSecuritySettings()
        return runCatching {
            val plain = decryptWithStorageKey(settingsFile.readBytes(), "security_settings_v2")
            json.decodeFromString<AppSecuritySettings>(String(plain, Charsets.UTF_8))
        }.getOrDefault(AppSecuritySettings())
    }

    private fun saveSettingsInternal(settings: AppSecuritySettings) {
        runCatching {
            val raw = json.encodeToString(settings).toByteArray(Charsets.UTF_8)
            val enc = encryptWithStorageKey(raw, "security_settings_v2")
            settingsFile.writeBytes(enc)
        }
    }

    private fun encryptWithStorageKey(plaintext: ByteArray, aad: String): ByteArray {
        val key = getOrCreateStorageKey()
        val cipher = Cipher.getInstance(AES_GCM_TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, key)
        cipher.updateAAD(aad.toByteArray(Charsets.UTF_8))
        val iv = cipher.iv
        val ct = cipher.doFinal(plaintext)
        val packed = ByteArray(1 + iv.size + ct.size)
        packed[0] = iv.size.toByte()
        System.arraycopy(iv, 0, packed, 1, iv.size)
        System.arraycopy(ct, 0, packed, 1 + iv.size, ct.size)
        return packed
    }

    private fun decryptWithStorageKey(packed: ByteArray, aad: String): ByteArray {
        val key = getOrCreateStorageKey()
        val ivLen = packed[0].toInt() and 0xFF
        val iv = packed.copyOfRange(1, 1 + ivLen)
        val ct = packed.copyOfRange(1 + ivLen, packed.size)
        val cipher = Cipher.getInstance(AES_GCM_TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, iv))
        cipher.updateAAD(aad.toByteArray(Charsets.UTF_8))
        return cipher.doFinal(ct)
    }

    private fun getOrCreateStorageKey(): SecretKey {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        val existing = (ks.getEntry(STORAGE_KEY_ALIAS, null) as? KeyStore.SecretKeyEntry)?.secretKey
        if (existing != null) return existing

        val keyGen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        val spec = KeyGenParameterSpec.Builder(
            STORAGE_KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .build()
        keyGen.init(spec)
        return keyGen.generateKey()
    }

    private fun getBiometricKeyOrNull(): SecretKey? {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        return (ks.getEntry(BIOMETRIC_KEY_ALIAS, null) as? KeyStore.SecretKeyEntry)?.secretKey
    }

    private fun getOrCreateBiometricKey(recreate: Boolean): SecretKey {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        if (!recreate) {
            val existing = (ks.getEntry(BIOMETRIC_KEY_ALIAS, null) as? KeyStore.SecretKeyEntry)?.secretKey
            if (existing != null) return existing
        } else if (ks.containsAlias(BIOMETRIC_KEY_ALIAS)) {
            ks.deleteEntry(BIOMETRIC_KEY_ALIAS)
        }

        val keyGen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        val builder = KeyGenParameterSpec.Builder(
            BIOMETRIC_KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setUserAuthenticationRequired(true)
            .setInvalidatedByBiometricEnrollment(true)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            builder.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
        } else {
            @Suppress("DEPRECATION")
            builder.setUserAuthenticationValidityDurationSeconds(-1)
        }

        keyGen.init(builder.build())
        return keyGen.generateKey()
    }

    companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val STORAGE_KEY_ALIAS = "meshvault_hw_storage_v2"
        private const val BIOMETRIC_KEY_ALIAS = "meshvault_bio_vmk_v2"
        private const val AES_GCM_TRANSFORMATION = "AES/GCM/NoPadding"
    }
}
