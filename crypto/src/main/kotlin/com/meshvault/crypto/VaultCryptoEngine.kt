package com.meshvault.crypto

import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.util.Base64
import java.util.UUID

@Serializable
data class EncryptedVmkSlot(
    val slotIndex: Int,
    val saltBase64: String,
    val nonceBase64: String,
    val wrappedVmkBase64: String,
)

@Serializable
data class VaultHeader(
    val formatMagic: String = FORMAT_MAGIC,
    val formatVersion: Int = FORMAT_VERSION,
    val vaultId: String,
    val kdfConfig: KdfConfig,
    val envelopeSuite: AeadCipherSuite = AeadCipherSuite.XCHACHA20_POLY1305,
    val slots: List<EncryptedVmkSlot>,
    val updatedAtEpochMs: Long,
) {
    companion object {
        const val FORMAT_MAGIC = "MESHVAULT_HEADER"
        const val FORMAT_VERSION = 2
    }
}

data class VaultCreationResult(
    val header: VaultHeader,
    val primarySession: VaultSessionKeys,
    val decoySession: VaultSessionKeys?,
)

object VaultCryptoEngine {
    private const val VMK_BYTES = 32
    private const val SALT_BYTES = 32
    private const val WRAPPED_VMK_CIPHERTEXT_BYTES = VMK_BYTES + EnvelopeCiphers.TAG_BYTES // 48 байт

    private val headerJson = Json {
        prettyPrint = true
        ignoreUnknownKeys = true
        encodeDefaults = true
    }

    fun serializeHeader(header: VaultHeader): String = headerJson.encodeToString(header)

    fun deserializeHeader(rawJson: String): VaultHeader {
        val parsed = headerJson.decodeFromString<VaultHeader>(rawJson)
        require(parsed.formatMagic == VaultHeader.FORMAT_MAGIC) { "Неизвестный формат заголовка хранилища" }
        require(parsed.slots.size == 2) { "Заголовок хранилища должен содержать ровно 2 слота ключей" }
        return parsed
    }

    /**
     * Создаёт новое Zero-Knowledge хранилище с 2 неотличимыми слотами ключей (Envelope Encryption).
     * Если [decoyPassword] == null, второй слот заполняется криптостойким шумом той же длины (48 байт),
     * чтобы криминалистическая экспертиза не могла доказать наличие или отсутствие ложного дна.
     */
    fun createVault(
        primaryPassword: CharArray,
        decoyPassword: CharArray? = null,
        kdfConfig: KdfConfig = KdfConfig.PRODUCTION_DEFAULT,
        envelopeSuite: AeadCipherSuite = AeadCipherSuite.XCHACHA20_POLY1305,
        nowEpochMs: Long = System.currentTimeMillis(),
    ): VaultCreationResult {
        require(primaryPassword.isNotEmpty()) { "Мастер-пароль не может быть пустым" }
        if (decoyPassword != null) {
            require(decoyPassword.isNotEmpty()) { "Пароль ложного дна не может быть пустым" }
            require(!primaryPassword.contentEquals(decoyPassword)) {
                "Пароль ложного дна должен отличаться от основного мастер-пароля"
            }
        }

        val vaultId = UUID.randomUUID().toString()
        val primaryVmk = CryptoRandom.nextBytes(VMK_BYTES)
        val decoyVmk = if (decoyPassword != null) CryptoRandom.nextBytes(VMK_BYTES) else null

        try {
            val slot0 = wrapVmkIntoSlot(
                slotIndex = VaultContour.PRIMARY.slotIndex,
                vaultId = vaultId,
                password = primaryPassword,
                vmk = primaryVmk,
                kdfConfig = kdfConfig,
                suite = envelopeSuite,
            )

            val slot1 = if (decoyPassword != null && decoyVmk != null) {
                wrapVmkIntoSlot(
                    slotIndex = VaultContour.DECOY.slotIndex,
                    vaultId = vaultId,
                    password = decoyPassword,
                    vmk = decoyVmk,
                    kdfConfig = kdfConfig,
                    suite = envelopeSuite,
                )
            } else {
                createChaffSlot(
                    slotIndex = VaultContour.DECOY.slotIndex,
                    suite = envelopeSuite,
                )
            }

            val header = VaultHeader(
                vaultId = vaultId,
                kdfConfig = kdfConfig,
                envelopeSuite = envelopeSuite,
                slots = listOf(slot0, slot1),
                updatedAtEpochMs = nowEpochMs,
            )

            val primarySession = HkdfSha256.deriveSessionHierarchy(VaultContour.PRIMARY, primaryVmk)
            val decoySession = decoyVmk?.let { HkdfSha256.deriveSessionHierarchy(VaultContour.DECOY, it) }

            return VaultCreationResult(
                header = header,
                primarySession = primarySession,
                decoySession = decoySession,
            )
        } finally {
            primaryVmk.wipe()
            decoyVmk?.wipe()
        }
    }

    /**
     * Проверяет оба слота заголовка без раннего выхода, обеспечивая одинаковое время работы
     * для основного контура и контура ложного дна.
     */
    fun unlockVault(header: VaultHeader, password: CharArray): VaultSessionKeys {
        require(header.slots.size == 2) { "Некорректное число слотов в заголовке" }

        var matchedContour: VaultContour? = null
        var matchedVmk: ByteArray? = null

        for (slot in header.slots) {
            val contour = if (slot.slotIndex == VaultContour.PRIMARY.slotIndex) {
                VaultContour.PRIMARY
            } else {
                VaultContour.DECOY
            }
            val unwrapped = tryUnwrapSlot(header, slot, password)
            if (unwrapped != null) {
                matchedVmk?.wipe()
                matchedContour = contour
                matchedVmk = unwrapped
            }
        }

        val vmk = matchedVmk ?: throw CryptoAuthException("Неверный мастер-пароль")
        val contour = matchedContour ?: throw CryptoAuthException("Неверный мастер-пароль")
        return try {
            HkdfSha256.deriveSessionHierarchy(contour, vmk)
        } finally {
            vmk.wipe()
        }
    }

    /**
     * Восстанавливает сессию напрямую из 32-байтного VMK, расшифрованного аппаратным ключом Android Keystore (BiometricPrompt).
     */
    fun unlockWithBiometricVmk(contour: VaultContour, rawVmk: ByteArray): VaultSessionKeys {
        require(rawVmk.size == VMK_BYTES) { "Некорректный размер биометрического VMK" }
        return HkdfSha256.deriveSessionHierarchy(contour, rawVmk)
    }

    /**
     * Смена пароля активного контура перешифровывает ТОЛЬКО 32-байтный VMK (гигабайты медиа не затрагиваются).
     */
    fun changePassword(
        header: VaultHeader,
        currentPassword: CharArray,
        newPassword: CharArray,
        newKdfConfig: KdfConfig = header.kdfConfig,
        nowEpochMs: Long = System.currentTimeMillis(),
    ): VaultHeader {
        require(newPassword.isNotEmpty()) { "Новый пароль не может быть пустым" }
        val activeSession = unlockVault(header, currentPassword)
        val targetSlotIndex = activeSession.contour.slotIndex

        // Убеждаемся, что новый пароль не совпадает с паролем соседнего контура
        val otherSlot = header.slots.first { it.slotIndex != targetSlotIndex }
        val collisionCheck = tryUnwrapSlot(header, otherSlot, newPassword)
        if (collisionCheck != null) {
            collisionCheck.wipe()
            activeSession.wipeAll()
            throw IllegalArgumentException("Новый пароль совпадает с паролем второго контура")
        }

        return try {
            activeSession.withVmk { vmk ->
                val updatedTargetSlot = wrapVmkIntoSlot(
                    slotIndex = targetSlotIndex,
                    vaultId = header.vaultId,
                    password = newPassword,
                    vmk = vmk,
                    kdfConfig = newKdfConfig,
                    suite = header.envelopeSuite,
                )
                val updatedSlots = header.slots.map { slot ->
                    if (slot.slotIndex == targetSlotIndex) updatedTargetSlot else slot
                }
                header.copy(
                    kdfConfig = newKdfConfig,
                    slots = updatedSlots,
                    updatedAtEpochMs = nowEpochMs,
                )
            }
        } finally {
            activeSession.wipeAll()
        }
    }

    /**
     * Активирует или обновляет контур ложного дна (Decoy Vault) с изолированным VMK.
     */
    fun configureDecoyPassword(
        header: VaultHeader,
        primaryPassword: CharArray,
        decoyPassword: CharArray,
        existingDecoyVmk: ByteArray? = null,
        nowEpochMs: Long = System.currentTimeMillis(),
    ): Pair<VaultHeader, VaultSessionKeys> {
        require(decoyPassword.isNotEmpty()) { "Пароль ложного дна не может быть пустым" }
        require(!primaryPassword.contentEquals(decoyPassword)) {
            "Пароль ложного дна должен отличаться от основного мастер-пароля"
        }

        val verifiedSession = unlockVault(header, primaryPassword)
        if (verifiedSession.contour != VaultContour.PRIMARY) {
            verifiedSession.wipeAll()
            throw CryptoAuthException("Для настройки ложного дна необходим основной мастер-пароль")
        }
        verifiedSession.wipeAll()

        val decoyVmk = existingDecoyVmk?.copyOf() ?: CryptoRandom.nextBytes(VMK_BYTES)
        try {
            val decoySlot = wrapVmkIntoSlot(
                slotIndex = VaultContour.DECOY.slotIndex,
                vaultId = header.vaultId,
                password = decoyPassword,
                vmk = decoyVmk,
                kdfConfig = header.kdfConfig,
                suite = header.envelopeSuite,
            )
            val newHeader = header.copy(
                slots = listOf(header.slots.first { it.slotIndex == 0 }, decoySlot),
                updatedAtEpochMs = nowEpochMs,
            )
            val decoySession = HkdfSha256.deriveSessionHierarchy(VaultContour.DECOY, decoyVmk)
            return newHeader to decoySession
        } finally {
            decoyVmk.wipe()
        }
    }

    fun encryptMeta(session: VaultSessionKeys, aadContext: String, plaintext: ByteArray): ByteArray =
        session.withMetaKey { kMeta ->
            EnvelopeCiphers.sealEnvelopeField(
                key = kMeta,
                plaintext = plaintext,
                aad = aadContext.toByteArray(Charsets.UTF_8),
                suite = AeadCipherSuite.AES_256_GCM,
            )
        }

    fun decryptMeta(session: VaultSessionKeys, aadContext: String, packedCiphertext: ByteArray): ByteArray =
        session.withMetaKey { kMeta ->
            EnvelopeCiphers.openEnvelopeField(
                key = kMeta,
                packed = packedCiphertext,
                aad = aadContext.toByteArray(Charsets.UTF_8),
            )
        }

    fun encryptMetaString(session: VaultSessionKeys, aadContext: String, text: String): ByteArray =
        encryptMeta(session, aadContext, text.toByteArray(Charsets.UTF_8))

    fun decryptMetaString(session: VaultSessionKeys, aadContext: String, packedCiphertext: ByteArray): String =
        String(decryptMeta(session, aadContext, packedCiphertext), Charsets.UTF_8)

    fun encryptThumbnail(session: VaultSessionKeys, mediaId: String, thumbBytes: ByteArray): ByteArray =
        session.withThumbKey { kThumb ->
            EnvelopeCiphers.sealEnvelopeField(
                key = kThumb,
                plaintext = thumbBytes,
                aad = "mvthumb:$mediaId".toByteArray(Charsets.UTF_8),
                suite = AeadCipherSuite.AES_256_GCM,
            )
        }

    fun decryptThumbnail(session: VaultSessionKeys, mediaId: String, encryptedThumb: ByteArray): ByteArray =
        session.withThumbKey { kThumb ->
            EnvelopeCiphers.openEnvelopeField(
                key = kThumb,
                packed = encryptedThumb,
                aad = "mvthumb:$mediaId".toByteArray(Charsets.UTF_8),
            )
        }

    private fun wrapVmkIntoSlot(
        slotIndex: Int,
        vaultId: String,
        password: CharArray,
        vmk: ByteArray,
        kdfConfig: KdfConfig,
        suite: AeadCipherSuite,
    ): EncryptedVmkSlot {
        val salt = CryptoRandom.nextBytes(SALT_BYTES)
        val nonce = CryptoRandom.nextBytes(EnvelopeCiphers.nonceSizeFor(suite))
        val kek = Argon2idKdf.deriveKek(password, salt, kdfConfig, outputLength = 32)
        val aad = buildSlotAad(vaultId, slotIndex, suite)
        return try {
            val wrapped = EnvelopeCiphers.encrypt(suite, kek, nonce, vmk, aad)
            EncryptedVmkSlot(
                slotIndex = slotIndex,
                saltBase64 = Base64.getEncoder().withoutPadding().encodeToString(salt),
                nonceBase64 = Base64.getEncoder().withoutPadding().encodeToString(nonce),
                wrappedVmkBase64 = Base64.getEncoder().withoutPadding().encodeToString(wrapped),
            )
        } finally {
            kek.wipe()
        }
    }

    private fun createChaffSlot(slotIndex: Int, suite: AeadCipherSuite): EncryptedVmkSlot {
        val salt = CryptoRandom.nextBytes(SALT_BYTES)
        val nonce = CryptoRandom.nextBytes(EnvelopeCiphers.nonceSizeFor(suite))
        val chaffWrapped = CryptoRandom.nextBytes(WRAPPED_VMK_CIPHERTEXT_BYTES)
        return EncryptedVmkSlot(
            slotIndex = slotIndex,
            saltBase64 = Base64.getEncoder().withoutPadding().encodeToString(salt),
            nonceBase64 = Base64.getEncoder().withoutPadding().encodeToString(nonce),
            wrappedVmkBase64 = Base64.getEncoder().withoutPadding().encodeToString(chaffWrapped),
        )
    }

    private fun tryUnwrapSlot(header: VaultHeader, slot: EncryptedVmkSlot, password: CharArray): ByteArray? {
        val salt = Base64.getDecoder().decode(slot.saltBase64)
        val nonce = Base64.getDecoder().decode(slot.nonceBase64)
        val wrapped = Base64.getDecoder().decode(slot.wrappedVmkBase64)
        val kek = Argon2idKdf.deriveKek(password, salt, header.kdfConfig, outputLength = 32)
        val aad = buildSlotAad(header.vaultId, slot.slotIndex, header.envelopeSuite)
        return try {
            EnvelopeCiphers.decrypt(header.envelopeSuite, kek, nonce, wrapped, aad)
        } catch (_: CryptoAuthException) {
            null
        } finally {
            kek.wipe()
        }
    }

    private fun buildSlotAad(vaultId: String, slotIndex: Int, suite: AeadCipherSuite): ByteArray =
        "meshvault:header:v2:$vaultId:slot=$slotIndex:suite=${suite.name}".toByteArray(Charsets.UTF_8)
}
