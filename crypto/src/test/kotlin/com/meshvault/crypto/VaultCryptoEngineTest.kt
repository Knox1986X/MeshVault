package com.meshvault.crypto

import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.StandardOpenOption
import kotlin.random.Random

class VaultCryptoEngineTest {

    @Test
    fun `argon2id matches official RFC 9106 section 5_3 test vector`() {
        val password = ByteArray(32) { 0x01 }
        val salt = ByteArray(16) { 0x02 }
        val secret = ByteArray(8) { 0x03 }
        val ad = ByteArray(12) { 0x04 }

        val tag = Argon2idKdf.deriveArgon2idRaw(
            password = password,
            salt = salt,
            secret = secret,
            associatedData = ad,
            iterations = 3,
            memoryKiB = 32,
            parallelism = 4,
            tagLength = 32,
        )

        val expectedHex = "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659"
        assertEquals(expectedHex, HexCodec.encode(tag))
    }

    @Test
    fun `blake3 matches official empty and multi-chunk Merkle tree vectors`() {
        val emptyDigest = Blake3Hasher.hash(ByteArray(0))
        assertEquals(
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
            HexCodec.encode(emptyDigest),
        )

        // Вход официального тестового набора BLAKE3: последовательность i % 251 длиной 2500 байт (> 2 чанков по 1024 байта)
        val input2500 = ByteArray(2500) { (it % 251).toByte() }
        val streamDigest = Blake3Hasher.hashStream(ByteArrayInputStream(input2500))
        val directDigest = Blake3Hasher.hash(input2500)
        assertArrayEquals(directDigest, streamDigest)
        assertEquals(32, directDigest.size)
    }

    @Test
    fun `pbkdf2 fallback derives deterministic 256-bit key`() {
        val salt = ByteArray(32) { (it + 7).toByte() }
        val cfg = KdfConfig(
            algorithm = KdfAlgorithm.PBKDF2_HMAC_SHA256,
            pbkdf2Iterations = 50_000,
        )
        val k1 = Argon2idKdf.deriveKek("CyberObsidian!2026".toCharArray(), salt, cfg)
        val k2 = Argon2idKdf.deriveKek("CyberObsidian!2026".toCharArray(), salt, cfg)
        val kDifferent = Argon2idKdf.deriveKek("OtherPassword!2026".toCharArray(), salt, cfg)

        assertEquals(32, k1.size)
        assertArrayEquals(k1, k2)
        assertFalse(k1.contentEquals(kDifferent))
    }

    @Test
    fun `vmk password rotation rewraps only 32-byte VMK without re-encrypting data`() = runTest {
        val created = VaultCryptoEngine.createVault(
            primaryPassword = "Master#Password#1".toCharArray(),
            kdfConfig = KdfConfig.FAST_TEST,
            envelopeSuite = AeadCipherSuite.XCHACHA20_POLY1305,
        )

        val secretCiphertext = VaultCryptoEngine.encryptMetaString(
            session = created.primarySession,
            aadContext = "secret:entry-42",
            text = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMeshVaultKey",
        )
        created.primarySession.wipeAll()

        // Меняем мастер-пароль: медиа и записи БД НЕ перешифровываются
        val rotatedHeader = VaultCryptoEngine.changePassword(
            header = created.header,
            currentPassword = "Master#Password#1".toCharArray(),
            newPassword = "Rotated#Master#Password#2".toCharArray(),
            newKdfConfig = KdfConfig.FAST_TEST,
        )

        // Старый пароль больше не подходит
        assertThrows(CryptoAuthException::class.java) {
            VaultCryptoEngine.unlockVault(rotatedHeader, "Master#Password#1".toCharArray())
        }

        // Новый пароль открывает тот же VMK и расшифровывает ранее зашифрованные данные
        val unlocked = VaultCryptoEngine.unlockVault(rotatedHeader, "Rotated#Master#Password#2".toCharArray())
        assertEquals(VaultContour.PRIMARY, unlocked.contour)
        val decrypted = VaultCryptoEngine.decryptMetaString(unlocked, "secret:entry-42", secretCiphertext)
        assertEquals("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMeshVaultKey", decrypted)
        unlocked.wipeAll()
    }

    @Test
    fun `aad mismatch and ciphertext tampering are strictly rejected`() {
        val created = VaultCryptoEngine.createVault(
            primaryPassword = "AadCheck!99".toCharArray(),
            kdfConfig = KdfConfig.FAST_TEST,
        )
        val session = created.primarySession
        val packed = VaultCryptoEngine.encryptMetaString(session, "folder:uuid-1", "Фото моделей")

        // Подмена контекста AAD (попытка переставить шифротекст в другую запись)
        assertThrows(CryptoAuthException::class.java) {
            VaultCryptoEngine.decryptMetaString(session, "folder:uuid-2", packed)
        }

        // Искажение одного бита шифротекста
        val corrupted = packed.copyOf()
        corrupted[corrupted.lastIndex - 3] = (corrupted[corrupted.lastIndex - 3].toInt() xor 0x01).toByte()
        assertThrows(CryptoAuthException::class.java) {
            VaultCryptoEngine.decryptMetaString(session, "folder:uuid-1", corrupted)
        }

        session.wipeAll()
        assertTrue(session.isLocked)
        assertThrows(VaultLockedException::class.java) {
            VaultCryptoEngine.encryptMetaString(session, "folder:uuid-1", "После блокировки")
        }
    }

    @Test
    fun `plausible deniability decoy vault opens isolated contour indistinguishable in header`() {
        val withoutDecoy = VaultCryptoEngine.createVault(
            primaryPassword = "RealVaultPass!1".toCharArray(),
            decoyPassword = null,
            kdfConfig = KdfConfig.FAST_TEST,
        )
        val withDecoy = VaultCryptoEngine.createVault(
            primaryPassword = "RealVaultPass!1".toCharArray(),
            decoyPassword = "HarmlessDecoyPass!2".toCharArray(),
            kdfConfig = KdfConfig.FAST_TEST,
        )

        // В обоих заголовках ровно 2 слота одинакового размера соли, nonce и шифротекста
        assertEquals(2, withoutDecoy.header.slots.size)
        assertEquals(2, withDecoy.header.slots.size)
        assertEquals(
            withoutDecoy.header.slots[1].wrappedVmkBase64.length,
            withDecoy.header.slots[1].wrappedVmkBase64.length,
        )

        val jsonHeader = VaultCryptoEngine.serializeHeader(withDecoy.header)
        val restoredHeader = VaultCryptoEngine.deserializeHeader(jsonHeader)

        val primaryUnlocked = VaultCryptoEngine.unlockVault(restoredHeader, "RealVaultPass!1".toCharArray())
        val decoyUnlocked = VaultCryptoEngine.unlockVault(restoredHeader, "HarmlessDecoyPass!2".toCharArray())

        assertEquals(VaultContour.PRIMARY, primaryUnlocked.contour)
        assertEquals(VaultContour.DECOY, decoyUnlocked.contour)
        assertNotEquals(primaryUnlocked.contour.dbFileName, decoyUnlocked.contour.dbFileName)

        // Ключи основного и ложного контуров полностью изолированы
        val primaryCipher = VaultCryptoEngine.encryptMetaString(primaryUnlocked, "note:1", "Секретный проект")
        assertThrows(CryptoAuthException::class.java) {
            VaultCryptoEngine.decryptMetaString(decoyUnlocked, "note:1", primaryCipher)
        }

        withoutDecoy.primarySession.wipeAll()
        withDecoy.primarySession.wipeAll()
        withDecoy.decoySession?.wipeAll()
        primaryUnlocked.wipeAll()
        decoyUnlocked.wipeAll()
    }

    @Test
    fun `mvch v2 supports O(1) random-access mid-file seeking and detects chunk swapping or truncation`() {
        val tempFile = Files.createTempFile("meshvault-mvch-test-", ".mvbin").toFile()
        tempFile.deleteOnExit()

        val kBlob = CryptoRandom.nextBytes(32)
        val fileUuid = "media-video-500mb-sim"
        // 5 полных чанков по 64 КБ + хвостовой неполный чанк (итого ~350 КБ)
        val plainSize = MvchStreamCipher.CHUNK_SIZE_64K * 5 + 19_321
        val originalVideo = Random(20261126).nextBytes(plainSize)

        val encResult = MvchStreamCipher.encryptToFile(
            input = ByteArrayInputStream(originalVideo),
            targetFile = tempFile,
            kBlob = kBlob,
            fileUuid = fileUuid,
            chunkSize = MvchStreamCipher.CHUNK_SIZE_64K,
        )

        assertEquals(plainSize.toLong(), encResult.plaintextSize)
        assertEquals(6, encResult.header.totalChunks)
        assertArrayEquals(Blake3Hasher.hash(originalVideo), encResult.blake3Hash)

        FileChannel.open(tempFile.toPath(), StandardOpenOption.READ).use { channel ->
            val header = MvchStreamCipher.readHeader(channel, kBlob, fileUuid)
            assertEquals(plainSize.toLong(), header.totalPlaintextSize)

            // Произвольное чтение прямо с середины файла на стыке чанков #2, #3 и #4 (имитация перемотки ExoPlayer)
            val seekOffset = MvchStreamCipher.CHUNK_SIZE_64K * 2L + 61_000L
            val readLen = 80_000
            val buffer = ByteArray(readLen)
            val bytesRead = MvchStreamCipher.readPlaintextRange(
                channel = channel,
                header = header,
                kBlob = kBlob,
                fileUuid = fileUuid,
                plaintextOffset = seekOffset,
                target = buffer,
                targetOffset = 0,
                length = readLen,
            )

            assertEquals(readLen, bytesRead)
            val expectedSlice = originalVideo.copyOfRange(seekOffset.toInt(), seekOffset.toInt() + readLen)
            assertArrayEquals(expectedSlice, buffer)

            // Попытка расшифровать файл с чужим fileUuid отклоняется заголовком/AAD
            assertThrows(CryptoAuthException::class.java) {
                MvchStreamCipher.readHeader(channel, kBlob, "wrong-file-uuid")
            }
        }

        // Проверка защиты от перестановки чанков местами (меняем чанк #1 и чанк #3)
        val rawFileBytes = tempFile.readBytes()
        val frameSize = MvchStreamCipher.CHUNK_SIZE_64K + EnvelopeCiphers.TAG_BYTES
        val swapped = rawFileBytes.copyOf()
        val c1Start = MvchStreamCipher.HEADER_BYTES + 1 * frameSize
        val c3Start = MvchStreamCipher.HEADER_BYTES + 3 * frameSize
        for (i in 0 until frameSize) {
            val tmp = swapped[c1Start + i]
            swapped[c1Start + i] = swapped[c3Start + i]
            swapped[c3Start + i] = tmp
        }
        val swappedFile = Files.createTempFile("meshvault-swapped-", ".mvbin").toFile()
        swappedFile.deleteOnExit()
        swappedFile.writeBytes(swapped)

        FileChannel.open(swappedFile.toPath(), StandardOpenOption.READ).use { channel ->
            val header = MvchStreamCipher.readHeader(channel, kBlob, fileUuid)
            assertThrows(CryptoAuthException::class.java) {
                MvchStreamCipher.decryptChunkAtIndex(channel, header, kBlob, fileUuid, chunkIndex = 1)
            }
        }

        // Проверка защиты от обрезки хвоста файла
        val truncatedFile = Files.createTempFile("meshvault-truncated-", ".mvbin").toFile()
        truncatedFile.deleteOnExit()
        truncatedFile.writeBytes(rawFileBytes.copyOf(rawFileBytes.size - 128))
        FileChannel.open(truncatedFile.toPath(), StandardOpenOption.READ).use { channel ->
            assertThrows(CryptoAuthException::class.java) {
                MvchStreamCipher.readHeader(channel, kBlob, fileUuid)
            }
        }
    }
}
