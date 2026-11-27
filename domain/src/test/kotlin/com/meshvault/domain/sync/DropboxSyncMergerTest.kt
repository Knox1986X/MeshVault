package com.meshvault.domain.sync

import com.meshvault.crypto.KdfConfig
import com.meshvault.crypto.VaultCryptoEngine
import com.meshvault.domain.model.BitwardenImporter
import com.meshvault.domain.model.MarkdownBlock
import com.meshvault.domain.model.MarkdownNoteEngine
import com.meshvault.domain.model.MediaItem
import com.meshvault.domain.model.MediaKind
import com.meshvault.domain.model.MvBackupCodec
import com.meshvault.domain.model.MvBackupPayload
import com.meshvault.domain.model.SecretEntry
import com.meshvault.domain.model.SecretEntryType
import com.meshvault.domain.model.VaultFolder
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class DropboxSyncMergerTest {

    @Test
    fun `crdt merger is commutative respects LWW HLC order and prevents tombstone resurrection`() {
        val clockPhoneA = HlcClock("phone-A")
        val clockPhoneB = HlcClock("phone-B")

        val t1 = clockPhoneA.nextTick(1_000L)
        val folderInitial = VaultFolder(
            id = "f-models",
            name = "Модели черновик",
            createdAtMs = 1_000L,
            updatedAtMs = 1_000L,
        )

        val t2 = clockPhoneA.nextTick(1_500L)
        val duplicatePhoto = MediaItem(
            id = "media-dup-99",
            folderId = "f-models",
            displayName = "pose_01_copy.jpg",
            mimeType = "image/jpeg",
            kind = MediaKind.PHOTO,
            width = 1080,
            height = 1920,
            plaintextSizeBytes = 900_000L,
            encryptedSizeBytes = 900_256L,
            blurHash = "LEHV6nWB2yk8pyo0adR*.7kCMdnj",
            dominantPaletteHex = listOf("#10B981"),
            cryptoBlake3BlindHex = "deadbeef",
            dHash64 = 42L,
            pHash64 = 84L,
            createdAtMs = 1_500L,
            updatedAtMs = 1_500L,
        )

        val baseManifest = VaultSyncManifest(
            compactedUpToHlc = t2,
            folders = mapOf(folderInitial.id to VersionedEntity(t1, folderInitial)),
            media = mapOf(duplicatePhoto.id to VersionedEntity(t2, duplicatePhoto)),
        )

        // Телефон B переименовал папку позже (t=2_200) и удалил дубликат фото с purgeCloudBlob=true (t=2_500)
        val tRenameB = clockPhoneB.nextTick(2_200L)
        val renamedFolder = folderInitial.copy(name = "Фото моделей", updatedAtMs = 2_200L)
        val tDeleteDupB = clockPhoneB.nextTick(2_500L)

        // Телефон A в офлайне пытался обновить тег у удаляемого фото чуть раньше удаления (t=2_100)
        val tStaleEditA = clockPhoneA.nextTick(2_100L)
        val staleEditedMedia = duplicatePhoto.copy(tags = listOf("старый-тег"), updatedAtMs = 2_100L)

        // Телефон A добавил новый пароль (t=2_600)
        val tNewSecretA = clockPhoneA.nextTick(2_600L)
        val newSecret = SecretEntry(
            id = "sec-github",
            type = SecretEntryType.LOGIN,
            title = "GitHub",
            username = "architect",
            password = "UltraSecretPassword!1",
            createdAtMs = 2_600L,
            updatedAtMs = 2_600L,
            passwordUpdatedAtMs = 2_600L,
        )

        val batchFromA = SyncDeltaBatch(
            batchId = "batch-A1",
            deviceNodeId = "phone-A",
            createdAtHlc = tNewSecretA,
            operations = listOf(
                SyncDeltaOp.UpsertMedia(tStaleEditA, staleEditedMedia),
                SyncDeltaOp.UpsertSecret(tNewSecretA, newSecret),
            ),
        )

        val batchFromB = SyncDeltaBatch(
            batchId = "batch-B1",
            deviceNodeId = "phone-B",
            createdAtHlc = tDeleteDupB,
            operations = listOf(
                SyncDeltaOp.UpsertFolder(tRenameB, renamedFolder),
                SyncDeltaOp.DeleteEntity(
                    hlc = tDeleteDupB,
                    kind = SyncEntityKind.MEDIA,
                    entityId = duplicatePhoto.id,
                    purgeCloudBlob = true,
                ),
            ),
        )

        // Порядок [A, B] и [B, A] должен давать абсолютно идентичный результат (коммутативность CRDT)
        val mergeAB = DropboxSyncMerger.merge(
            localManifest = baseManifest,
            remoteManifest = baseManifest,
            deltaBatches = listOf(batchFromA, batchFromB),
            nowEpochMs = 5_000L,
        )
        val mergeBA = DropboxSyncMerger.merge(
            localManifest = baseManifest,
            remoteManifest = baseManifest,
            deltaBatches = listOf(batchFromB, batchFromA),
            nowEpochMs = 5_000L,
        )

        assertEquals(mergeAB.mergedManifest, mergeBA.mergedManifest)
        assertEquals("Фото моделей", mergeAB.mergedManifest.folders["f-models"]?.entity?.name)
        assertFalse("Удалённый дубликат не должен воскреснуть из более раннего офлайн-апдейта",
            "media-dup-99" in mergeAB.mergedManifest.media)
        assertTrue("media-dup-99" in mergeAB.mediaIdsToPurgeInCloud)
        assertEquals("GitHub", mergeAB.mergedManifest.secrets["sec-github"]?.entity?.title)

        // Проверка шифрования манифеста и дельта-журнала ключом K_meta
        val vault = VaultCryptoEngine.createVault("SyncKey!2026".toCharArray(), kdfConfig = KdfConfig.FAST_TEST)
        val encManifest = DropboxSyncMerger.encryptManifest(vault.primarySession, mergeAB.mergedManifest)
        val decManifest = DropboxSyncMerger.decryptManifest(vault.primarySession, encManifest)
        assertEquals(mergeAB.mergedManifest, decManifest)

        val encDelta = DropboxSyncMerger.encryptDeltaBatch(vault.primarySession, batchFromB)
        val decDelta = DropboxSyncMerger.decryptDeltaBatch(vault.primarySession, batchFromB.batchId, encDelta)
        assertEquals(batchFromB, decDelta)
        vault.primarySession.wipeAll()
    }

    @Test
    fun `markdown checklist toggling bitwarden import and mvbackup roundtrip work end-to-end`() {
        val md = """
            # План съёмки референсов
            - [ ] Настроить контровой свет
            - [x] Зарядить стойки
            ```kotlin
            val secure = true
            ```
        """.trimIndent()

        val blocks = MarkdownNoteEngine.parseBlocks(md)
        val firstChecklist = blocks.filterIsInstance<MarkdownBlock.ChecklistItem>().first()
        assertFalse(firstChecklist.checked)

        val toggled = MarkdownNoteEngine.toggleChecklistLine(md, firstChecklist.lineIndex)
        val toggledBlocks = MarkdownNoteEngine.parseBlocks(toggled)
        assertTrue(toggledBlocks.filterIsInstance<MarkdownBlock.ChecklistItem>().first().checked)

        val bwJson = """
            {
              "folders": [{"id": "f1", "name": "Работа"}],
              "items": [
                {
                  "type": 1,
                  "folderId": "f1",
                  "name": "GitLab",
                  "favorite": true,
                  "login": {
                    "username": "knox",
                    "password": "Strong#GitLabPassword99",
                    "totp": "JBSWY3DPEHPK3PXP",
                    "uris": [{"uri": "https://gitlab.com/login"}, {"uri": "androidapp://com.gitlab.app"}]
                  }
                }
              ]
            }
        """.trimIndent().toByteArray(Charsets.UTF_8)

        val imported = BitwardenImporter.importFromJsonBytes(bwJson, nowMs = 10_000L)
        assertTrue("Буфер импорта должен быть занулён после парсинга", bwJson.all { it == 0.toByte() })
        assertEquals(1, imported.secrets.size)
        assertEquals("gitlab.com", imported.secrets.first().autofillDomains.first())
        assertEquals("com.gitlab.app", imported.secrets.first().autofillPackages.first())

        val backupBytes = MvBackupCodec.exportArchive(
            payload = MvBackupPayload(
                exportedAtMs = 10_000L,
                folders = emptyList(),
                secrets = imported.secrets,
                notes = imported.notes,
            ),
            backupPassword = "Backup#Password!77".toCharArray(),
            kdfConfig = KdfConfig.FAST_TEST,
        )
        val restored = MvBackupCodec.importArchive(backupBytes, "Backup#Password!77".toCharArray())
        assertEquals("GitLab", restored.secrets.first().title)
    }
}
