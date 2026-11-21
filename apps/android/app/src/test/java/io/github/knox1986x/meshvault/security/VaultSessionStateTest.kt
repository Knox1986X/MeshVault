package io.github.knox1986x.meshvault.security

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class VaultSessionStateTest {

    @Test
    fun nestedFolderImportDeduplicationAndSafePresentationWork() {
        val backend = InMemoryVaultBackend()
        assertEquals(VaultSecurityState.LOCKED, backend.securityState)
        assertTrue(backend.unlockWithPassphrase("strong-passphrase"))
        assertEquals(VaultSecurityState.UNLOCKED_FULL, backend.securityState)

        val root = backend.rootFolderId()
        val payload = byteArrayOf(0xFF.toByte(), 0xD8.toByte(), 0xFF.toByte(), 0xE0.toByte(), 1, 2, 3, 4)

        val first = backend.importStreamItem(
            targetParentId = root,
            relativeSegments = listOf("2026", "Отпуск"),
            fileName = "beach.jpg",
            bytes = payload,
            policy = DedupPolicy.SKIP_DUPLICATE,
        )
        assertNotNull(first)

        val duplicate = backend.importStreamItem(
            targetParentId = root,
            relativeSegments = listOf("2026", "Отпуск"),
            fileName = "beach_copy.jpg",
            bytes = payload,
            policy = DedupPolicy.SKIP_DUPLICATE,
        )
        assertEquals(null, duplicate)

        val metrics = backend.vaultMetrics()
        assertEquals(1L, metrics.totalMedia)
        assertEquals(2L, metrics.folderCount)

        val item = backend.listAllMediaTimeline().first()
        backend.enterSafePresentation(setOf(item.id))
        assertEquals(VaultSecurityState.UNLOCKED_SAFE_PRESENTATION, backend.securityState)
        assertTrue(backend.readMediaAllBytes(item.id).contentEquals(payload))

        backend.lock()
        assertEquals(VaultSecurityState.LOCKED, backend.securityState)
        assertFalse(backend.readMediaAllBytes(item.id).isNotEmpty())
    }
}
