package io.github.knox1986x.meshvault.security

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SecurityGuardsTest {

    @Test
    fun decoyVaultTrashShredAndCleanExportWorkInBackend() {
        val backend = InMemoryVaultBackend()
        backend.createVault("Main", "real-pass")
        backend.configureDecoyVault("decoy-pass")

        val root = backend.rootFolderId()
        // Minimal JPEG containing an APP1 EXIF segment that Clean Export must strip.
        val jpegWithExif = byteArrayOf(
            0xFF.toByte(), 0xD8.toByte(),
            0xFF.toByte(), 0xE1.toByte(), 0x00, 0x08, 0x45, 0x78, 0x69, 0x66, 0x00, 0x00,
            0xFF.toByte(), 0xDA.toByte(), 0x00, 0x02, 0xFF.toByte(), 0xD9.toByte(),
        )
        val mediaId = backend.importStreamItem(
            targetParentId = root,
            relativeSegments = listOf("Private"),
            fileName = "id_scan.jpg",
            bytes = jpegWithExif,
            policy = DedupPolicy.SKIP_DUPLICATE,
        )!!

        val cleaned = backend.cleanExportBytes(mediaId)
        assertFalse(cleaned.toList().windowed(4).any { it == listOf<Byte>(0x45, 0x78, 0x69, 0x66) })

        // Move to Trash -> restore -> trash again -> purge after 31 days.
        val t0 = 1_700_000_000_000L
        backend.moveToTrash(mediaId, t0)
        assertEquals(0, backend.listAllMediaTimeline().size)
        assertEquals(1, backend.listTrashedMedia().size)
        backend.restoreFromTrash(mediaId)
        assertEquals(1, backend.listAllMediaTimeline().size)

        backend.moveToTrash(mediaId, t0)
        val purged = backend.purgeExpiredTrash(30, t0 + 31L * 86_400_000L)
        assertEquals(1L, purged)
        assertEquals(0, backend.listTrashedMedia().size)

        // Safe Presentation lock requires passphrase to exit back to UNLOCKED_FULL.
        backend.enterSafePresentation(emptySet())
        assertFalse(backend.exitSafePresentationWithPassphrase("wrong-pass"))
        assertEquals(VaultSecurityState.UNLOCKED_SAFE_PRESENTATION, backend.securityState)
        assertTrue(backend.exitSafePresentationWithPassphrase("real-pass"))
        assertEquals(VaultSecurityState.UNLOCKED_FULL, backend.securityState)

        // Switching to Decoy passphrase isolates decoy folders/media from real vault.
        backend.lock()
        assertTrue(backend.unlockWithPassphrase("decoy-pass"))
        assertEquals(VaultSecurityState.UNLOCKED_DECOY, backend.securityState)
        assertEquals(0L, backend.vaultMetrics().totalMedia)
    }

    @Test
    fun thermalBatteryGuardAndInboxWatcherBehaveCorrectly() {
        assertTrue(
            ThermalBatteryGuard.shouldPauseHeavyWork(
                ThermalBatteryGuard.PowerThermalStatus(
                    batteryPercent = 85,
                    isCharging = true,
                    temperatureTenthsCelsius = 435,
                ),
            ),
        )
        assertTrue(
            ThermalBatteryGuard.shouldPauseHeavyWork(
                ThermalBatteryGuard.PowerThermalStatus(
                    batteryPercent = 12,
                    isCharging = false,
                    temperatureTenthsCelsius = 320,
                ),
            ),
        )
        assertFalse(
            ThermalBatteryGuard.shouldPauseHeavyWork(
                ThermalBatteryGuard.PowerThermalStatus(
                    batteryPercent = 50,
                    isCharging = false,
                    temperatureTenthsCelsius = 360,
                ),
            ),
        )

        val candidates = InboxFolderWatcher.findNewCandidateIds(
            currentDocumentIds = listOf("doc-1", "doc-2", "doc-3"),
            alreadyProcessedIds = setOf("doc-1"),
        )
        assertEquals(listOf("doc-2", "doc-3"), candidates)
    }
}
