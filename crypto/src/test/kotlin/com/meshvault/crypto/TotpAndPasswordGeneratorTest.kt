package com.meshvault.crypto

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class TotpAndPasswordGeneratorTest {

    @Test
    fun `totp matches official RFC 6238 Appendix B vectors for SHA1 SHA256 and SHA512`() {
        val sha1Seed = "12345678901234567890".toByteArray(Charsets.US_ASCII)
        // 32-байтный и 64-байтный ASCII-секреты согласно RFC 6238 Appendix B
        val sha256Seed = "12345678901234567890123456789012".toByteArray(Charsets.US_ASCII)
        val sha512Seed = "1234567890123456789012345678901234567890123456789012345678901234"
            .toByteArray(Charsets.US_ASCII)

        val cases = listOf(
            59L to Triple("94287082", "46119246", "90693936"),
            1111111109L to Triple("07081804", "68084774", "25091201"),
            1111111111L to Triple("14050471", "67062674", "99943326"),
            1234567890L to Triple("89005924", "91819424", "93441116"),
            2000000000L to Triple("69279037", "90698825", "38618901"),
            20000000000L to Triple("65353130", "77737706", "47863826"),
        )

        for ((epochSec, expected) in cases) {
            assertEquals(
                "SHA1 @ $epochSec",
                expected.first,
                TotpGenerator.generateFromRawSecret(sha1Seed, epochSec, TotpAlgorithm.SHA1, digits = 8),
            )
            assertEquals(
                "SHA256 @ $epochSec",
                expected.second,
                TotpGenerator.generateFromRawSecret(sha256Seed, epochSec, TotpAlgorithm.SHA256, digits = 8),
            )
            assertEquals(
                "SHA512 @ $epochSec",
                expected.third,
                TotpGenerator.generateFromRawSecret(sha512Seed, epochSec, TotpAlgorithm.SHA512, digits = 8),
            )
        }
    }

    @Test
    fun `otpauth URI parser and Base32 roundtrip preserve issuer digits and algorithm`() {
        val rawUri = "otpauth://totp/GitHub:dev%40meshvault.io?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&algorithm=SHA256&digits=6&period=30"
        val parsed = TotpGenerator.parseInputOrUri(rawUri)
        assertEquals("GitHub", parsed.issuer)
        assertEquals("dev@meshvault.io", parsed.accountName)
        assertEquals("JBSWY3DPEHPK3PXP", parsed.secretBase32)
        assertEquals(TotpAlgorithm.SHA256, parsed.algorithm)
        assertEquals(6, parsed.digits)
        assertEquals(30, parsed.periodSeconds)

        val rebuilt = TotpGenerator.toOtpAuthUri(parsed)
        val reparsed = TotpGenerator.parseInputOrUri(rebuilt)
        assertEquals(parsed, reparsed)

        // 1_700_000_010 делится на 30 нацело, значит в +5с остаётся ровно 25 секунд до смены окна
        val snap = TotpGenerator.generateSnapshot(parsed, epochMillis = 1_700_000_015_000L)
        assertEquals(6, snap.code.length)
        assertEquals(25, snap.secondsRemaining)
    }

    @Test
    fun `password generator diceware and health audit detect weak reused and stale credentials`() {
        val strongPwd = PasswordGenerator.generatePassword(PasswordGenOptions(length = 24))
        assertEquals(24, strongPwd.length)
        val strongEntropy = PasswordGenerator.evaluateEntropy(strongPwd)
        assertTrue("Ожидалась высокая энтропия, получено ${strongEntropy.entropyBits}", strongEntropy.entropyBits >= 95.0)

        val passphrase = PasswordGenerator.generatePassphrase(DicewareOptions(wordCount = 5, separator = "-"))
        assertEquals(5, passphrase.split("-").size)
        assertTrue(PasswordGenerator.evaluateEntropy(passphrase).entropyBits >= 75.0)

        val now = 1_795_718_000_000L
        val yearAgo = now - 365L * 86_400_000L
        val audit = PasswordGenerator.auditVaultPasswords(
            credentials = listOf(
                AuditableCredential("1", "GitHub", strongPwd, now),
                AuditableCredential("2", "OldForum", "123456", yearAgo),
                AuditableCredential("3", "ShopA", "SamePass!99", now),
                AuditableCredential("4", "ShopB", "SamePass!99", now),
            ),
            nowEpochMs = now,
        )

        assertTrue("1" !in audit.weakEntries)
        assertTrue("2" in audit.weakEntries)
        assertTrue("2" in audit.staleEntries)
        assertEquals(1, audit.reusedGroups.size)
        assertEquals(listOf("3", "4"), audit.reusedGroups.values.first())
        assertTrue(audit.securityScore in 1..85)
    }
}
