package com.meshvault.crypto

import kotlin.math.ln
import kotlin.math.roundToInt

data class PasswordGenOptions(
    val length: Int = 20,
    val includeLowercase: Boolean = true,
    val includeUppercase: Boolean = true,
    val includeDigits: Boolean = true,
    val includeSymbols: Boolean = true,
    val excludeAmbiguous: Boolean = true,
)

data class DicewareOptions(
    val wordCount: Int = 5,
    val separator: String = "-",
    val capitalizeWords: Boolean = true,
    val appendNumber: Boolean = true,
)

enum class PasswordStrengthLevel(val labelRu: String) {
    CRITICAL("Критически слабый"),
    WEAK("Слабый"),
    FAIR("Средний"),
    STRONG("Надёжный"),
    FORTRESS("Криптостойкий"),
}

data class EntropyReport(
    val entropyBits: Double,
    val level: PasswordStrengthLevel,
    val warningsRu: List<String>,
)

data class AuditableCredential(
    val id: String,
    val title: String,
    val password: String,
    val passwordUpdatedAtMs: Long,
)

data class PasswordAuditReport(
    val securityScore: Int, // 0..100
    val totalCount: Int,
    val weakEntries: List<String>,
    val reusedGroups: Map<String, List<String>>, // blindKey -> list of entry IDs
    val staleEntries: List<String>,
)

object PasswordGenerator {
    private const val LOWER = "abcdefghijklmnopqrstuvwxyz"
    private const val UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    private const val DIGITS = "0123456789"
    private const val SYMBOLS = "!@#$%^&*()-_=+[]{};:,.<>?"
    private val AMBIGUOUS = setOf('0', 'O', 'o', '1', 'l', 'I', '|')

    // Курированный крипто-словарь для Diceware (высокоразличимые корни без омофонов)
    private val DICEWARE_WORDS = listOf(
        "obsidian", "cipher", "nebula", "quantum", "falcon", "granite", "aurora", "vortex",
        "cobalt", "prism", "horizon", "tundra", "zenith", "ember", "glacier", "monolith",
        "vector", "photon", "argon", "basalt", "cosmos", "delta", "eclipse", "fjord",
        "galaxy", "helium", "iridium", "jasper", "krypton", "lumen", "magnet", "neutron",
        "onyx", "pulsar", "quartz", "reactor", "solstice", "titanium", "umbra", "velvet",
        "whisper", "xenon", "yarrow", "zircon", "anchor", "breeze", "canyon", "dynamo",
        "emerald", "fortress", "griffin", "harbor", "impulse", "javelin", "keystone", "lantern",
        "mirage", "nimbus", "orbit", "paradox", "quasar", "ripple", "sapphire", "tempest",
        "utopia", "valkyrie", "warden", "zephyr", "alchemy", "bastion", "cascade", "drift",
        "enigma", "fission", "galleon", "halcyon", "isotope", "jubilee", "kinetic", "labyrinth",
        "meridian", "nocturne", "odyssey", "pinnacle", "relic", "sentinel", "talisman", "uplink",
        "vanguard", "wildfire", "zenithal", "acorn", "beacon", "citadel", "dagger", "equinox",
        "firefly", "garnet", "helios", "icicle", "juniper", "kestrel", "lyrical", "mariner",
        "nectar", "outpost", "phoenix", "quarry", "redwood", "starlight", "trident", "urchin",
        "voyager", "wayfarer", "xylem", "yonder", "zodiac", "atlas", "blizzard", "compass",
        "dominion", "evergreen", "foundry", "gondola", "hologram", "infinitum", "jackdaw", "monarch",
    )

    fun generatePassword(options: PasswordGenOptions = PasswordGenOptions()): String {
        require(options.length in 6..128) { "Длина пароля должна быть от 6 до 128 символов" }

        val groups = mutableListOf<List<Char>>()
        fun filterChars(raw: String): List<Char> =
            if (options.excludeAmbiguous) raw.toList().filterNot { it in AMBIGUOUS } else raw.toList()

        if (options.includeLowercase) groups += filterChars(LOWER)
        if (options.includeUppercase) groups += filterChars(UPPER)
        if (options.includeDigits) groups += filterChars(DIGITS)
        if (options.includeSymbols) groups += filterChars(SYMBOLS)
        require(groups.isNotEmpty()) { "Выберите хотя бы один набор символов" }

        val fullPool = groups.flatten().distinct()
        val result = CharArray(options.length)

        // Гарантируем минимум по 1 символу из каждой выбранной категории
        var pos = 0
        for (group in groups) {
            if (pos < result.size) {
                result[pos++] = group[CryptoRandom.nextInt(group.size)]
            }
        }
        while (pos < result.size) {
            result[pos++] = fullPool[CryptoRandom.nextInt(fullPool.size)]
        }

        // Криптостойкое перемешивание Фишера—Йетса
        for (i in result.lastIndex downTo 1) {
            val j = CryptoRandom.nextInt(i + 1)
            val tmp = result[i]
            result[i] = result[j]
            result[j] = tmp
        }
        return String(result)
    }

    fun generatePassphrase(options: DicewareOptions = DicewareOptions()): String {
        require(options.wordCount in 3..12) { "Количество слов парольной фразы должно быть от 3 до 12" }
        val chosen = (0 until options.wordCount).map {
            val word = DICEWARE_WORDS[CryptoRandom.nextInt(DICEWARE_WORDS.size)]
            if (options.capitalizeWords) {
                word.replaceFirstChar { c -> c.uppercaseChar() }
            } else {
                word
            }
        }.toMutableList()

        if (options.appendNumber) {
            val idx = CryptoRandom.nextInt(chosen.size)
            val suffix = 10 + CryptoRandom.nextInt(90)
            chosen[idx] = "${chosen[idx]}$suffix"
        }
        return chosen.joinToString(options.separator)
    }

    fun evaluateEntropy(password: String): EntropyReport {
        if (password.isEmpty()) {
            return EntropyReport(
                entropyBits = 0.0,
                level = PasswordStrengthLevel.CRITICAL,
                warningsRu = listOf("Пароль пуст"),
            )
        }

        var pool = 0
        if (password.any { it in 'a'..'z' }) pool += 26
        if (password.any { it in 'A'..'Z' }) pool += 26
        if (password.any { it in '0'..'9' }) pool += 10
        if (password.any { !it.isLetterOrDigit() && it.code < 128 }) pool += 32
        if (password.any { it.code >= 128 }) pool += 66
        if (pool == 0) pool = 26

        val uniqueRatio = password.toSet().size.toDouble() / password.length.toDouble()
        val effectiveLength = password.length * (0.55 + 0.45 * uniqueRatio)
        var bits = effectiveLength * (ln(pool.toDouble()) / ln(2.0))

        val warnings = mutableListOf<String>()
        if (password.length < 10) {
            warnings += "Длина менее 10 символов уязвима к перебору на GPU"
        }
        if (hasSequentialRun(password)) {
            bits *= 0.72
            warnings += "Обнаружена последовательность символов (например, 1234 или abcd)"
        }
        if (uniqueRatio < 0.45) {
            warnings += "Много повторяющихся символов снижает реальную энтропию"
        }

        val level = when {
            bits < 36.0 -> PasswordStrengthLevel.CRITICAL
            bits < 58.0 -> PasswordStrengthLevel.WEAK
            bits < 78.0 -> PasswordStrengthLevel.FAIR
            bits < 105.0 -> PasswordStrengthLevel.STRONG
            else -> PasswordStrengthLevel.FORTRESS
        }

        return EntropyReport(
            entropyBits = (bits * 10.0).roundToInt() / 10.0,
            level = level,
            warningsRu = warnings,
        )
    }

    fun auditVaultPasswords(
        credentials: List<AuditableCredential>,
        nowEpochMs: Long = System.currentTimeMillis(),
        staleThresholdDays: Long = 180L,
    ): PasswordAuditReport {
        if (credentials.isEmpty()) {
            return PasswordAuditReport(
                securityScore = 100,
                totalCount = 0,
                weakEntries = emptyList(),
                reusedGroups = emptyMap(),
                staleEntries = emptyList(),
            )
        }

        val staleCutoffMs = nowEpochMs - staleThresholdDays * 86_400_000L
        val weak = mutableListOf<String>()
        val stale = mutableListOf<String>()
        val byHash = linkedMapOf<String, MutableList<String>>()
        val auditKey = CryptoRandom.nextBytes(32)

        try {
            for (item in credentials) {
                if (item.password.isBlank()) continue
                val report = evaluateEntropy(item.password)
                if (report.entropyBits < 58.0) {
                    weak += item.id
                }
                if (item.passwordUpdatedAtMs in 1 until staleCutoffMs) {
                    stale += item.id
                }
                val pwdBytes = item.password.toByteArray(Charsets.UTF_8)
                val blind = BlindIndex.computeBlindHex(auditKey, "audit", pwdBytes)
                pwdBytes.wipe()
                byHash.getOrPut(blind) { mutableListOf() }.add(item.id)
            }
        } finally {
            auditKey.wipe()
        }

        val reused = byHash.filterValues { it.size > 1 }
        val reusedCount = reused.values.sumOf { it.size }

        val total = credentials.size.coerceAtLeast(1)
        val weakPenalty = (weak.size * 45.0) / total
        val reusedPenalty = (reusedCount * 35.0) / total
        val stalePenalty = (stale.size * 20.0) / total
        val score = (100.0 - weakPenalty - reusedPenalty - stalePenalty).roundToInt().coerceIn(0, 100)

        return PasswordAuditReport(
            securityScore = score,
            totalCount = credentials.size,
            weakEntries = weak,
            reusedGroups = reused,
            staleEntries = stale,
        )
    }

    private fun hasSequentialRun(s: String): Boolean {
        if (s.length < 4) return false
        var asc = 1
        var desc = 1
        for (i in 1 until s.length) {
            val diff = s[i].code - s[i - 1].code
            asc = if (diff == 1) asc + 1 else 1
            desc = if (diff == -1) desc + 1 else 1
            if (asc >= 4 || desc >= 4) return true
        }
        return false
    }
}
