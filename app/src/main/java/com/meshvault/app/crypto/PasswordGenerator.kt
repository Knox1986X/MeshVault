package com.meshvault.app.crypto

import java.security.SecureRandom
import kotlin.math.log2

data class PasswordOptions(
    val length: Int = 16,
    val includeUppercase: Boolean = true,
    val includeLowercase: Boolean = true,
    val includeDigits: Boolean = true,
    val includeSymbols: Boolean = true,
    val avoidAmbiguous: Boolean = false
)

enum class PasswordStrength(val label: String, val score: Float) {
    WEAK("Слабый", 0.25f),
    FAIR("Средний", 0.5f),
    STRONG("Надёжный", 0.75f),
    EXCELLENT("Отличный", 1.0f)
}

object PasswordGenerator {
    private val random = SecureRandom()

    private const val UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    private const val UPPER_NO_AMBIG = "ABCDEFGHJKLMNPQRSTUVWXYZ"
    private const val LOWER = "abcdefghijklmnopqrstuvwxyz"
    private const val LOWER_NO_AMBIG = "abcdefghijkmnopqrstuvwxyz"
    private const val DIGITS = "0123456789"
    private const val DIGITS_NO_AMBIG = "23456789"
    private const val SYMBOLS = "!@#$%^&*()-_=+[]{};:,.<>?"

    private val WORD_LIST = listOf(
        "amber", "anchor", "atlas", "aurora", "beacon", "breeze", "canyon", "cipher",
        "comet", "coral", "cosmos", "crystal", "delta", "drift", "eclipse", "ember",
        "falcon", "fjord", "forest", "galaxy", "glacier", "granite", "harbor", "horizon",
        "indigo", "island", "jasper", "kestrel", "lagoon", "lantern", "lumen", "marble",
        "meadow", "meteor", "mirage", "nebula", "nectar", "nordic", "obsidian", "onyx",
        "orbit", "osprey", "pebble", "phoenix", "prism", "quartz", "raven", "ridge",
        "river", "saffron", "shield", "silver", "solstice", "spark", "summit", "timber",
        "topaz", "vector", "velvet", "vertex", "voyage", "willow", "zenith", "zephyr"
    )

    fun generatePassword(options: PasswordOptions): String {
        val pools = mutableListOf<String>()
        if (options.includeUppercase) {
            pools += if (options.avoidAmbiguous) UPPER_NO_AMBIG else UPPER
        }
        if (options.includeLowercase) {
            pools += if (options.avoidAmbiguous) LOWER_NO_AMBIG else LOWER
        }
        if (options.includeDigits) {
            pools += if (options.avoidAmbiguous) DIGITS_NO_AMBIG else DIGITS
        }
        if (options.includeSymbols) {
            pools += SYMBOLS
        }
        if (pools.isEmpty()) {
            pools += LOWER
        }

        val allChars = pools.joinToString("")
        val result = CharArray(options.length.coerceIn(6, 64))

        // Гарантируем хотя бы по одному символу из каждой выбранной категории
        var idx = 0
        for (pool in pools) {
            if (idx < result.size) {
                result[idx++] = pool[random.nextInt(pool.length)]
            }
        }
        while (idx < result.size) {
            result[idx++] = allChars[random.nextInt(allChars.length)]
        }

        // Перемешивание Фишера-Йейтса
        for (i in result.size - 1 downTo 1) {
            val j = random.nextInt(i + 1)
            val tmp = result[i]
            result[i] = result[j]
            result[j] = tmp
        }
        return String(result)
    }

    fun generatePassphrase(wordCount: Int = 5, separator: String = "-", capitalize: Boolean = true): String {
        val count = wordCount.coerceIn(3, 10)
        return (0 until count).joinToString(separator) {
            val word = WORD_LIST[random.nextInt(WORD_LIST.size)]
            if (capitalize) word.replaceFirstChar { c -> c.uppercase() } else word
        }
    }

    fun evaluateStrength(password: String): PasswordStrength {
        if (password.isEmpty()) return PasswordStrength.WEAK
        var poolSize = 0
        if (password.any { it.isLowerCase() }) poolSize += 26
        if (password.any { it.isUpperCase() }) poolSize += 26
        if (password.any { it.isDigit() }) poolSize += 10
        if (password.any { !it.isLetterOrDigit() }) poolSize += 28
        if (poolSize == 0) poolSize = 26

        val entropy = password.length * log2(poolSize.toDouble())
        return when {
            entropy < 40 -> PasswordStrength.WEAK
            entropy < 60 -> PasswordStrength.FAIR
            entropy < 80 -> PasswordStrength.STRONG
            else -> PasswordStrength.EXCELLENT
        }
    }
}
