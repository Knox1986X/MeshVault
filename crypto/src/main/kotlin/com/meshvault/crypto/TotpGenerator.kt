package com.meshvault.crypto

import kotlinx.serialization.Serializable
import java.net.URLDecoder
import java.net.URLEncoder
import java.nio.ByteBuffer
import java.nio.ByteOrder
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlin.math.pow

@Serializable
enum class TotpAlgorithm(val jcaHmacName: String) {
    SHA1("HmacSHA1"),
    SHA256("HmacSHA256"),
    SHA512("HmacSHA512"),
}

@Serializable
data class TotpConfig(
    val secretBase32: String,
    val issuer: String = "",
    val accountName: String = "",
    val algorithm: TotpAlgorithm = TotpAlgorithm.SHA1,
    val digits: Int = 6,
    val periodSeconds: Int = 30,
) {
    init {
        require(digits == 6 || digits == 8) { "Поддерживаются 6- и 8-значные коды TOTP" }
        require(periodSeconds in 10..120) { "Период TOTP должен быть от 10 до 120 секунд" }
    }
}

data class TotpSnapshot(
    val code: String,
    val secondsRemaining: Int,
    val progressFraction: Float,
)

/**
 * Полноценный генератор TOTP 2FA по стандарту RFC 6238 (SHA1 / SHA256 / SHA512, 6 / 8 цифр)
 * с парсером QR-ссылок `otpauth://totp/...`.
 */
object TotpGenerator {

    fun generateCode(
        config: TotpConfig,
        epochSeconds: Long = System.currentTimeMillis() / 1000L,
    ): String {
        val secretBytes = Base32Codec.decode(config.secretBase32)
        return try {
            generateFromRawSecret(
                secretBytes = secretBytes,
                epochSeconds = epochSeconds,
                algorithm = config.algorithm,
                digits = config.digits,
                periodSeconds = config.periodSeconds,
            )
        } finally {
            secretBytes.wipe()
        }
    }

    fun generateSnapshot(
        config: TotpConfig,
        epochMillis: Long = System.currentTimeMillis(),
    ): TotpSnapshot {
        val epochSeconds = epochMillis / 1000L
        val code = generateCode(config, epochSeconds)
        val periodMs = config.periodSeconds * 1000L
        val elapsedMs = epochMillis % periodMs
        val remainingMs = periodMs - elapsedMs
        val secondsRemaining = ((remainingMs + 999L) / 1000L).toInt().coerceIn(1, config.periodSeconds)
        val progress = (remainingMs.toFloat() / periodMs.toFloat()).coerceIn(0f, 1f)
        return TotpSnapshot(
            code = code,
            secondsRemaining = secondsRemaining,
            progressFraction = progress,
        )
    }

    fun generateFromRawSecret(
        secretBytes: ByteArray,
        epochSeconds: Long,
        algorithm: TotpAlgorithm = TotpAlgorithm.SHA1,
        digits: Int = 6,
        periodSeconds: Int = 30,
        t0Seconds: Long = 0L,
    ): String {
        require(secretBytes.isNotEmpty()) { "Секрет TOTP пуст" }
        require(digits == 6 || digits == 8) { "Число цифр TOTP должно быть 6 или 8" }

        val counter = Math.floorDiv(epochSeconds - t0Seconds, periodSeconds.toLong())
        val counterBytes = ByteBuffer.allocate(8).order(ByteOrder.BIG_ENDIAN).putLong(counter).array()

        val mac = Mac.getInstance(algorithm.jcaHmacName)
        mac.init(SecretKeySpec(secretBytes, algorithm.jcaHmacName))
        val hash = mac.doFinal(counterBytes)

        try {
            val offset = hash[hash.lastIndex].toInt() and 0x0F
            val binary = ((hash[offset].toInt() and 0x7F) shl 24) or
                ((hash[offset + 1].toInt() and 0xFF) shl 16) or
                ((hash[offset + 2].toInt() and 0xFF) shl 8) or
                (hash[offset + 3].toInt() and 0xFF)

            val mod = 10.0.pow(digits.toDouble()).toLong()
            val otp = binary.toLong() % mod
            return otp.toString().padStart(digits, '0')
        } finally {
            hash.wipe()
            counterBytes.wipe()
        }
    }

    /**
     * Парсит как `otpauth://totp/Issuer:account?secret=JBSWY3DPEHPK3PXP&algorithm=SHA256&digits=6&period=30`,
     * так и голый Base32-ключ, вставленный пользователем вручную.
     */
    fun parseInputOrUri(rawInput: String): TotpConfig {
        val trimmed = rawInput.trim()
        if (!trimmed.startsWith("otpauth://", ignoreCase = true)) {
            val validated = Base32Codec.decode(trimmed)
            validated.wipe()
            return TotpConfig(secretBase32 = Base32Codec.normalize(trimmed))
        }

        val withoutScheme = trimmed.substring("otpauth://".length)
        val slashIdx = withoutScheme.indexOf('/')
        require(slashIdx > 0) { "Некорректный формат ссылки otpauth://" }
        val type = withoutScheme.substring(0, slashIdx).lowercase()
        require(type == "totp") { "Поддерживается только тип otpauth://totp/ (получен: $type)" }

        val rest = withoutScheme.substring(slashIdx + 1)
        val qIdx = rest.indexOf('?')
        require(qIdx >= 0) { "В ссылке otpauth:// отсутствуют параметры" }

        val rawLabel = URLDecoder.decode(rest.substring(0, qIdx), Charsets.UTF_8)
        val query = rest.substring(qIdx + 1)
        val params = query.split('&')
            .mapNotNull { pair ->
                val eq = pair.indexOf('=')
                if (eq <= 0) null
                else {
                    val k = URLDecoder.decode(pair.substring(0, eq), Charsets.UTF_8).lowercase()
                    val v = URLDecoder.decode(pair.substring(eq + 1), Charsets.UTF_8)
                    k to v
                }
            }
            .toMap()

        val secret = params["secret"]?.let(Base32Codec::normalize)
            ?: throw IllegalArgumentException("В ссылке otpauth:// отсутствует параметр secret")
        val check = Base32Codec.decode(secret)
        check.wipe()

        val labelIssuer: String
        val account: String
        if (':' in rawLabel) {
            labelIssuer = rawLabel.substringBefore(':').trim()
            account = rawLabel.substringAfter(':').trim()
        } else {
            labelIssuer = ""
            account = rawLabel.trim()
        }

        val issuer = params["issuer"]?.trim()?.takeIf { it.isNotEmpty() } ?: labelIssuer
        val algo = when (params["algorithm"]?.uppercase()) {
            null, "", "SHA1", "HMAC-SHA1" -> TotpAlgorithm.SHA1
            "SHA256", "HMAC-SHA256" -> TotpAlgorithm.SHA256
            "SHA512", "HMAC-SHA512" -> TotpAlgorithm.SHA512
            else -> throw IllegalArgumentException("Неизвестный алгоритм TOTP: ${params["algorithm"]}")
        }
        val digits = params["digits"]?.toIntOrNull() ?: 6
        val period = params["period"]?.toIntOrNull() ?: 30

        return TotpConfig(
            secretBase32 = secret,
            issuer = issuer,
            accountName = account,
            algorithm = algo,
            digits = digits,
            periodSeconds = period,
        )
    }

    fun toOtpAuthUri(config: TotpConfig): String {
        val label = if (config.issuer.isNotBlank()) {
            "${config.issuer}:${config.accountName}"
        } else {
            config.accountName.ifBlank { "MeshVault" }
        }
        val encLabel = URLEncoder.encode(label, Charsets.UTF_8).replace("+", "%20")
        val encIssuer = URLEncoder.encode(config.issuer, Charsets.UTF_8)
        return buildString {
            append("otpauth://totp/").append(encLabel)
            append("?secret=").append(Base32Codec.normalize(config.secretBase32))
            if (config.issuer.isNotBlank()) append("&issuer=").append(encIssuer)
            append("&algorithm=").append(config.algorithm.name)
            append("&digits=").append(config.digits)
            append("&period=").append(config.periodSeconds)
        }
    }
}

object Base32Codec {
    private const val ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

    fun normalize(input: String): String =
        input.uppercase().filter { it in 'A'..'Z' || it in '2'..'7' }

    fun encode(data: ByteArray): String {
        if (data.isEmpty()) return ""
        val out = StringBuilder((data.size * 8 + 4) / 5)
        var buffer = 0
        var bitsLeft = 0
        for (b in data) {
            buffer = (buffer shl 8) or (b.toInt() and 0xFF)
            bitsLeft += 8
            while (bitsLeft >= 5) {
                val index = (buffer ushr (bitsLeft - 5)) and 0x1F
                out.append(ALPHABET[index])
                bitsLeft -= 5
            }
        }
        if (bitsLeft > 0) {
            val index = (buffer shl (5 - bitsLeft)) and 0x1F
            out.append(ALPHABET[index])
        }
        return out.toString()
    }

    fun decode(input: String): ByteArray {
        val clean = input.trim().trimEnd('=').replace(" ", "").replace("-", "").uppercase()
        require(clean.isNotEmpty()) { "Пустая строка Base32" }

        val out = ByteArray(clean.length * 5 / 8)
        var outIndex = 0
        var buffer = 0
        var bitsLeft = 0

        for (ch in clean) {
            val value = ALPHABET.indexOf(ch)
            require(value >= 0) { "Недопустимый символ Base32: '$ch'" }
            buffer = (buffer shl 5) or value
            bitsLeft += 5
            if (bitsLeft >= 8) {
                out[outIndex++] = ((buffer ushr (bitsLeft - 8)) and 0xFF).toByte()
                bitsLeft -= 8
            }
        }
        return if (outIndex == out.size) out else out.copyOf(outIndex)
    }
}
