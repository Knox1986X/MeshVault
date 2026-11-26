package com.meshvault.app.crypto

import java.nio.ByteBuffer
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlin.math.pow

object TotpGenerator {
    private const val BASE32_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

    fun generateCode(
        secretBase32: String,
        timeSeconds: Long = System.currentTimeMillis() / 1000L,
        period: Int = 30,
        digits: Int = 6
    ): String {
        val cleanSecret = secretBase32
            .uppercase()
            .replace(" ", "")
            .replace("-", "")
            .trimEnd('=')
        if (cleanSecret.isEmpty()) return "------"

        val keyBytes = decodeBase32(cleanSecret) ?: return "------"
        val counter = timeSeconds / period
        val counterBytes = ByteBuffer.allocate(8).putLong(counter).array()

        val mac = Mac.getInstance("HmacSHA1")
        mac.init(SecretKeySpec(keyBytes, "HmacSHA1"))
        val hash = mac.doFinal(counterBytes)

        val offset = hash[hash.size - 1].toInt() and 0x0F
        val binary = ((hash[offset].toInt() and 0x7F) shl 24) or
            ((hash[offset + 1].toInt() and 0xFF) shl 16) or
            ((hash[offset + 2].toInt() and 0xFF) shl 8) or
            (hash[offset + 3].toInt() and 0xFF)

        val otp = binary % 10.0.pow(digits).toInt()
        return otp.toString().padStart(digits, '0')
    }

    fun remainingSeconds(
        timeSeconds: Long = System.currentTimeMillis() / 1000L,
        period: Int = 30
    ): Int {
        return period - (timeSeconds % period).toInt()
    }

    private fun decodeBase32(input: String): ByteArray? {
        val output = ArrayList<Byte>()
        var buffer = 0
        var bitsLeft = 0
        for (c in input) {
            val value = BASE32_CHARS.indexOf(c)
            if (value < 0) return null
            buffer = (buffer shl 5) or value
            bitsLeft += 5
            if (bitsLeft >= 8) {
                output.add(((buffer shr (bitsLeft - 8)) and 0xFF).toByte())
                bitsLeft -= 8
            }
        }
        return output.toByteArray()
    }
}
