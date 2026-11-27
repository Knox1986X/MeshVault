package com.meshvault.domain.model

import com.meshvault.crypto.AeadCipherSuite
import com.meshvault.crypto.Argon2idKdf
import com.meshvault.crypto.CryptoAuthException
import com.meshvault.crypto.CryptoRandom
import com.meshvault.crypto.EnvelopeCiphers
import com.meshvault.crypto.KdfConfig
import com.meshvault.crypto.wipe
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.util.Base64
import java.util.UUID

@Serializable
enum class SecretEntryType(val titleRu: String) {
    LOGIN("Логин и пароль"),
    BANK_CARD("Банковская карта"),
    SSH_API_SEED("SSH / API ключ / Seed-фраза"),
    IDENTITY_DOC("Личный документ"),
}

@Serializable
data class CustomSecretField(
    val name: String,
    val value: String,
    val isHidden: Boolean = true,
)

@Serializable
data class PasswordHistoryItem(
    val previousPassword: String,
    val replacedAtMs: Long,
)

@Serializable
data class SecretEntry(
    val id: String,
    val type: SecretEntryType,
    val title: String,
    val categoryFolder: String = "",
    val iconKey: String = "key",
    // Поля логина и автозаполнения
    val username: String = "",
    val password: String = "",
    val totpUri: String? = null,
    val autofillDomains: List<String> = emptyList(),
    val autofillPackages: List<String> = emptyList(),
    // Поля банковской карты
    val cardholderName: String = "",
    val cardNumber: String = "",
    val cardExpiry: String = "",
    val cardCvv: String = "",
    // Поля SSH / API / Seed и документов
    val secretPayload: String = "",
    val documentNumber: String = "",
    val documentIssuer: String = "",
    // Общие расширения
    val notes: String = "",
    val customFields: List<CustomSecretField> = emptyList(),
    val passwordHistory: List<PasswordHistoryItem> = emptyList(),
    val tags: List<String> = emptyList(),
    val isFavorite: Boolean = false,
    val createdAtMs: Long,
    val updatedAtMs: Long,
    val passwordUpdatedAtMs: Long,
) {
    /**
     * Обновляет пароль записи с автоматическим сохранением предыдущего значения в историю изменений.
     */
    fun withUpdatedPassword(newPassword: String, nowMs: Long, maxHistory: Int = 15): SecretEntry {
        if (newPassword == password) return copy(updatedAtMs = nowMs)
        val updatedHistory = if (password.isNotEmpty()) {
            (listOf(PasswordHistoryItem(password, nowMs)) + passwordHistory).take(maxHistory)
        } else {
            passwordHistory
        }
        return copy(
            password = newPassword,
            passwordHistory = updatedHistory,
            updatedAtMs = nowMs,
            passwordUpdatedAtMs = nowMs,
        )
    }
}

@Serializable
enum class CrossLinkTargetType(val labelRu: String) {
    MEDIA_REFERENCE("Фото/видео референс"),
    SECRET_ENTRY("Запись пароля"),
}

@Serializable
data class VaultCrossLink(
    val targetType: CrossLinkTargetType,
    val targetId: String,
    val displayLabel: String,
)

@Serializable
data class VaultNote(
    val id: String,
    val title: String,
    val markdownBody: String,
    val colorLabelHex: String = "#10B981",
    val tags: List<String> = emptyList(),
    val isPinned: Boolean = false,
    val biometricLockRequired: Boolean = false,
    val crossLinks: List<VaultCrossLink> = emptyList(),
    val createdAtMs: Long,
    val updatedAtMs: Long,
)

sealed interface MarkdownBlock {
    data class Heading(val level: Int, val text: String) : MarkdownBlock
    data class Paragraph(val text: String) : MarkdownBlock
    data class ChecklistItem(val lineIndex: Int, val checked: Boolean, val text: String) : MarkdownBlock
    data class BulletItem(val text: String) : MarkdownBlock
    data class CodeFence(val language: String, val code: String) : MarkdownBlock
}

object MarkdownNoteEngine {
    private val CHECKLIST_REGEX = Regex("""^(\s*[-*]\s+\[)([ xX])(\]\s+)(.*)$""")

    fun parseBlocks(markdown: String): List<MarkdownBlock> {
        if (markdown.isEmpty()) return emptyList()
        val lines = markdown.lines()
        val blocks = mutableListOf<MarkdownBlock>()
        var i = 0
        while (i < lines.size) {
            val line = lines[i]
            val trimmed = line.trimStart()
            if (trimmed.startsWith("```")) {
                val lang = trimmed.removePrefix("```").trim()
                val codeLines = mutableListOf<String>()
                i++
                while (i < lines.size && !lines[i].trimStart().startsWith("```")) {
                    codeLines += lines[i]
                    i++
                }
                blocks += MarkdownBlock.CodeFence(language = lang, code = codeLines.joinToString("\n"))
                i++ // пропускаем закрывающий ```
                continue
            }

            val checklistMatch = CHECKLIST_REGEX.matchEntire(line)
            if (checklistMatch != null) {
                val checked = checklistMatch.groupValues[2].equals("x", ignoreCase = true)
                val content = checklistMatch.groupValues[4]
                blocks += MarkdownBlock.ChecklistItem(lineIndex = i, checked = checked, text = content)
                i++
                continue
            }

            if (trimmed.startsWith("#")) {
                val hashes = trimmed.takeWhile { it == '#' }.length.coerceIn(1, 6)
                val headingText = trimmed.drop(hashes).trimStart()
                if (headingText.isNotEmpty()) {
                    blocks += MarkdownBlock.Heading(level = hashes, text = headingText)
                    i++
                    continue
                }
            }

            if (trimmed.startsWith("- ") || trimmed.startsWith("* ")) {
                blocks += MarkdownBlock.BulletItem(text = trimmed.drop(2))
                i++
                continue
            }

            if (trimmed.isNotEmpty()) {
                blocks += MarkdownBlock.Paragraph(text = line)
            }
            i++
        }
        return blocks
    }

    /**
     * Переключает интерактивный чек-лист `- [ ]` <-> `- [x]` прямо в режиме чтения по индексу строки.
     */
    fun toggleChecklistLine(markdown: String, targetLineIndex: Int): String {
        val lines = markdown.lines().toMutableList()
        if (targetLineIndex !in lines.indices) return markdown
        val match = CHECKLIST_REGEX.matchEntire(lines[targetLineIndex]) ?: return markdown
        val prefix = match.groupValues[1]
        val wasChecked = match.groupValues[2].equals("x", ignoreCase = true)
        val mid = match.groupValues[3]
        val rest = match.groupValues[4]
        val nextMark = if (wasChecked) " " else "x"
        lines[targetLineIndex] = "$prefix$nextMark$mid$rest"
        return lines.joinToString("\n")
    }
}

data class BitwardenImportResult(
    val secrets: List<SecretEntry>,
    val notes: List<VaultNote>,
)

/**
 * Импорт экспортов Bitwarden (JSON и CSV) строго в оперативной памяти с зачисткой буфера.
 */
object BitwardenImporter {
    private val lenientJson = Json { ignoreUnknownKeys = true }

    fun importFromJsonBytes(rawBytes: ByteArray, nowMs: Long = System.currentTimeMillis()): BitwardenImportResult {
        val textChars = String(rawBytes, Charsets.UTF_8).toCharArray()
        rawBytes.wipe()
        try {
            val root = lenientJson.parseToJsonElement(String(textChars)).jsonObject
            val foldersMap = root["folders"]?.jsonArray?.associate { elem ->
                val obj = elem.jsonObject
                (obj["id"]?.jsonPrimitive?.contentOrNull.orEmpty()) to
                    (obj["name"]?.jsonPrimitive?.contentOrNull.orEmpty())
            }.orEmpty()

            val itemsArray: JsonArray = root["items"]?.jsonArray ?: JsonArray(emptyList())
            val secrets = mutableListOf<SecretEntry>()
            val notes = mutableListOf<VaultNote>()

            for (element in itemsArray) {
                val obj = element.jsonObject
                val bwType = obj["type"]?.jsonPrimitive?.intOrNull ?: 1
                val name = obj["name"]?.jsonPrimitive?.contentOrNull ?: "Импортированная запись"
                val notesText = obj["notes"]?.jsonPrimitive?.contentOrNull.orEmpty()
                val favorite = obj["favorite"]?.jsonPrimitive?.contentOrNull?.toBooleanStrictOrNull() ?: false
                val folderName = obj["folderId"]?.jsonPrimitive?.contentOrNull?.let { foldersMap[it] }.orEmpty()
                val customFields = parseCustomFields(obj)

                when (bwType) {
                    2 -> {
                        notes += VaultNote(
                            id = UUID.randomUUID().toString(),
                            title = name,
                            markdownBody = notesText,
                            tags = if (folderName.isNotBlank()) listOf(folderName) else emptyList(),
                            isPinned = favorite,
                            createdAtMs = nowMs,
                            updatedAtMs = nowMs,
                        )
                    }
                    3 -> {
                        val card = obj["card"]?.jsonObject
                        val expMonth = card?.get("expMonth")?.jsonPrimitive?.contentOrNull.orEmpty().padStart(2, '0')
                        val expYear = card?.get("expYear")?.jsonPrimitive?.contentOrNull.orEmpty().takeLast(2)
                        val expiry = if (expMonth.isNotBlank() && expYear.isNotBlank()) "$expMonth/$expYear" else ""
                        secrets += SecretEntry(
                            id = UUID.randomUUID().toString(),
                            type = SecretEntryType.BANK_CARD,
                            title = name,
                            categoryFolder = folderName,
                            cardholderName = card?.get("cardholderName")?.jsonPrimitive?.contentOrNull.orEmpty(),
                            cardNumber = card?.get("number")?.jsonPrimitive?.contentOrNull.orEmpty(),
                            cardExpiry = expiry,
                            cardCvv = card?.get("code")?.jsonPrimitive?.contentOrNull.orEmpty(),
                            notes = notesText,
                            customFields = customFields,
                            isFavorite = favorite,
                            createdAtMs = nowMs,
                            updatedAtMs = nowMs,
                            passwordUpdatedAtMs = nowMs,
                        )
                    }
                    4 -> {
                        val ident = obj["identity"]?.jsonObject
                        val fullName = listOfNotNull(
                            ident?.get("firstName")?.jsonPrimitive?.contentOrNull,
                            ident?.get("lastName")?.jsonPrimitive?.contentOrNull,
                        ).joinToString(" ").trim()
                        val passport = ident?.get("passportNumber")?.jsonPrimitive?.contentOrNull
                            ?: ident?.get("licenseNumber")?.jsonPrimitive?.contentOrNull.orEmpty()
                        secrets += SecretEntry(
                            id = UUID.randomUUID().toString(),
                            type = SecretEntryType.IDENTITY_DOC,
                            title = name,
                            categoryFolder = folderName,
                            username = fullName,
                            documentNumber = passport,
                            notes = notesText,
                            customFields = customFields,
                            isFavorite = favorite,
                            createdAtMs = nowMs,
                            updatedAtMs = nowMs,
                            passwordUpdatedAtMs = nowMs,
                        )
                    }
                    else -> {
                        val login = obj["login"]?.jsonObject
                        val username = login?.get("username")?.jsonPrimitive?.contentOrNull.orEmpty()
                        val password = login?.get("password")?.jsonPrimitive?.contentOrNull.orEmpty()
                        val totp = login?.get("totp")?.jsonPrimitive?.contentOrNull
                        val uris = login?.get("uris")?.jsonArray
                            ?.mapNotNull { it.jsonObject["uri"]?.jsonPrimitive?.contentOrNull }
                            .orEmpty()
                        val domains = uris.filterNot { it.startsWith("androidapp://") }.map(::extractDomainHost)
                        val pkgs = uris.filter { it.startsWith("androidapp://") }
                            .map { it.removePrefix("androidapp://").trim('/') }

                        secrets += SecretEntry(
                            id = UUID.randomUUID().toString(),
                            type = SecretEntryType.LOGIN,
                            title = name,
                            categoryFolder = folderName,
                            username = username,
                            password = password,
                            totpUri = totp?.takeIf { it.isNotBlank() },
                            autofillDomains = domains.filter { it.isNotBlank() },
                            autofillPackages = pkgs.filter { it.isNotBlank() },
                            notes = notesText,
                            customFields = customFields,
                            isFavorite = favorite,
                            createdAtMs = nowMs,
                            updatedAtMs = nowMs,
                            passwordUpdatedAtMs = nowMs,
                        )
                    }
                }
            }
            return BitwardenImportResult(secrets = secrets, notes = notes)
        } finally {
            textChars.wipe()
        }
    }

    fun importFromCsvBytes(rawBytes: ByteArray, nowMs: Long = System.currentTimeMillis()): BitwardenImportResult {
        val textChars = String(rawBytes, Charsets.UTF_8).toCharArray()
        rawBytes.wipe()
        try {
            val rows = parseCsvRows(String(textChars))
            if (rows.size < 2) return BitwardenImportResult(emptyList(), emptyList())
            val header = rows.first().map { it.trim().lowercase() }
            fun col(row: List<String>, name: String): String {
                val idx = header.indexOf(name)
                return if (idx in row.indices) row[idx] else ""
            }

            val secrets = mutableListOf<SecretEntry>()
            val notes = mutableListOf<VaultNote>()
            for (row in rows.drop(1)) {
                if (row.all { it.isBlank() }) continue
                val type = col(row, "type").lowercase()
                val title = col(row, "name").ifBlank { "Запись CSV" }
                val folder = col(row, "folder")
                val fav = col(row, "favorite") == "1"
                val noteBody = col(row, "notes")

                if (type == "note") {
                    notes += VaultNote(
                        id = UUID.randomUUID().toString(),
                        title = title,
                        markdownBody = noteBody,
                        tags = if (folder.isNotBlank()) listOf(folder) else emptyList(),
                        isPinned = fav,
                        createdAtMs = nowMs,
                        updatedAtMs = nowMs,
                    )
                } else {
                    val uri = col(row, "login_uri")
                    secrets += SecretEntry(
                        id = UUID.randomUUID().toString(),
                        type = SecretEntryType.LOGIN,
                        title = title,
                        categoryFolder = folder,
                        username = col(row, "login_username"),
                        password = col(row, "login_password"),
                        totpUri = col(row, "login_totp").takeIf { it.isNotBlank() },
                        autofillDomains = if (uri.isNotBlank()) listOf(extractDomainHost(uri)) else emptyList(),
                        notes = noteBody,
                        isFavorite = fav,
                        createdAtMs = nowMs,
                        updatedAtMs = nowMs,
                        passwordUpdatedAtMs = nowMs,
                    )
                }
            }
            return BitwardenImportResult(secrets = secrets, notes = notes)
        } finally {
            textChars.wipe()
        }
    }

    private fun parseCustomFields(obj: JsonObject): List<CustomSecretField> {
        val arr = obj["fields"]?.jsonArray ?: return emptyList()
        return arr.mapNotNull { el ->
            val f = el.jsonObject
            val fName = f["name"]?.jsonPrimitive?.contentOrNull ?: return@mapNotNull null
            val fVal = f["value"]?.jsonPrimitive?.contentOrNull.orEmpty()
            val fType = f["type"]?.jsonPrimitive?.intOrNull ?: 0
            CustomSecretField(name = fName, value = fVal, isHidden = fType == 1)
        }
    }

    private fun extractDomainHost(rawUri: String): String {
        val trimmed = rawUri.trim().lowercase()
        val noScheme = trimmed.substringAfter("://", trimmed)
        return noScheme.substringBefore('/').substringBefore(':').removePrefix("www.")
    }

    private fun parseCsvRows(csv: String): List<List<String>> {
        val rows = mutableListOf<List<String>>()
        var currentRow = mutableListOf<String>()
        val field = StringBuilder()
        var inQuotes = false
        var i = 0
        while (i < csv.length) {
            val ch = csv[i]
            if (inQuotes) {
                if (ch == '"') {
                    if (i + 1 < csv.length && csv[i + 1] == '"') {
                        field.append('"')
                        i += 2
                        continue
                    } else {
                        inQuotes = false
                    }
                } else {
                    field.append(ch)
                }
            } else {
                when (ch) {
                    '"' -> inQuotes = true
                    ',' -> {
                        currentRow += field.toString()
                        field.setLength(0)
                    }
                    '\n' -> {
                        currentRow += field.toString()
                        field.setLength(0)
                        rows += currentRow
                        currentRow = mutableListOf()
                    }
                    '\r' -> Unit
                    else -> field.append(ch)
                }
            }
            i++
        }
        if (field.isNotEmpty() || currentRow.isNotEmpty()) {
            currentRow += field.toString()
            rows += currentRow
        }
        return rows
    }
}

@Serializable
data class MvBackupPayload(
    val exportedAtMs: Long,
    val folders: List<VaultFolder>,
    val secrets: List<SecretEntry>,
    val notes: List<VaultNote>,
)

@Serializable
private data class MvBackupEnvelope(
    val magic: String = "MVBACKUP_V2",
    val kdfConfig: KdfConfig,
    val saltBase64: String,
    val nonceBase64: String,
    val ciphertextBase64: String,
)

/**
 * Автономный зашифрованный архив `.mvbackup` (Argon2id + XChaCha20-Poly1305).
 */
object MvBackupCodec {
    private val json = Json {
        ignoreUnknownKeys = true
        encodeDefaults = true
    }
    private val AAD = "meshvault:mvbackup:v2".toByteArray(Charsets.UTF_8)

    fun exportArchive(
        payload: MvBackupPayload,
        backupPassword: CharArray,
        kdfConfig: KdfConfig = KdfConfig.BALANCED_MOBILE,
    ): ByteArray {
        val salt = CryptoRandom.nextBytes(32)
        val nonce = CryptoRandom.nextBytes(EnvelopeCiphers.XCHACHA_NONCE_BYTES)
        val kek = Argon2idKdf.deriveKek(backupPassword, salt, kdfConfig, outputLength = 32)
        val plainBytes = json.encodeToString(payload).toByteArray(Charsets.UTF_8)
        return try {
            val ct = EnvelopeCiphers.encrypt(
                suite = AeadCipherSuite.XCHACHA20_POLY1305,
                key = kek,
                nonce = nonce,
                plaintext = plainBytes,
                aad = AAD,
            )
            val env = MvBackupEnvelope(
                kdfConfig = kdfConfig,
                saltBase64 = Base64.getEncoder().withoutPadding().encodeToString(salt),
                nonceBase64 = Base64.getEncoder().withoutPadding().encodeToString(nonce),
                ciphertextBase64 = Base64.getEncoder().withoutPadding().encodeToString(ct),
            )
            json.encodeToString(env).toByteArray(Charsets.UTF_8)
        } finally {
            kek.wipe()
            plainBytes.wipe()
        }
    }

    fun importArchive(archiveBytes: ByteArray, backupPassword: CharArray): MvBackupPayload {
        val env = json.decodeFromString<MvBackupEnvelope>(String(archiveBytes, Charsets.UTF_8))
        if (env.magic != "MVBACKUP_V2") throw CryptoAuthException("Неподдерживаемый формат архива .mvbackup")
        val salt = Base64.getDecoder().decode(env.saltBase64)
        val nonce = Base64.getDecoder().decode(env.nonceBase64)
        val ct = Base64.getDecoder().decode(env.ciphertextBase64)
        val kek = Argon2idKdf.deriveKek(backupPassword, salt, env.kdfConfig, outputLength = 32)
        return try {
            val plainBytes = EnvelopeCiphers.decrypt(
                suite = AeadCipherSuite.XCHACHA20_POLY1305,
                key = kek,
                nonce = nonce,
                ciphertextWithTag = ct,
                aad = AAD,
            )
            val decoded = json.decodeFromString<MvBackupPayload>(String(plainBytes, Charsets.UTF_8))
            plainBytes.wipe()
            decoded
        } finally {
            kek.wipe()
        }
    }
}
