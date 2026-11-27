package com.meshvault.data.sync.dropbox

import android.net.Uri
import com.meshvault.crypto.CryptoRandom
import com.meshvault.data.db.HardwareKeystoreManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.longOrNull
import okhttp3.FormBody
import okhttp3.OkHttpClient
import okhttp3.Request
import java.io.IOException
import java.net.URLEncoder
import java.security.MessageDigest
import java.util.Base64

@Serializable
data class DropboxTokenState(
    val appKey: String,
    val accessToken: String,
    val refreshToken: String? = null,
    val expiresAtEpochMs: Long = Long.MAX_VALUE,
)

@Serializable
data class PkcePendingSession(
    val appKey: String,
    val codeVerifier: String,
    val stateNonce: String,
    val useCustomRedirect: Boolean,
)

/**
 * Авторизация OAuth 2.0 с PKCE (S256, `token_access_type=offline`, редирект `meshvault://oauth2redirect`),
 * автоматическое обновление `access_token` по `refresh_token`, а также резервный режим ручной вставки кода
 * или dev-токена для кастомных прошивок (GrapheneOS / LineageOS без браузерного редиректа).
 */
class DropboxPkceAuthManager(
    private val keystoreManager: HardwareKeystoreManager,
    private val httpClient: OkHttpClient,
) {
    private val refreshMutex = Mutex()
    private val json = Json {
        ignoreUnknownKeys = true
        encodeDefaults = true
    }

    @Volatile
    private var pendingPkce: PkcePendingSession? = null

    private val _isAuthenticatedFlow = MutableStateFlow(readStoredTokenState() != null)
    val isAuthenticatedFlow: StateFlow<Boolean> = _isAuthenticatedFlow.asStateFlow()

    fun buildAuthorizeUrl(appKey: String, useCustomSchemeRedirect: Boolean = true): String {
        val cleanAppKey = appKey.trim()
        require(cleanAppKey.isNotEmpty()) { "Укажите App Key приложения Dropbox" }

        val verifier = generatePkceVerifier()
        val challenge = computeS256Challenge(verifier)
        val state = Base64.getUrlEncoder().withoutPadding().encodeToString(CryptoRandom.nextBytes(18))

        pendingPkce = PkcePendingSession(
            appKey = cleanAppKey,
            codeVerifier = verifier,
            stateNonce = state,
            useCustomRedirect = useCustomSchemeRedirect,
        )

        return buildString {
            append("https://www.dropbox.com/oauth2/authorize")
            append("?client_id=").append(URLEncoder.encode(cleanAppKey, Charsets.UTF_8))
            append("&response_type=code")
            append("&token_access_type=offline")
            append("&code_challenge=").append(challenge)
            append("&code_challenge_method=S256")
            if (useCustomSchemeRedirect) {
                append("&redirect_uri=").append(URLEncoder.encode(REDIRECT_URI, Charsets.UTF_8))
                append("&state=").append(URLEncoder.encode(state, Charsets.UTF_8))
            }
        }
    }

    suspend fun handleOAuthRedirectUri(uri: Uri): Result<Unit> = withContext(Dispatchers.IO) {
        runCatching {
            val session = pendingPkce
                ?: throw IllegalStateException("Нет активной сессии PKCE авторизации")
            val returnedState = uri.getQueryParameter("state")
            if (session.useCustomRedirect && returnedState != session.stateNonce) {
                throw SecurityException("Несовпадение параметра state OAuth 2.0 (защита от CSRF)")
            }
            val code = uri.getQueryParameter("code")?.takeIf { it.isNotBlank() }
                ?: throw IllegalArgumentException(
                    uri.getQueryParameter("error_description") ?: "Код авторизации не получен от Dropbox",
                )
            exchangeCodeForTokensInternal(session, code)
        }
    }

    /**
     * Резервный режим ручной вставки кода авторизации (без браузерного редиректа).
     */
    suspend fun completeManualAuthCode(authorizationCode: String): Result<Unit> = withContext(Dispatchers.IO) {
        runCatching {
            val session = pendingPkce
                ?: throw IllegalStateException("Сначала сгенерируйте ссылку авторизации PKCE")
            exchangeCodeForTokensInternal(session, authorizationCode.trim())
        }
    }

    /**
     * Резервный режим прямого подключения по сгенерированному в консоли Dropbox токену (Dev Token).
     */
    fun saveDirectAccessToken(accessToken: String, appKey: String = "dev_token") {
        val clean = accessToken.trim()
        require(clean.length >= 16) { "Токен доступа слишком короткий" }
        persistTokens(
            DropboxTokenState(
                appKey = appKey,
                accessToken = clean,
                refreshToken = null,
                expiresAtEpochMs = Long.MAX_VALUE,
            ),
        )
    }

    suspend fun getValidAccessToken(): String = refreshMutex.withLock {
        val current = readStoredTokenState()
            ?: throw IOException("Dropbox не подключён")
        val now = System.currentTimeMillis()
        if (current.expiresAtEpochMs - 60_000L > now || current.refreshToken.isNullOrBlank()) {
            return@withLock current.accessToken
        }

        withContext(Dispatchers.IO) {
            val form = FormBody.Builder()
                .add("grant_type", "refresh_token")
                .add("refresh_token", current.refreshToken)
                .add("client_id", current.appKey)
                .build()

            val request = Request.Builder()
                .url(TOKEN_ENDPOINT)
                .post(form)
                .build()

            httpClient.newCall(request).execute().use { response ->
                val bodyStr = response.body?.string().orEmpty()
                if (!response.isSuccessful) {
                    throw IOException("Не удалось обновить токен Dropbox (${response.code})")
                }
                val parsed = json.parseToJsonElement(bodyStr).jsonObject
                val newAccess = parsed["access_token"]?.jsonPrimitive?.contentOrNull
                    ?: throw IOException("В ответе Dropbox отсутствует access_token")
                val expiresInSec = parsed["expires_in"]?.jsonPrimitive?.longOrNull ?: 14_400L

                val updated = current.copy(
                    accessToken = newAccess,
                    expiresAtEpochMs = System.currentTimeMillis() + expiresInSec * 1000L,
                )
                persistTokens(updated)
                updated.accessToken
            }
        }
    }

    fun disconnectAndWipe() {
        pendingPkce = null
        keystoreManager.wipeEncryptedDropboxTokenBlob()
        _isAuthenticatedFlow.value = false
    }

    private fun exchangeCodeForTokensInternal(session: PkcePendingSession, code: String) {
        val formBuilder = FormBody.Builder()
            .add("code", code)
            .add("grant_type", "authorization_code")
            .add("client_id", session.appKey)
            .add("code_verifier", session.codeVerifier)

        if (session.useCustomRedirect) {
            formBuilder.add("redirect_uri", REDIRECT_URI)
        }

        val req = Request.Builder()
            .url(TOKEN_ENDPOINT)
            .post(formBuilder.build())
            .build()

        httpClient.newCall(req).execute().use { resp ->
            val bodyStr = resp.body?.string().orEmpty()
            if (!resp.isSuccessful) {
                throw IOException("Ошибка обмена кода PKCE (${resp.code}): $bodyStr")
            }
            val obj = json.parseToJsonElement(bodyStr).jsonObject
            val access = obj["access_token"]?.jsonPrimitive?.contentOrNull
                ?: throw IOException("Отсутствует access_token")
            val refresh = obj["refresh_token"]?.jsonPrimitive?.contentOrNull
            val expiresInSec = obj["expires_in"]?.jsonPrimitive?.longOrNull ?: 14_400L

            persistTokens(
                DropboxTokenState(
                    appKey = session.appKey,
                    accessToken = access,
                    refreshToken = refresh,
                    expiresAtEpochMs = System.currentTimeMillis() + expiresInSec * 1000L,
                ),
            )
            pendingPkce = null
        }
    }

    private fun persistTokens(state: DropboxTokenState) {
        keystoreManager.saveEncryptedDropboxTokenBlob(json.encodeToString(state))
        _isAuthenticatedFlow.value = true
    }

    private fun readStoredTokenState(): DropboxTokenState? {
        val raw = keystoreManager.readEncryptedDropboxTokenBlob() ?: return null
        return runCatching { json.decodeFromString<DropboxTokenState>(raw) }.getOrNull()
    }

    companion object {
        const val REDIRECT_URI = "meshvault://oauth2redirect"
        const val DEFAULT_DROPBOX_APP_KEY = "meshvault_pkce_client"
        private const val TOKEN_ENDPOINT = "https://api.dropboxapi.com/oauth2/token"
        private const val PKCE_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"

        internal fun generatePkceVerifier(length: Int = 64): String {
            val rnd = CryptoRandom.nextBytes(length)
            val sb = StringBuilder(length)
            for (b in rnd) {
                sb.append(PKCE_CHARS[(b.toInt() and 0xFF) % PKCE_CHARS.length])
            }
            return sb.toString()
        }

        internal fun computeS256Challenge(verifier: String): String {
            val sha256 = MessageDigest.getInstance("SHA-256")
                .digest(verifier.toByteArray(Charsets.US_ASCII))
            return Base64.getUrlEncoder().withoutPadding().encodeToString(sha256)
        }
    }
}
