package com.meshvault.app

import android.app.Application
import android.content.IntentSender
import android.graphics.Bitmap
import android.net.Uri
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.meshvault.crypto.CryptoAuthException
import com.meshvault.crypto.VaultContour
import com.meshvault.crypto.VaultCryptoEngine
import com.meshvault.crypto.VaultSessionKeys
import com.meshvault.data.db.EncryptedVaultRepositoryImpl
import com.meshvault.data.db.MeshVaultDatabase
import com.meshvault.data.media.EncryptedMediaFileStore
import com.meshvault.data.media.ImportPreflightReport
import com.meshvault.data.media.SecureMediaVaultManager
import com.meshvault.data.sync.dropbox.DropboxHttpApiClient
import com.meshvault.data.sync.dropbox.DropboxSyncEngine
import com.meshvault.data.sync.dropbox.DropboxSyncWorkRegistry
import com.meshvault.domain.media.ImportDuplicateStrategy
import com.meshvault.domain.model.FolderIconType
import com.meshvault.domain.model.MediaItem
import com.meshvault.domain.model.StoragePolicy
import com.meshvault.domain.model.VaultFolder
import com.meshvault.domain.repository.AppSecuritySettings
import com.meshvault.domain.repository.DropboxSyncPhase
import com.meshvault.domain.repository.AutoLockTimeout
import com.meshvault.domain.repository.DropboxQuotaInfo
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.UUID
import javax.crypto.Cipher

/**
 * Состояние корневого экрана: экран разблокировки либо галерея хранилища.
 * Явные handles на открытые ресурсы живут в [VaultRuntime] внутри ViewModel —
 * в UI-state они не попадают.
 */
data class VaultUiState(
    val vaultExists: Boolean = false,
    val unlocked: Boolean = false,
    val isWorking: Boolean = false,
    val errorMessage: String? = null,
    val settings: AppSecuritySettings = AppSecuritySettings(),
    val folders: List<VaultFolder> = emptyList(),
    val media: List<MediaItem> = emptyList(),
    val currentFolderId: String? = null,
    val dropboxConnected: Boolean = false,
    val dropboxQuota: DropboxQuotaInfo? = null,
    val syncPhase: DropboxSyncPhase = DropboxSyncPhase.Idle,
    val viewerMediaId: String? = null,
    val isImporting: Boolean = false,
    val importProgress: Pair<Int, Int>? = null,
    val pendingDuplicateReport: ImportPreflightReport? = null,
    val pendingSystemDeleteSender: IntentSender? = null,
    val snackbarMessage: String? = null,
)

/** Открытое зашифрованное хранилище: сессия + Room + Dropbox-движок. */
private class VaultRuntime(
    val session: VaultSessionKeys,
    val database: MeshVaultDatabase,
    val repository: EncryptedVaultRepositoryImpl,
    val syncEngine: DropboxSyncEngine,
    val secureMediaManager: SecureMediaVaultManager,
)

class VaultViewModel(application: Application) : AndroidViewModel(application) {

    private val app: MeshVaultApplication = application as MeshVaultApplication
    private val keystoreManager = app.keystoreManager
    private val fileStore: EncryptedMediaFileStore = app.fileStore

    private var runtime: VaultRuntime? = null
    private var flowJobs: List<Job> = emptyList()

    private val _uiState = MutableStateFlow(
        VaultUiState(
            vaultExists = app.keystoreManager.hasVaultHeader(),
            settings = app.keystoreManager.settingsFlow.value,
        ),
    )
    val uiState: StateFlow<VaultUiState> = _uiState.asStateFlow()

    init {
        viewModelScope.launch {
            keystoreManager.settingsFlow.collect { settings ->
                fileStore.applyPerformanceProfile(settings.performanceProfile)
                _uiState.update { it.copy(settings = settings) }
            }
        }
        viewModelScope.launch {
            app.dropboxAuthManager.isAuthenticatedFlow.collect { connected ->
                _uiState.update { it.copy(dropboxConnected = connected) }
            }
        }
    }

    // ---------------------------------------------------------------
    // Сессия: открытие / закрытие / паник-лок
    // ---------------------------------------------------------------

    private suspend fun onSessionOpened(session: VaultSessionKeys) {
        val context = getApplication<Application>()
        val database = MeshVaultDatabase.openEncrypted(context, session)
        val deviceNodeId = keystoreManager.getOrCreateDeviceNodeId()

        val repository = EncryptedVaultRepositoryImpl(
            database = database,
            session = session,
            deviceNodeId = deviceNodeId,
            onDeleteLocalMediaFiles = { mediaId ->
                fileStore.deleteMediaFiles(session.contour, mediaId)
            },
            onCloneLocalMediaFiles = { sourceId, newId ->
                fileStore.cloneEncryptedMedia(session, sourceId, newId)
            },
        )
        val httpApi = DropboxHttpApiClient(context, app.dropboxAuthManager, app.dropboxHttpClient)
        val syncEngine = DropboxSyncEngine(
            context = context,
            session = session,
            repository = repository,
            fileStore = fileStore,
            authManager = app.dropboxAuthManager,
            httpApi = httpApi,
            keystoreManager = keystoreManager,
        )
        val secureMediaManager = SecureMediaVaultManager(context, fileStore)

        DropboxSyncWorkRegistry.activeRunner = {
            syncEngine.triggerDeltaSync(keystoreManager.settingsFlow.value.syncWifiOnly)
        }
        DropboxSyncWorkRegistry.ensurePeriodicSyncScheduled(context)

        runtime = VaultRuntime(session, database, repository, syncEngine, secureMediaManager)

        flowJobs = listOf(
            viewModelScope.launch { repository.foldersFlow.collect { f -> _uiState.update { it.copy(folders = f) } } },
            viewModelScope.launch { repository.mediaFlow.collect { m -> _uiState.update { it.copy(media = m) } } },
            viewModelScope.launch { syncEngine.syncPhaseFlow.collect { p -> _uiState.update { it.copy(syncPhase = p) } } },
            viewModelScope.launch { syncEngine.quotaFlow.collect { q -> _uiState.update { it.copy(dropboxQuota = q) } } },
        )

        // Фоновый бэкап заголовка хранилища в Dropbox + актуальная квота (если уже подключён)
        viewModelScope.launch { runCatching { syncEngine.uploadVaultHeaderBackupIfPossible() } }
        viewModelScope.launch { runCatching { syncEngine.refreshSpaceUsage() } }

        _uiState.update {
            it.copy(
                unlocked = true,
                isWorking = false,
                errorMessage = null,
                vaultExists = true,
                currentFolderId = null,
            )
        }
    }

    /** Мгновенная паника/блокировка: ключи затираются, сессия закрывается, DB отключается. */
    fun lockVault() {
        autoLockJob?.cancel()
        autoLockJob = null
        val rt = runtime ?: return
        runtime = null
        flowJobs.forEach { it.cancel() }
        flowJobs = emptyList()
        DropboxSyncWorkRegistry.activeRunner = null
        runCatching { rt.database.close() }
        runCatching { rt.session.wipeAll() }
        fileStore.panicWipeMemoryCache()
        _uiState.update {
            it.copy(
                unlocked = false,
                isWorking = false,
                folders = emptyList(),
                media = emptyList(),
                currentFolderId = null,
                viewerMediaId = null,
                syncPhase = DropboxSyncPhase.Idle,
                dropboxQuota = null,
                pendingDuplicateReport = null,
                pendingSystemDeleteSender = null,
                importProgress = null,
                isImporting = false,
            )
        }
    }

    private var autoLockJob: Job? = null

    fun onBackgrounded() {
        val timeout = keystoreManager.settingsFlow.value.autoLockTimeout
        if (timeout == AutoLockTimeout.IMMEDIATE) {
            lockVault()
            return
        }
        autoLockJob?.cancel()
        autoLockJob = viewModelScope.launch {
            delay(timeout.delayMillis)
            lockVault()
        }
    }

    fun onForegrounded() {
        autoLockJob?.cancel()
        autoLockJob = null
    }

    // ---------------------------------------------------------------
    // Разблокировка / создание
    // ---------------------------------------------------------------

    fun createVault(primaryPassword: CharArray, decoyPassword: CharArray?) {
        viewModelScope.launch {
            _uiState.update { it.copy(isWorking = true, errorMessage = null) }
            try {
                val result = withContext(Dispatchers.Default) {
                    VaultCryptoEngine.createVault(primaryPassword, decoyPassword)
                }
                keystoreManager.saveVaultHeaderRaw(VaultCryptoEngine.serializeHeader(result.header))
                wipePasswords(primaryPassword, decoyPassword)
                onSessionOpened(result.primarySession)
            } catch (e: Exception) {
                wipePasswords(primaryPassword, decoyPassword)
                _uiState.update {
                    it.copy(isWorking = false, errorMessage = e.message ?: "Не удалось создать хранилище")
                }
            }
        }
    }

    fun unlock(password: CharArray) {
        viewModelScope.launch {
            _uiState.update { it.copy(isWorking = true, errorMessage = null) }
            val raw = keystoreManager.readVaultHeaderRaw()
            if (raw == null) {
                wipePasswords(password, null)
                _uiState.update {
                    it.copy(
                        isWorking = false,
                        vaultExists = false,
                        errorMessage = "Хранилище не найдено на этом устройстве. Создайте новое.",
                    )
                }
                return@launch
            }
            try {
                val header = VaultCryptoEngine.deserializeHeader(raw)
                val session = withContext(Dispatchers.Default) {
                    VaultCryptoEngine.unlockVault(header, password)
                }
                wipePasswords(password, null)
                onSessionOpened(session)
            } catch (e: CryptoAuthException) {
                wipePasswords(password, null)
                _uiState.update { it.copy(isWorking = false, errorMessage = "Неверный мастер-пароль") }
            } catch (e: Exception) {
                wipePasswords(password, null)
                _uiState.update {
                    it.copy(isWorking = false, errorMessage = e.message ?: "Не удалось разблокировать хранилище")
                }
            }
        }
    }

    // ---------------------------------------------------------------
    // Биометрия (BiometricPrompt → аппаратный ключ в Android Keystore)
    // ---------------------------------------------------------------

    fun createBiometricUnlockCipher(): Pair<Cipher, VaultContour>? =
        runCatching { keystoreManager.createBiometricDecryptCipher() }.getOrNull()

    fun createBiometricEncryptCipher(): Cipher? =
        runCatching { keystoreManager.createBiometricEncryptCipher() }.getOrNull()

    fun unlockWithBiometric(authenticatedCipher: Cipher, contour: VaultContour) {
        viewModelScope.launch {
            _uiState.update { it.copy(isWorking = true, errorMessage = null) }
            try {
                val vmk = keystoreManager.decryptVmkWithAuthenticatedCipher(authenticatedCipher)
                val session = try {
                    VaultCryptoEngine.unlockWithBiometricVmk(contour, vmk)
                } finally {
                    vmk.fill(0)
                }
                onSessionOpened(session)
            } catch (e: Exception) {
                _uiState.update {
                    it.copy(isWorking = false, errorMessage = "Не удалось разблокировать по биометрии")
                }
            }
        }
    }

    fun enrollBiometric(authenticatedCipher: Cipher) {
        val rt = runtime ?: return
        viewModelScope.launch {
            try {
                rt.session.withVmk { vmk ->
                    keystoreManager.finalizeBiometricEnrollment(authenticatedCipher, rt.session.contour, vmk)
                }
                postSnackbar("Биометрическая разблокировка включена")
            } catch (e: Exception) {
                postSnackbar("Не удалось включить биометрию: ${e.message ?: "ошибка keystore"}")
            }
        }
    }

    fun disableBiometric() {
        viewModelScope.launch { keystoreManager.clearBiometricEnrollment() }
    }

    fun reportBiometricError(message: String) {
        _uiState.update { it.copy(errorMessage = message) }
    }

    // ---------------------------------------------------------------
    // Навигация и папки
    // ---------------------------------------------------------------

    fun navigateToFolder(folderId: String?) {
        _uiState.update { it.copy(currentFolderId = folderId) }
    }

    fun createFolder(
        name: String,
        colorHex: String,
        iconType: FolderIconType,
        policy: StoragePolicy,
        coverMediaId: String?,
        pinned: Boolean,
        parentId: String?,
    ) {
        val rt = runtime ?: return
        viewModelScope.launch {
            val now = System.currentTimeMillis()
            rt.repository.upsertFolder(
                VaultFolder(
                    id = UUID.randomUUID().toString(),
                    parentId = parentId,
                    name = name.trim().ifBlank { "Новая папка" },
                    accentColorHex = colorHex,
                    iconType = iconType,
                    coverMediaId = coverMediaId,
                    isPinned = pinned,
                    storagePolicy = policy,
                    createdAtMs = now,
                    updatedAtMs = now,
                ),
            )
        }
    }

    fun editFolder(updated: VaultFolder) {
        val rt = runtime ?: return
        viewModelScope.launch {
            rt.repository.upsertFolder(updated.copy(updatedAtMs = System.currentTimeMillis()))
        }
    }

    fun deleteFolder(folderId: String) {
        val rt = runtime ?: return
        viewModelScope.launch {
            rt.repository.deleteFolderCascade(folderId)
            if (_uiState.value.currentFolderId == folderId) {
                _uiState.update { it.copy(currentFolderId = null) }
            }
        }
    }

    // ---------------------------------------------------------------
    // Медиа: массовые операции / избранное / просмотр
    // ---------------------------------------------------------------

    fun moveMedia(ids: Set<String>, targetFolderId: String?) {
        val rt = runtime ?: return
        viewModelScope.launch { rt.repository.moveMediaItems(ids, targetFolderId) }
    }

    fun copyMedia(ids: Set<String>, targetFolderId: String?) {
        val rt = runtime ?: return
        viewModelScope.launch { rt.repository.copyMediaItems(ids, targetFolderId) }
    }

    fun deleteMedia(ids: Set<String>, purgeFromCloud: Boolean) {
        val rt = runtime ?: return
        viewModelScope.launch {
            rt.repository.deleteMediaItems(ids, purgeFromCloud)
            postSnackbar(
                if (purgeFromCloud) "Удалено объектов: ${ids.size} (локально и в Dropbox)"
                else "Удалено объектов: ${ids.size}",
            )
        }
    }

    fun toggleFavorites(ids: Set<String>, favorite: Boolean) {
        val rt = runtime ?: return
        viewModelScope.launch {
            val now = System.currentTimeMillis()
            _uiState.value.media
                .filter { it.id in ids }
                .forEach { rt.repository.upsertMedia(it.copy(isFavorite = favorite, updatedAtMs = now)) }
        }
    }

    fun openViewer(item: MediaItem) {
        _uiState.update { it.copy(viewerMediaId = item.id) }
    }

    fun closeViewer() {
        _uiState.update { it.copy(viewerMediaId = null) }
    }

    fun viewerItem(): MediaItem? {
        val id = _uiState.value.viewerMediaId ?: return null
        return _uiState.value.media.firstOrNull { it.id == id }
    }

    fun currentSession(): VaultSessionKeys? = runtime?.session

    fun resolveEncryptedBlobFile(mediaId: String): java.io.File? {
        val rt = runtime ?: return null
        return fileStore.blobFile(rt.session.contour, mediaId)
    }

    suspend fun loadThumbnail(item: MediaItem): Bitmap? {
        val rt = runtime ?: return null
        return withContext(Dispatchers.IO) { fileStore.loadDecryptedThumbnail(rt.session, item.id) }
    }

    suspend fun loadFullResolution(item: MediaItem): Bitmap? {
        val rt = runtime ?: return null
        return withContext(Dispatchers.IO) { fileStore.loadFullResolutionPhoto(rt.session, item.id) }
    }

    // ---------------------------------------------------------------
    // Импорт из системной галереи (Scoped Storage + preflight-дубликаты)
    // ---------------------------------------------------------------

    fun onImportUrisPicked(uris: List<Uri>) {
        val rt = runtime ?: return
        if (uris.isEmpty()) return
        viewModelScope.launch {
            _uiState.update { it.copy(isImporting = true, errorMessage = null) }
            val report = withContext(Dispatchers.Default) {
                rt.secureMediaManager.preflightScanImports(uris, rt.session, _uiState.value.media)
            }
            if (report.duplicateHits.isNotEmpty()) {
                _uiState.update { it.copy(isImporting = false, pendingDuplicateReport = report) }
            } else {
                executeImportInternal(report, ImportDuplicateStrategy.KEEP_ALL, deleteSystemOriginals = false)
            }
        }
    }

    fun confirmDuplicateImport(strategy: ImportDuplicateStrategy, deleteSystemOriginals: Boolean) {
        val report = _uiState.value.pendingDuplicateReport ?: return
        viewModelScope.launch { executeImportInternal(report, strategy, deleteSystemOriginals) }
    }

    fun dismissDuplicateImport() {
        _uiState.update { it.copy(pendingDuplicateReport = null) }
    }

    private suspend fun executeImportInternal(
        report: ImportPreflightReport,
        strategy: ImportDuplicateStrategy,
        deleteSystemOriginals: Boolean,
    ) {
        val rt = runtime ?: return
        _uiState.update {
            it.copy(isImporting = true, pendingDuplicateReport = null, importProgress = 0 to report.stagedItems.size)
        }
        try {
            val outcome = rt.secureMediaManager.executeImport(
                report = report,
                targetFolderId = _uiState.value.currentFolderId,
                strategy = strategy,
                deleteSystemOriginalsAfterEncrypt = deleteSystemOriginals,
                session = rt.session,
                repository = rt.repository,
                onProgress = { current, total ->
                    _uiState.update { it.copy(importProgress = current to total) }
                },
            )
            _uiState.update {
                it.copy(
                    isImporting = false,
                    importProgress = null,
                    pendingSystemDeleteSender = outcome.systemDeleteIntentSender,
                    snackbarMessage = buildString {
                        append("Импорт завершён: ${outcome.importedCount} добавлено")
                        if (outcome.skippedDuplicatesCount > 0) append(", ${outcome.skippedDuplicatesCount} дублей пропущено")
                        if (outcome.replacedCount > 0) append(", ${outcome.replacedCount} заменено")
                    },
                )
            }
        } catch (e: Exception) {
            _uiState.update {
                it.copy(
                    isImporting = false,
                    importProgress = null,
                    snackbarMessage = "Ошибка импорта: ${e.message ?: "неизвестная ошибка"}",
                )
            }
        }
    }

    fun consumeSystemDeleteSender() {
        _uiState.update { it.copy(pendingSystemDeleteSender = null) }
    }

    // ---------------------------------------------------------------
    // Dropbox: OAuth PKCE, синхронизация, квота
    // ---------------------------------------------------------------

    /** Возвращает URL авторизации, либо null с игрой в snackbar при некорректном App Key. */
    fun buildDropboxAuthorizeUrl(appKey: String): String? {
        if (appKey.isBlank()) {
            postSnackbar("Укажите App Key приложения Dropbox")
            return null
        }
        val url = runCatching { app.dropboxAuthManager.buildAuthorizeUrl(appKey.trim(), true) }.getOrNull()
        if (url == null) {
            postSnackbar("Некорректный App Key Dropbox")
        }
        return url
    }

    fun handleDropboxRedirect(uri: Uri) {
        viewModelScope.launch {
            app.dropboxAuthManager.handleOAuthRedirectUri(uri)
                .onSuccess {
                    postSnackbar("Dropbox подключён. Шифрованные копии будут синхронизироваться автоматически.")
                    runtime?.let { rt ->
                        viewModelScope.launch { runCatching { rt.syncEngine.uploadVaultHeaderBackupIfPossible() } }
                        viewModelScope.launch { runCatching { rt.syncEngine.refreshSpaceUsage() } }
                    }
                    DropboxSyncWorkRegistry.ensurePeriodicSyncScheduled(getApplication())
                }
                .onFailure { e ->
                    postSnackbar("Dropbox: ${e.message ?: "ошибка авторизации"}")
                }
        }
    }

    fun triggerDropboxSync() {
        val rt = runtime ?: return
        viewModelScope.launch {
            runCatching { rt.syncEngine.triggerDeltaSync(keystoreManager.settingsFlow.value.syncWifiOnly) }
                .onFailure { e -> postSnackbar("Синхронизация не удалась: ${e.message ?: "ошибка"}") }
        }
    }

    fun disconnectDropbox() {
        viewModelScope.launch {
            val rt = runtime
            runCatching {
                if (rt != null) rt.syncEngine.disconnectAndWipeTokens() else app.dropboxAuthManager.disconnectAndWipe()
            }
            DropboxSyncWorkRegistry.cancelAll(getApplication())
            postSnackbar("Dropbox отключён, токены стёрты из хранилища")
        }
    }

    // ---------------------------------------------------------------
    // Настройки безопасности / производительности
    // ---------------------------------------------------------------

    fun updateSettings(transform: (AppSecuritySettings) -> AppSecuritySettings) {
        keystoreManager.updateSettings(transform)
    }

    fun postSnackbar(message: String) {
        _uiState.update { it.copy(snackbarMessage = message) }
    }

    fun consumeSnackbar() {
        _uiState.update { it.copy(snackbarMessage = null) }
    }

    private fun wipePasswords(primary: CharArray, decoy: CharArray?) {
        primary.fill('\u0000')
        decoy?.fill('\u0000')
    }
}
