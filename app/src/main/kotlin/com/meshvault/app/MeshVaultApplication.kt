package com.meshvault.app

import android.app.Application
import com.meshvault.data.db.HardwareKeystoreManager
import com.meshvault.data.media.EncryptedMediaFileStore
import com.meshvault.data.sync.dropbox.DropboxPkceAuthManager
import okhttp3.OkHttpClient

/**
 * Точка входа и владелец process-wide синглтонов:
 * - аппаратный keystore-менеджер (vault_header / настройки / биометрия / токены Dropbox),
 * - кэш зашифрованных файлов и миниатюр в ОЗУ (с настраиваемым профилем производительности),
 * - общий PKCE-менеджер Dropbox (авторизация возможна до открытия хранилища).
 *
 * Сессия VaultSessionKeys создаётся только в [VaultViewModel] после разблокировки
 * и живёт только в памяти — на диске ключей нет.
 */
class MeshVaultApplication : Application() {

    lateinit var keystoreManager: HardwareKeystoreManager
        private set

    lateinit var fileStore: EncryptedMediaFileStore
        private set

    lateinit var dropboxAuthManager: DropboxPkceAuthManager
        private set

    val dropboxHttpClient: OkHttpClient = OkHttpClient()

    override fun onCreate() {
        super.onCreate()
        keystoreManager = HardwareKeystoreManager(this)
        fileStore = EncryptedMediaFileStore(this, keystoreManager.settingsFlow.value.performanceProfile)
        dropboxAuthManager = DropboxPkceAuthManager(keystoreManager, dropboxHttpClient)
    }
}
