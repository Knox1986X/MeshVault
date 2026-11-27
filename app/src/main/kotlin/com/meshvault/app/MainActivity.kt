package com.meshvault.app

import android.content.Intent
import android.os.Bundle
import androidx.activity.compose.setContent
import androidx.activity.viewModels
import androidx.appcompat.app.AppCompatActivity
import com.meshvault.ui.theme.CyberObsidianTheme

/**
 * Единственная Activity: разблокировка → галерея.
 * Обрабатывает OAuth-редирект Dropbox (meshvault://oauth2redirect).
 */
class MainActivity : AppCompatActivity() {

    private val viewModel: VaultViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        handleDropboxRedirect(intent)

        setContent {
            CyberObsidianTheme {
                com.meshvault.app.ui.MeshVaultApp(
                    viewModel = viewModel,
                    onRequestBiometricUnlock = ::launchBiometricUnlock,
                    onRequestBiometricEnrollment = ::launchBiometricEnrollment,
                )
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        handleDropboxRedirect(intent)
    }

    override fun onStart() {
        super.onStart()
        viewModel.onForegrounded()
    }

    override fun onStop() {
        super.onStop()
        viewModel.onBackgrounded()
    }

    private fun handleDropboxRedirect(intent: Intent?) {
        val uri = intent?.data ?: return
        if (uri.scheme == "meshvault" && uri.host == "oauth2redirect") {
            viewModel.handleDropboxRedirect(uri)
            // Одноразовый редирект — не переобрабатывать при повороте
            intent.data = null
        }
    }

    private fun launchBiometricUnlock() {
        val pair = viewModel.createBiometricUnlockCipher()
        if (pair == null) {
            viewModel.reportBiometricError("Биометрическая разблокировка не настроена на этом устройстве")
            return
        }
        val (cipher, contour) = pair
        BiometricPromptManager.show(
            activity = this,
            title = "Разблокировка MeshVault",
            subtitle = "Подтвердите личность для расшифровки хранилища",
            cipher = cipher,
            onAuthenticated = { authenticated -> viewModel.unlockWithBiometric(authenticated, contour) },
            onError = { message -> viewModel.reportBiometricError(message) },
        )
    }

    private fun launchBiometricEnrollment() {
        val cipher = viewModel.createBiometricEncryptCipher()
        if (cipher == null) {
            viewModel.reportBiometricError("Биометрический ключ недоступен. Проверьте настройки устройства.")
            return
        }
        BiometricPromptManager.show(
            activity = this,
            title = "Включить разблокировку по биометрии",
            subtitle = "VMK будет зашифрован аппаратным ключом Android Keystore",
            cipher = cipher,
            onAuthenticated = { authenticated -> viewModel.enrollBiometric(authenticated) },
            onError = { message -> viewModel.reportBiometricError(message) },
        )
    }
}
