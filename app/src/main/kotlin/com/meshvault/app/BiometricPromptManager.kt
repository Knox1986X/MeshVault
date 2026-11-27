package com.meshvault.app

import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.fragment.app.FragmentActivity
import java.util.concurrent.Executor
import java.util.concurrent.Executors
import javax.crypto.Cipher

/**
 * Тонкая обёртка над androidx.biometric.BiometricPrompt с CryptoObject:
 * ключ разблокировки хранится в Android Keystore и аутентифицируется биометрией —
 * сам VMK никогда не покидает keystore без подтверждения личности.
 */
object BiometricPromptManager {

    private val executor: Executor = Executors.newSingleThreadExecutor()

    fun isBiometricAvailable(activity: FragmentActivity): Boolean =
        BiometricManager.from(activity)
            .canAuthenticate(BiometricManager.BIOMETRIC_STRONG) == BiometricManager.BIOMETRIC_SUCCESS

    /**
     * Показывает диалог биометрии. [onAuthenticated] получает аутентифицированный [Cipher],
     * который после успешной аутентификации разрешает операции with аппаратным ключом.
     */
    fun show(
        activity: FragmentActivity,
        title: String,
        subtitle: String,
        cipher: Cipher,
        onAuthenticated: (Cipher) -> Unit,
        onError: (String) -> Unit,
    ) {
        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle(title)
            .setSubtitle(subtitle)
            .setNegativeButtonText("Отмена")
            .setAllowedAuthenticators(BiometricManager.BIOMETRIC_STRONG)
            .build()

        val prompt = BiometricPrompt(
            activity,
            executor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    if (errorCode != BiometricPrompt.ERROR_USER_CANCELED &&
                        errorCode != BiometricPrompt.ERROR_NEGATIVE_BUTTON &&
                        errorCode != BiometricPrompt.ERROR_CANCELED
                    ) {
                        onError(errString.toString())
                    }
                }

                override fun onAuthenticationFailed() {
                    // BiometricPrompt сам показывает «не получилось» — ничего не делаем
                }

                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    val authenticated = result.cryptoObject?.cipher ?: cipher
                    onAuthenticated(authenticated)
                }
            },
        )
        prompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(cipher))
    }
}
