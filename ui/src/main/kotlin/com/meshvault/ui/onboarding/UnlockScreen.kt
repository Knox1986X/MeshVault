package com.meshvault.ui.onboarding

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Fingerprint
import androidx.compose.material.icons.filled.Add
import com.meshvault.ui.theme.CyberObsidian

/**
 * Экран создания и разблокировки хранилища.
 * Пароль ложного дна ничем не отличается визуально — одно и то же поле ввода,
 * чтобы наблюдатель не мог отличить основной контур от «безобидного».
 */
@Composable
fun UnlockScreen(
    vaultExists: Boolean,
    isWorking: Boolean,
    errorMessage: String?,
    biometricEnabled: Boolean,
    onUnlock: (CharArray) -> Unit,
    onCreateVault: (CharArray, CharArray?) -> Unit,
    onBiometricUnlock: () -> Unit,
) {
    var password by remember { mutableStateOf("") }
    var passwordRepeat by remember { mutableStateOf("") }
    var decoyPassword by remember { mutableStateOf("") }
    var decoyExpanded by remember { mutableStateOf(false) }
    var passwordVisible by remember { mutableStateOf(false) }

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(CyberObsidian.Abyss)
            .verticalScroll(rememberScrollState()),
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 28.dp, vertical = 46.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Box(
                modifier = Modifier
                    .size(84.dp)
                    .clip(RoundedCornerShape(22.dp))
                    .background(CyberObsidian.EmeraldDim),
                contentAlignment = Alignment.Center,
            ) {
                Icon(
                    imageVector = Icons.Filled.Shield,
                    contentDescription = null,
                    modifier = Modifier.size(40.dp),
                    tint = CyberObsidian.Emerald,
                )
            }

            Text(
                text = "MeshVault",
                modifier = Modifier.padding(top = 18.dp),
                fontSize = 30.sp,
                fontWeight = FontWeight.Black,
                color = CyberObsidian.TextPrimary,
            )
            Text(
                text = if (vaultExists) {
                    "Zero-Knowledge хранилище заблокировано"
                } else {
                    "Создайте Zero-Knowledge хранилище"
                },
                modifier = Modifier.padding(top = 4.dp),
                style = MaterialTheme.typography.bodyMedium,
                color = CyberObsidian.TextSecondary,
            )

            Row(
                modifier = Modifier.padding(top = 10.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                HintChip("Argon2id · 64 МБ")
                HintChip("AES-256-GCM")
                HintChip("MVCH v2")
            }

            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(top = 28.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                OutlinedTextField(
                    value = password,
                    onValueChange = { password = it },
                    modifier = Modifier.fillMaxWidth(),
                    label = { Text(if (vaultExists) "Мастер-пароль" else "Новый мастер-пароль") },
                    singleLine = true,
                    visualTransformation = if (passwordVisible) VisualTransformation.None else PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(
                        keyboardType = KeyboardType.Password,
                        imeAction = ImeAction.Done,
                        autoCorrectEnabled = false,
                    ),
                    trailingIcon = {
                        IconButton(onClick = { passwordVisible = !passwordVisible }) {
                            Icon(
                                imageVector = if (passwordVisible) Icons.Filled.VisibilityOff else Icons.Filled.Visibility,
                                contentDescription = if (passwordVisible) "Скрыть пароль" else "Показать пароль",
                                tint = CyberObsidian.TextSecondary,
                            )
                        }
                    },
                )

                if (!vaultExists) {
                    if (passwordRepeat.isNotEmpty() && password != passwordRepeat) {
                        Text(
                            text = "Пароли не совпадают",
                            color = CyberObsidian.Danger,
                            style = MaterialTheme.typography.bodySmall,
                            modifier = Modifier.padding(horizontal = 4.dp),
                        )
                    }
                    OutlinedTextField(
                        value = passwordRepeat,
                        onValueChange = { passwordRepeat = it },
                        modifier = Modifier.fillMaxWidth(),
                        label = { Text("Повторите мастер-пароль") },
                        singleLine = true,
                        visualTransformation = PasswordVisualTransformation(),
                        keyboardOptions = KeyboardOptions(
                            keyboardType = KeyboardType.Password,
                            imeAction = ImeAction.Next,
                            autoCorrectEnabled = false,
                        ),
                    )

                    TextButton(onClick = { decoyExpanded = !decoyExpanded }) {
                        Icon(
                            imageVector = Icons.Filled.Add,
                            contentDescription = null,
                            tint = CyberObsidian.Sky,
                            modifier = Modifier.size(16.dp),
                        )
                        Text(
                            text = if (decoyExpanded) "Скрыть ложное дно" else "Добавить ложное дно (decoy vault)",
                            color = CyberObsidian.Sky,
                            modifier = Modifier.padding(start = 6.dp),
                        )
                    }

                    if (decoyExpanded) {
                        OutlinedTextField(
                            value = decoyPassword,
                            onValueChange = { decoyPassword = it },
                            modifier = Modifier.fillMaxWidth(),
                            label = { Text("Пароль ложного дна") },
                            singleLine = true,
                            visualTransformation = PasswordVisualTransformation(),
                            keyboardOptions = KeyboardOptions(
                                keyboardType = KeyboardType.Password,
                                imeAction = ImeAction.Done,
                                autoCorrectEnabled = false,
                            ),
                        )
                        Text(
                            text = "Второй пароль открывает изолированное хранилище с нейтральным содержимым. " +
                                "Его невозможно отличить от основного контура ни визуально, ни по заголовку файла.",
                            style = MaterialTheme.typography.bodySmall,
                            color = CyberObsidian.TextSecondary,
                            modifier = Modifier.padding(horizontal = 4.dp),
                        )
                    }
                }
            }

            if (errorMessage != null) {
                Text(
                    text = errorMessage,
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(top = 12.dp),
                    color = CyberObsidian.Danger,
                    style = MaterialTheme.typography.bodyMedium,
                )
            }

            val canSubmit = if (vaultExists) {
                password.isNotBlank()
            } else {
                password.isNotBlank() && passwordRepeat.isNotBlank() && password == passwordRepeat
            }

            Button(
                onClick = {
                    if (isWorking || !canSubmit) return@Button
                    if (vaultExists) {
                        onUnlock(password.toCharArray())
                    } else {
                        val decoy = decoyPassword.takeIf { it.isNotBlank() }?.toCharArray()
                        onCreateVault(password.toCharArray(), decoy)
                    }
                },
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(top = 18.dp),
                enabled = canSubmit,
                colors = ButtonDefaults.buttonColors(
                    containerColor = CyberObsidian.Emerald,
                    contentColor = CyberObsidian.EmeraldOn,
                ),
            ) {
                if (isWorking) {
                    CircularProgressIndicator(
                        modifier = Modifier.size(18.dp),
                        strokeWidth = 2.dp,
                        color = CyberObsidian.EmeraldOn,
                    )
                } else {
                    Icon(
                        imageVector = Icons.Filled.Lock,
                        contentDescription = null,
                        modifier = Modifier.size(18.dp),
                    )
                    Text(
                        text = if (vaultExists) "Разблокировать" else "Создать хранилище",
                        modifier = Modifier.padding(start = 8.dp),
                        fontWeight = FontWeight.Bold,
                    )
                }
            }

            if (vaultExists && biometricEnabled) {
                OutlinedButton(
                    onClick = { if (!isWorking) onBiometricUnlock() },
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(top = 10.dp),
                ) {
                    Icon(
                        imageVector = Icons.Filled.Fingerprint,
                        contentDescription = null,
                        tint = CyberObsidian.Sky,
                    )
                    Text(
                        text = "Войти по биометрии",
                        modifier = Modifier.padding(start = 8.dp),
                        color = CyberObsidian.Sky,
                    )
                }
            }

            Text(
                text = "Panic Lock: мгновенный выход по кнопке в шапке, таймеру или встряхиванию. " +
                    "Все ключи в ОЗУ и кэш битмапов зануляются.",
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(top = 26.dp),
                style = MaterialTheme.typography.bodySmall,
                color = CyberObsidian.TextMuted,
            )
        }
    }
}

@Composable
private fun HintChip(text: String) {
    Box(
        modifier = Modifier
            .clip(RoundedCornerShape(10.dp))
            .background(CyberObsidian.Surface)
            .padding(horizontal = 10.dp, vertical = 6.dp),
    ) {
        Text(
            text = text,
            style = MaterialTheme.typography.labelSmall,
            color = CyberObsidian.TextSecondary,
            fontWeight = FontWeight.SemiBold,
        )
    }
}
