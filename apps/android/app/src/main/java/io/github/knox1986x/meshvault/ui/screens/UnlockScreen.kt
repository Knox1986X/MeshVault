package io.github.knox1986x.meshvault.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Fingerprint
import androidx.compose.material.icons.rounded.Key
import androidx.compose.material.icons.rounded.Shield
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import io.github.knox1986x.meshvault.ui.components.CockpitCard
import io.github.knox1986x.meshvault.ui.components.StatusPill
import io.github.knox1986x.meshvault.ui.theme.CockpitColors

@Composable
fun UnlockScreen(
    selectedVaultName: String,
    biometricsAvailable: Boolean,
    errorText: String?,
    onUnlockPassphrase: (String) -> Unit,
    onUnlockBiometric: () -> Unit,
    onUnlockRecoveryKit: (String) -> Unit,
    onSelectVaultName: (String) -> Unit,
) {
    var passphrase by remember { mutableStateOf("") }
    var showRecoveryMode by remember { mutableStateOf(false) }
    var recoveryPhrase by remember { mutableStateOf("") }
    val vaults = remember { listOf("Личное", "Документы", "Поездки") }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(CockpitColors.Background)
            .verticalScroll(rememberScrollState())
            .padding(20.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Icon(
            imageVector = Icons.Rounded.Shield,
            contentDescription = "MeshVault",
            tint = CockpitColors.AccentVioletLight,
            modifier = Modifier.size(54.dp),
        )
        Spacer(modifier = Modifier.height(10.dp))
        Text(
            text = "MeshVault",
            color = CockpitColors.TextPrimary,
            fontSize = 26.sp,
            fontWeight = FontWeight.Bold,
        )
        Text(
            text = "zero-plaintext-on-disk · XChaCha20-Poly1305",
            color = CockpitColors.TextSecondary,
            fontSize = 12.sp,
            fontFamily = FontFamily.Monospace,
        )
        Spacer(modifier = Modifier.height(14.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            StatusPill(label = "Screen: FLAG_SECURE", dotColor = CockpitColors.AccentVioletLight)
            StatusPill(label = "Vault: Locked", dotColor = CockpitColors.Amber)
        }
        Spacer(modifier = Modifier.height(20.dp))

        CockpitCard(modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(16.dp)) {
                Text(
                    text = "Выбор независимого сейфа",
                    color = CockpitColors.TextSecondary,
                    fontSize = 12.sp,
                )
                Spacer(modifier = Modifier.height(8.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    vaults.forEach { name ->
                        val active = name == selectedVaultName
                        OutlinedButton(
                            onClick = { onSelectVaultName(name) },
                            modifier = Modifier.weight(1f),
                            shape = RoundedCornerShape(8.dp),
                            colors = ButtonDefaults.outlinedButtonColors(
                                containerColor = if (active) CockpitColors.AccentViolet.copy(alpha = 0.22f)
                                else Color.Transparent,
                                contentColor = if (active) CockpitColors.AccentVioletLight else CockpitColors.TextSecondary,
                            ),
                        ) {
                            Text(text = name, fontSize = 11.sp, maxLines = 1)
                        }
                    }
                }

                Spacer(modifier = Modifier.height(16.dp))

                if (!showRecoveryMode) {
                    OutlinedTextField(
                        value = passphrase,
                        onValueChange = { passphrase = it },
                        label = { Text("Мастер-пароль сейфа «$selectedVaultName»") },
                        singleLine = true,
                        visualTransformation = PasswordVisualTransformation(),
                        keyboardOptions = KeyboardOptions(
                            keyboardType = KeyboardType.Password,
                            autoCorrectEnabled = false,
                            imeAction = ImeAction.Done,
                        ),
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedBorderColor = CockpitColors.AccentViolet,
                            unfocusedBorderColor = CockpitColors.CardBorder,
                            focusedTextColor = CockpitColors.TextPrimary,
                            unfocusedTextColor = CockpitColors.TextPrimary,
                        ),
                        modifier = Modifier.fillMaxWidth(),
                    )
                    Spacer(modifier = Modifier.height(12.dp))
                    Button(
                        onClick = { onUnlockPassphrase(passphrase) },
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(8.dp),
                        colors = ButtonDefaults.buttonColors(containerColor = CockpitColors.AccentViolet),
                    ) {
                        Text("Открыть сейф", fontWeight = FontWeight.SemiBold)
                    }

                    if (biometricsAvailable) {
                        Spacer(modifier = Modifier.height(8.dp))
                        OutlinedButton(
                            onClick = onUnlockBiometric,
                            modifier = Modifier.fillMaxWidth(),
                            shape = RoundedCornerShape(8.dp),
                        ) {
                            Icon(Icons.Rounded.Fingerprint, contentDescription = null)
                            Spacer(modifier = Modifier.size(8.dp))
                            Text("Войти по биометрии (Keystore TEE)")
                        }
                    }
                } else {
                    OutlinedTextField(
                        value = recoveryPhrase,
                        onValueChange = { recoveryPhrase = it },
                        label = { Text("Recovery Kit (24 слова через пробел)") },
                        minLines = 3,
                        keyboardOptions = KeyboardOptions(
                            autoCorrectEnabled = false,
                            keyboardType = KeyboardType.Ascii,
                        ),
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedBorderColor = CockpitColors.Cyan,
                            unfocusedBorderColor = CockpitColors.CardBorder,
                            focusedTextColor = CockpitColors.TextPrimary,
                            unfocusedTextColor = CockpitColors.TextPrimary,
                        ),
                        modifier = Modifier.fillMaxWidth(),
                    )
                    Spacer(modifier = Modifier.height(12.dp))
                    Button(
                        onClick = { onUnlockRecoveryKit(recoveryPhrase) },
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(8.dp),
                        colors = ButtonDefaults.buttonColors(containerColor = CockpitColors.Cyan),
                    ) {
                        Text("Восстановить доступ по Recovery Kit", color = Color.Black, fontWeight = FontWeight.Bold)
                    }
                }

                if (errorText != null) {
                    Spacer(modifier = Modifier.height(10.dp))
                    Text(text = errorText, color = CockpitColors.Red, fontSize = 12.sp)
                }

                Spacer(modifier = Modifier.height(10.dp))
                OutlinedButton(
                    onClick = { showRecoveryMode = !showRecoveryMode },
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(8.dp),
                ) {
                    Icon(Icons.Rounded.Key, contentDescription = null, modifier = Modifier.size(16.dp))
                    Spacer(modifier = Modifier.size(6.dp))
                    Text(
                        text = if (showRecoveryMode) "Вернуться к мастер-паролю" else "Аварийный вход по 24 словам",
                        fontSize = 12.sp,
                    )
                }
            }
        }
    }
}
