package io.github.knox1986x.meshvault.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import io.github.knox1986x.meshvault.security.DoctorSnapshot
import io.github.knox1986x.meshvault.security.ScrubSummary
import io.github.knox1986x.meshvault.security.VaultMediaItem
import io.github.knox1986x.meshvault.ui.components.CockpitCard
import io.github.knox1986x.meshvault.ui.components.StatusPill
import io.github.knox1986x.meshvault.ui.components.formatBytesCompact
import io.github.knox1986x.meshvault.ui.theme.CockpitColors

@Composable
fun SecurityScreen(
    biometricEnrolled: Boolean,
    disguisedNotesIcon: Boolean,
    flipToLockEnabled: Boolean,
    trashedItems: List<VaultMediaItem>,
    onToggleDisguisedIcon: (Boolean) -> Unit,
    onToggleFlipToLock: (Boolean) -> Unit,
    onConfigureDecoyVault: (String) -> Unit,
    onRestoreTrashed: (String) -> Unit,
    onShredTrashed: (String) -> Unit,
    onRunScrub: () -> ScrubSummary,
    onRunDoctor: () -> DoctorSnapshot,
    onGenerateRecoveryKit: () -> String,
    onCopySensitive: (String) -> Unit,
    onEnterSafePresentation: () -> Unit,
    onLockNow: () -> Unit,
) {
    var scrubResult by remember { mutableStateOf<ScrubSummary?>(null) }
    var doctorResult by remember { mutableStateOf<DoctorSnapshot?>(null) }
    var recoveryPhrase by remember { mutableStateOf<String?>(null) }
    var decoyPin by remember { mutableStateOf("") }
    var decoyStatus by remember { mutableStateOf<String?>(null) }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        CockpitCard(modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(
                    text = "Криптографическая защита",
                    color = CockpitColors.TextPrimary,
                    fontSize = 16.sp,
                    fontWeight = FontWeight.SemiBold,
                )
                StatusPill(
                    label = if (biometricEnrolled) "Keystore TEE: Активен" else "Keystore TEE: Мастер-пароль",
                    dotColor = if (biometricEnrolled) CockpitColors.Emerald else CockpitColors.Amber,
                )
                StatusPill(label = "Clipboard Guard: Автоочистка 30с", dotColor = CockpitColors.Cyan)
                StatusPill(label = "Sync: Local Only (Этап 5)", dotColor = CockpitColors.Amber)
            }
        }

        CockpitCard(modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Text(
                    text = "Приватность в жизни и маскировка",
                    color = CockpitColors.TextPrimary,
                    fontSize = 15.sp,
                    fontWeight = FontWeight.SemiBold,
                )
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween,
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text("Маскировать иконку под «Заметки»", color = CockpitColors.TextPrimary, fontSize = 13.sp)
                        Text("Переключение Launcher activity-alias", color = CockpitColors.TextMuted, fontSize = 11.sp)
                    }
                    Switch(checked = disguisedNotesIcon, onCheckedChange = onToggleDisguisedIcon)
                }
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween,
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text("Flip-to-Lock (экран вниз -> блок)", color = CockpitColors.TextPrimary, fontSize = 13.sp)
                        Text("Датчик акселерометра", color = CockpitColors.TextMuted, fontSize = 11.sp)
                    }
                    Switch(checked = flipToLockEnabled, onCheckedChange = onToggleFlipToLock)
                }
            }
        }

        CockpitCard(modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(
                    text = "Ложный сейф (Decoy Vault)",
                    color = CockpitColors.TextPrimary,
                    fontSize = 15.sp,
                    fontWeight = FontWeight.SemiBold,
                )
                Text(
                    text = "Отдельный пароль открывает изолированный ложный каталог. Модель угроз: при криминалистическом анализе наличие второго слота может быть замечено по размеру заголовка, но содержимое реального сейфа неотличимо от случайного шума.",
                    color = CockpitColors.TextSecondary,
                    fontSize = 11.sp,
                )
                OutlinedTextField(
                    value = decoyPin,
                    onValueChange = { decoyPin = it },
                    label = { Text("Пароль / PIN ложного сейфа") },
                    singleLine = true,
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(
                        keyboardType = KeyboardType.Password,
                        autoCorrectEnabled = false,
                    ),
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedButton(
                    onClick = {
                        if (decoyPin.isNotBlank()) {
                            onConfigureDecoyVault(decoyPin)
                            decoyPin = ""
                            decoyStatus = "Ложный сейф активирован (независимый MVK и каталог)"
                        }
                    },
                    shape = RoundedCornerShape(8.dp),
                ) {
                    Text("Настроить / обновить Decoy Vault")
                }
                decoyStatus?.let {
                    Text(text = it, color = CockpitColors.Emerald, fontSize = 11.sp, fontFamily = FontFamily.Monospace)
                }
            }
        }

        CockpitCard(modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(
                    text = "Зашифрованная Корзина (срок 30 дней)",
                    color = CockpitColors.TextPrimary,
                    fontSize = 15.sp,
                    fontWeight = FontWeight.SemiBold,
                )
                if (trashedItems.isEmpty()) {
                    Text("Корзина пуста.", color = CockpitColors.TextSecondary, fontSize = 12.sp)
                } else {
                    trashedItems.forEach { item ->
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.SpaceBetween,
                        ) {
                            Text(
                                text = "${item.originalName} (${formatBytesCompact(item.plaintextSize)})",
                                color = CockpitColors.TextPrimary,
                                fontSize = 12.sp,
                                modifier = Modifier.weight(1f),
                            )
                            TextButton(onClick = { onRestoreTrashed(item.id) }) {
                                Text("Восст.", color = CockpitColors.Emerald, fontSize = 11.sp)
                            }
                            TextButton(onClick = { onShredTrashed(item.id) }) {
                                Text("Уничтожить", color = CockpitColors.Red, fontSize = 11.sp)
                            }
                        }
                    }
                }
            }
        }

        CockpitCard(modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(
                    text = "MeshVault Doctor и Vault Scrub",
                    color = CockpitColors.TextPrimary,
                    fontSize = 15.sp,
                    fontWeight = FontWeight.SemiBold,
                )
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(
                        onClick = { scrubResult = onRunScrub() },
                        shape = RoundedCornerShape(8.dp),
                        colors = ButtonDefaults.buttonColors(containerColor = CockpitColors.AccentViolet),
                    ) {
                        Text("Запустить Scrub")
                    }
                    OutlinedButton(
                        onClick = { doctorResult = onRunDoctor() },
                        shape = RoundedCornerShape(8.dp),
                    ) {
                        Text("MeshVault Doctor")
                    }
                }
                scrubResult?.let { res ->
                    Text(
                        text = "Scrub: блобов ${res.checkedBlobs} · чанков ${res.checkedChunks} · " +
                            "байт ${formatBytesCompact(res.verifiedBytes)} · битых ${res.corruptedCount}",
                        color = if (res.corruptedCount == 0L) CockpitColors.Emerald else CockpitColors.Red,
                        fontFamily = FontFamily.Monospace,
                        fontSize = 11.sp,
                    )
                }
                doctorResult?.let { doc ->
                    Text(
                        text = "Doctor: hdr=${doc.primaryHeaderValid}/${doc.backupHeaderValid} · rev=${doc.headerRevision} · " +
                            "slots=${doc.keySlotCount} · decoy=${doc.decoyConfigured} · media=${doc.mediaCount} · missing=${doc.missingBlobsCount}",
                        color = CockpitColors.Cyan,
                        fontFamily = FontFamily.Monospace,
                        fontSize = 11.sp,
                    )
                }
            }
        }

        CockpitCard(modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(
                    text = "Аварийный ключ восстановления (24 слова)",
                    color = CockpitColors.TextPrimary,
                    fontSize = 15.sp,
                    fontWeight = FontWeight.SemiBold,
                )
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedButton(
                        onClick = { recoveryPhrase = onGenerateRecoveryKit() },
                        shape = RoundedCornerShape(8.dp),
                    ) {
                        Text("Показать 24 слова")
                    }
                    recoveryPhrase?.let { phrase ->
                        OutlinedButton(
                            onClick = { onCopySensitive(phrase) },
                            shape = RoundedCornerShape(8.dp),
                        ) {
                            Text("Копировать (30с)")
                        }
                    }
                }
                recoveryPhrase?.let { phrase ->
                    Text(
                        text = phrase,
                        color = CockpitColors.Cyan,
                        fontFamily = FontFamily.Monospace,
                        fontSize = 12.sp,
                    )
                }
            }
        }

        OutlinedButton(
            onClick = onEnterSafePresentation,
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(8.dp),
        ) {
            Text("Включить «Безопасный показ» (Safe Presentation Lock)")
        }

        Spacer(modifier = Modifier.height(4.dp))

        Button(
            onClick = onLockNow,
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(8.dp),
            colors = ButtonDefaults.buttonColors(containerColor = CockpitColors.Red),
        ) {
            Text("Экстренно заблокировать и очистить ОЗУ", fontWeight = FontWeight.Bold)
        }
    }
}
