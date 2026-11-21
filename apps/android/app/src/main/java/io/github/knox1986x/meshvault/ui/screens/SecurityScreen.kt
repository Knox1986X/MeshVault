package io.github.knox1986x.meshvault.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import io.github.knox1986x.meshvault.security.ScrubSummary
import io.github.knox1986x.meshvault.ui.components.CockpitCard
import io.github.knox1986x.meshvault.ui.components.StatusPill
import io.github.knox1986x.meshvault.ui.components.formatBytesCompact
import io.github.knox1986x.meshvault.ui.theme.CockpitColors

@Composable
fun SecurityScreen(
    biometricEnrolled: Boolean,
    onRunScrub: () -> ScrubSummary,
    onGenerateRecoveryKit: () -> String,
    onEnterSafePresentation: () -> Unit,
    onLockNow: () -> Unit,
) {
    var scrubResult by remember { mutableStateOf<ScrubSummary?>(null) }
    var recoveryPhrase by remember { mutableStateOf<String?>(null) }

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
                StatusPill(label = "Sync: Local Only (Dropbox / LAN на этапе 5)", dotColor = CockpitColors.Amber)
            }
        }

        CockpitCard(modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(
                    text = "Самопроверка целостности (Vault Scrub)",
                    color = CockpitColors.TextPrimary,
                    fontSize = 15.sp,
                    fontWeight = FontWeight.SemiBold,
                )
                Text(
                    text = "Проверяет теги аутентификации Poly1305 каждого чанка и заголовка.",
                    color = CockpitColors.TextSecondary,
                    fontSize = 12.sp,
                )
                Button(
                    onClick = { scrubResult = onRunScrub() },
                    shape = RoundedCornerShape(8.dp),
                    colors = ButtonDefaults.buttonColors(containerColor = CockpitColors.AccentViolet),
                ) {
                    Text("Запустить Scrub")
                }
                scrubResult?.let { res ->
                    Text(
                        text = "Проверено блобов: ${res.checkedBlobs} · чанков: ${res.checkedChunks} · " +
                            "байт: ${formatBytesCompact(res.verifiedBytes)} · битых: ${res.corruptedCount}",
                        color = if (res.corruptedCount == 0L) CockpitColors.Emerald else CockpitColors.Red,
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
                OutlinedButton(
                    onClick = { recoveryPhrase = onGenerateRecoveryKit() },
                    shape = RoundedCornerShape(8.dp),
                ) {
                    Text("Сформировать Recovery Kit")
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
            Text("Включить режим «Безопасный показ» (Safe Presentation)")
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
