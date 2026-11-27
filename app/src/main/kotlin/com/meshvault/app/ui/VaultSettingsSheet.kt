package com.meshvault.app.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.getValue
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.meshvault.app.VaultUiState
import com.meshvault.app.VaultViewModel
import com.meshvault.domain.repository.AutoLockTimeout
import com.meshvault.domain.repository.DropboxSyncPhase
import com.meshvault.domain.repository.PerformanceProfile
import com.meshvault.ui.components.SectionHeader
import com.meshvault.ui.components.formatBytesCompact
import com.meshvault.ui.theme.CyberObsidian

private val cacheLimitOptionsMb = listOf(1024, 2048, 8192)
private val clipboardOptionsSec = listOf(10, 25, 60)

/**
 * Нижняя шторка настроек: безопасность, производительность, Dropbox-синк.
 * Все переключатели пишут напрямую в аппаратно-зашифрованное хранилище настроек.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun VaultSettingsSheet(
    uiState: VaultUiState,
    viewModel: VaultViewModel,
    onDismiss: () -> Unit,
    onRequestBiometricEnrollment: () -> Unit,
    onOpenUrl: (String) -> Unit,
) {
    val settings = uiState.settings

    ModalBottomSheet(onDismissRequest = onDismiss) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 20.dp, vertical = 4.dp)
                .padding(bottom = 32.dp),
        ) {
            Text(
                text = "Настройки хранилища",
                style = MaterialTheme.typography.titleLarge,
                color = CyberObsidian.TextPrimary,
                fontWeight = FontWeight.Bold,
            )

            SectionHeader(
                title = "Безопасность",
                subtitle = "Всё защищено мастер-паролем и аппаратным ключом",
            )
            SwitchSettingRow(
                title = "Запретить скриншоты (FLAG_SECURE)",
                subtitle = "Блокировка захвата экрана и превью в списке последних приложений",
                checked = settings.flagSecureEnabled,
                onCheckedChange = { v -> viewModel.updateSettings { it.copy(flagSecureEnabled = v) } },
            )
            SwitchSettingRow(
                title = "Panic Lock по встряхиванию",
                subtitle = "Мгновенное зануление VMK и под ключей в ОЗУ при резкой встряске",
                checked = settings.shakeToPanicLockEnabled,
                onCheckedChange = { v -> viewModel.updateSettings { it.copy(shakeToPanicLockEnabled = v) } },
            )
            SwitchSettingRow(
                title = "Разблокировка по биометрии",
                subtitle = "VMK запечатан аппаратным ключом Android Keystore",
                checked = settings.biometricUnlockEnabled,
                onCheckedChange = { v ->
                    if (v) onRequestBiometricEnrollment() else viewModel.disableBiometric()
                },
            )
            ChipSettingRow(
                title = "Авто-блокировка при сворачивании",
                options = AutoLockTimeout.entries.map { it.labelRu },
                selected = settings.autoLockTimeout.labelRu,
                onSelect = { label ->
                    val match = AutoLockTimeout.entries.firstOrNull { it.labelRu == label }
                    if (match != null) viewModel.updateSettings { it.copy(autoLockTimeout = match) }
                },
            )
            ChipSettingRow(
                title = "Очистка буфера обмена",
                options = clipboardOptionsSec.map { "$it сек" },
                selected = "${settings.clipboardAutoClearSeconds} сек",
                onSelect = { label ->
                    val seconds = label.removeSuffix(" сек").toIntOrNull()
                    if (seconds != null) viewModel.updateSettings { it.copy(clipboardAutoClearSeconds = seconds) }
                },
            )

            SectionHeader(
                title = "Производительность",
                subtitle = "Профиль влияет на LruCache миниатюр и число потоков декодирования",
            )
            ChipSettingRow(
                title = "Профиль хранилища",
                options = PerformanceProfile.entries.map { it.labelRu },
                selected = settings.performanceProfile.labelRu,
                onSelect = { label ->
                    val match = PerformanceProfile.entries.firstOrNull { it.labelRu == label }
                    if (match != null) viewModel.updateSettings { it.copy(performanceProfile = match) }
                },
            )
            Text(
                text = settings.performanceProfile.descriptionRu,
                style = MaterialTheme.typography.bodySmall,
                color = CyberObsidian.TextSecondary,
                modifier = Modifier.padding(top = 2.dp, bottom = 8.dp),
            )
            ChipSettingRow(
                title = "Лимит кэша оригиналов (On-Demand)",
                options = cacheLimitOptionsMb.map { formatMb(it) },
                selected = formatMb(settings.onDemandCacheLimitMb),
                onSelect = { label ->
                    val mb = cacheLimitOptionsMb.firstOrNull { formatMb(it) == label }
                    if (mb != null) viewModel.updateSettings { it.copy(onDemandCacheLimitMb = mb) }
                },
            )

            SectionHeader(
                title = "Dropbox · E2EE-синхронизация",
                subtitle = "На сервер уходят только зашифрованные MVCH v2 контейнеры",
            )
            if (uiState.dropboxConnected) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(12.dp))
                        .background(CyberObsidian.EmeraldDim)
                        .padding(horizontal = 12.dp, vertical = 10.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Icon(
                        imageVector = androidx.compose.material.icons.Icons.Filled.CloudDone,
                        contentDescription = null,
                        tint = CyberObsidian.Emerald,
                    )
                    Text(
                        text = "Подключено. Дельта-синк CRDT раз в 6 часов.",
                        color = CyberObsidian.TextPrimary,
                        style = MaterialTheme.typography.bodySmall,
                        modifier = Modifier.padding(start = 8.dp),
                    )
                }

                uiState.dropboxQuota?.let { quota ->
                    LinearProgressIndicator(
                        progress = { quota.usedFraction },
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(top = 10.dp),
                        color = CyberObsidian.Emerald,
                        trackColor = CyberObsidian.SurfaceRaised,
                    )
                    Text(
                        text = buildString {
                            append("Занято ")
                            append(formatBytesCompact(quota.usedBytes))
                            append(" из ")
                            append(formatBytesCompact(quota.allocatedBytes))
                            if (quota.accountDisplayName.isNotBlank()) {
                                append(" · ")
                                append(quota.accountDisplayName)
                            }
                        },
                        style = MaterialTheme.typography.labelSmall,
                        color = CyberObsidian.TextMuted,
                        modifier = Modifier.padding(top = 4.dp),
                    )
                }

                when (val phase = uiState.syncPhase) {
                    is DropboxSyncPhase.Running -> Text(
                        text = "Синхронизация: ${phase.stepRu} (${phase.completedItems}/${phase.totalItems})",
                        style = MaterialTheme.typography.bodySmall,
                        color = CyberObsidian.Sky,
                        modifier = Modifier.padding(top = 8.dp),
                    )
                    is DropboxSyncPhase.Completed -> Text(
                        text = "Готово: загружено дельт ${phase.uploadedDeltas}, скачано ${phase.downloadedItems}",
                        style = MaterialTheme.typography.bodySmall,
                        color = CyberObsidian.Emerald,
                        modifier = Modifier.padding(top = 8.dp),
                    )
                    is DropboxSyncPhase.Error -> Text(
                        text = phase.messageRu,
                        style = MaterialTheme.typography.bodySmall,
                        color = CyberObsidian.Danger,
                        modifier = Modifier.padding(top = 8.dp),
                    )
                    DropboxSyncPhase.Idle -> Unit
                }

                Button(
                    onClick = viewModel::triggerDropboxSync,
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(top = 12.dp),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = CyberObsidian.Emerald,
                        contentColor = CyberObsidian.EmeraldOn,
                    ),
                ) {
                    Icon(
                        imageVector = androidx.compose.material.icons.Icons.Filled.Sync,
                        contentDescription = null,
                        modifier = Modifier.size(18.dp),
                    )
                    Text("Синхронизировать сейчас", modifier = Modifier.padding(start = 8.dp))
                }
                OutlinedButton(
                    onClick = viewModel::disconnectDropbox,
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(top = 8.dp),
                ) {
                    Text("Отключить и стереть токены", color = CyberObsidian.Danger)
                }
            } else {
                var appKey by remember { mutableStateOf("") }
                Text(
                    text = "OAuth 2.0 с PKCE (S256). Токены хранятся только в Android Keystore на этом устройстве; пароль Dropbox MeshVault не видит никогда.",
                    style = MaterialTheme.typography.bodySmall,
                    color = CyberObsidian.TextSecondary,
                    modifier = Modifier.padding(bottom = 10.dp),
                )
                OutlinedTextField(
                    value = appKey,
                    onValueChange = { appKey = it },
                    label = { Text("Dropbox App Key") },
                    placeholder = { Text("например, a1b2c3d4e5f6g7h") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                Button(
                    onClick = { viewModel.buildDropboxAuthorizeUrl(appKey)?.let(onOpenUrl) },
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(top = 10.dp),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = CyberObsidian.Emerald,
                        contentColor = CyberObsidian.EmeraldOn,
                    ),
                ) {
                    Text("Подключить Dropbox")
                }
            }
            SwitchSettingRow(
                title = "Синхронизировать только по Wi-Fi",
                subtitle = "Не тратить мобильный трафик на зашифрованные копии",
                checked = settings.syncWifiOnly,
                onCheckedChange = { v -> viewModel.updateSettings { it.copy(syncWifiOnly = v) } },
            )

            HorizontalDivider(
                modifier = Modifier.padding(top = 12.dp, bottom = 8.dp),
                color = CyberObsidian.Outline,
            )
            Text(
                text = "MeshVault 1.0.0 · Zero-Knowledge · MVCH v2 · XChaCha20-Poly1305 · Argon2id · SQLCipher",
                style = MaterialTheme.typography.labelSmall,
                color = CyberObsidian.TextMuted,
            )
        }
    }
}

@Composable
private fun SwitchSettingRow(
    title: String,
    subtitle: String? = null,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 6.dp),
        horizontalArrangement = Arrangement.spacedBy(12.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = title,
                style = MaterialTheme.typography.bodyMedium,
                color = CyberObsidian.TextPrimary,
                fontWeight = FontWeight.Medium,
            )
            if (subtitle != null) {
                Text(
                    text = subtitle,
                    style = MaterialTheme.typography.bodySmall,
                    color = CyberObsidian.TextSecondary,
                )
            }
        }
        Switch(checked = checked, onCheckedChange = onCheckedChange)
    }
}

@Composable
private fun ChipSettingRow(
    title: String,
    options: List<String>,
    selected: String,
    onSelect: (String) -> Unit,
) {
    Column(modifier = Modifier.padding(vertical = 6.dp)) {
        Text(
            text = title,
            style = MaterialTheme.typography.bodyMedium,
            color = CyberObsidian.TextPrimary,
            fontWeight = FontWeight.Medium,
        )
        Row(
            modifier = Modifier
                .horizontalScroll(rememberScrollState())
                .padding(top = 6.dp),
            horizontalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            options.forEach { option ->
                FilterChip(
                    selected = option == selected,
                    onClick = { onSelect(option) },
                    label = { Text(option) },
                )
            }
        }
    }
}

private fun formatMb(mb: Int): String =
    if (mb >= 1024) String.format(java.util.Locale.US, "%.0f ГБ", mb / 1024.0) else "$mb МБ"
