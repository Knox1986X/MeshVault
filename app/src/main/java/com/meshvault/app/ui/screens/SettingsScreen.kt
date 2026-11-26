package com.meshvault.app.ui.screens

import android.widget.Toast
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
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import com.meshvault.app.crypto.CryptoManager
import com.meshvault.app.data.VaultRepository

@Composable
fun SettingsScreen(
    repository: VaultRepository,
    onLockNow: () -> Unit
) {
    val context = LocalContext.current
    val db by repository.database.collectAsState()

    var biometricEnabled by remember { mutableStateOf(CryptoManager.isBiometricEnabled(context)) }
    var autoLockSec by remember { mutableIntStateOf(CryptoManager.getAutoLockSeconds(context)) }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        Card(
            shape = RoundedCornerShape(16.dp),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)
        ) {
            Column(
                modifier = Modifier.padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(6.dp)
            ) {
                Text("Статистика хранилища", style = MaterialTheme.typography.titleMedium)
                Text("Записей (пароли, карты, заметки): ${db.items.size}")
                Text("Зашифрованных медиафайлов: ${db.mediaItems.size}")
                Text(
                    "Шифрование: AES-256-GCM • PBKDF2 (600 000 итераций)",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }

        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text("Вход по биометрии", style = MaterialTheme.typography.titleMedium)
                Text(
                    "Отпечаток пальца или Face ID",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            Switch(
                checked = biometricEnabled,
                onCheckedChange = { enabled ->
                    biometricEnabled = enabled
                    repository.enableBiometrics(enabled)
                }
            )
        }

        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("Автоблокировка в фоне", style = MaterialTheme.typography.titleMedium)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                listOf(0 to "Сразу", 60 to "1 мин", 300 to "5 мин", 900 to "15 мин").forEach { (sec, label) ->
                    FilterChip(
                        selected = autoLockSec == sec,
                        onClick = {
                            autoLockSec = sec
                            CryptoManager.setAutoLockSeconds(context, sec)
                        },
                        label = { Text(label) }
                    )
                }
            }
        }

        OutlinedButton(
            onClick = {
                repository.clearPreviewCache()
                Toast.makeText(context, "Временный кэш очищен", Toast.LENGTH_SHORT).show()
            },
            shape = RoundedCornerShape(14.dp),
            modifier = Modifier.fillMaxWidth()
        ) {
            Text("Очистить временный кэш просмотрщика")
        }

        Spacer(modifier = Modifier.height(8.dp))

        Button(
            onClick = onLockNow,
            colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.error),
            shape = RoundedCornerShape(14.dp),
            modifier = Modifier
                .fillMaxWidth()
                .height(50.dp)
        ) {
            Icon(Icons.Default.Lock, contentDescription = null)
            Text("  Заблокировать хранилище")
        }
    }
}
