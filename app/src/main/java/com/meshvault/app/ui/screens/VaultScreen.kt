package com.meshvault.app.ui.screens

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.widget.Toast
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.AutoAwesome
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.CreditCard
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.Note
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Star
import androidx.compose.material.icons.filled.StarBorder
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.meshvault.app.crypto.PasswordGenerator
import com.meshvault.app.crypto.PasswordOptions
import com.meshvault.app.crypto.TotpGenerator
import com.meshvault.app.data.VaultItem
import com.meshvault.app.data.VaultItemType
import com.meshvault.app.data.VaultRepository
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

private enum class VaultFilter(val label: String) {
    ALL("Все"),
    LOGINS("Логины"),
    CARDS("Карты"),
    NOTES("Заметки"),
    FAVORITES("Избранное")
}

@Composable
fun VaultScreen(
    repository: VaultRepository
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val db by repository.database.collectAsState()

    var query by remember { mutableStateOf("") }
    var filter by remember { mutableStateOf(VaultFilter.ALL) }
    var editingItem by remember { mutableStateOf<VaultItem?>(null) }
    var isCreatingNew by remember { mutableStateOf(false) }

    // Обновление TOTP-таймера каждую секунду
    var tick by remember { mutableIntStateOf(0) }
    LaunchedEffect(Unit) {
        while (true) {
            delay(1000)
            tick++
        }
    }

    val filteredItems = remember(db.items, query, filter) {
        db.items.filter { item ->
            val matchesFilter = when (filter) {
                VaultFilter.ALL -> true
                VaultFilter.LOGINS -> item.type == VaultItemType.LOGIN
                VaultFilter.CARDS -> item.type == VaultItemType.CARD
                VaultFilter.NOTES -> item.type == VaultItemType.NOTE
                VaultFilter.FAVORITES -> item.isFavorite
            }
            val q = query.trim().lowercase()
            val matchesQuery = q.isEmpty() ||
                item.title.lowercase().contains(q) ||
                item.username.lowercase().contains(q) ||
                item.uri.lowercase().contains(q) ||
                item.notes.lowercase().contains(q)
            matchesFilter && matchesQuery
        }
    }

    fun copyToClipboard(label: String, value: String) {
        if (value.isEmpty()) return
        val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        cm.setPrimaryClip(ClipData.newPlainText(label, value))
        Toast.makeText(context, "$label скопирован", Toast.LENGTH_SHORT).show()
    }

    Scaffold(
        floatingActionButton = {
            FloatingActionButton(
                onClick = {
                    isCreatingNew = true
                    editingItem = VaultItem(title = "")
                }
            ) {
                Icon(Icons.Default.Add, contentDescription = "Добавить запись")
            }
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
        ) {
            OutlinedTextField(
                value = query,
                onValueChange = { query = it },
                placeholder = { Text("Поиск по хранилищу...") },
                leadingIcon = { Icon(Icons.Default.Search, contentDescription = null) },
                singleLine = true,
                shape = RoundedCornerShape(14.dp),
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp, vertical = 10.dp)
            )

            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .horizontalScroll(rememberScrollState())
                    .padding(horizontal = 16.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                VaultFilter.entries.forEach { f ->
                    FilterChip(
                        selected = filter == f,
                        onClick = { filter = f },
                        label = { Text(f.label) }
                    )
                }
            }

            Spacer(modifier = Modifier.height(6.dp))

            if (filteredItems.isEmpty()) {
                Box(
                    modifier = Modifier.fillMaxSize(),
                    contentAlignment = Alignment.Center
                ) {
                    Text(
                        text = if (db.items.isEmpty()) {
                            "Хранилище пусто. Нажмите + чтобы добавить пароль, карту или заметку."
                        } else {
                            "Ничего не найдено"
                        },
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(32.dp)
                    )
                }
            } else {
                LazyColumn(
                    contentPadding = PaddingValues(horizontal = 16.dp, vertical = 8.dp),
                    verticalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    items(filteredItems, key = { it.id }) { item ->
                        VaultItemCard(
                            item = item,
                            tick = tick,
                            onClick = {
                                isCreatingNew = false
                                editingItem = item
                            },
                            onCopyPrimary = {
                                when (item.type) {
                                    VaultItemType.LOGIN -> copyToClipboard("Пароль", item.password)
                                    VaultItemType.CARD -> copyToClipboard("Номер карты", item.cardNumber)
                                    VaultItemType.NOTE -> copyToClipboard("Заметка", item.notes)
                                }
                            },
                            onCopyTotp = { code ->
                                copyToClipboard("TOTP код", code)
                            }
                        )
                    }
                    item { Spacer(modifier = Modifier.height(72.dp)) }
                }
            }
        }
    }

    if (editingItem != null) {
        VaultItemEditorDialog(
            initial = editingItem!!,
            isNew = isCreatingNew,
            onDismiss = { editingItem = null },
            onSave = { updated ->
                scope.launch {
                    repository.upsertVaultItem(updated)
                    editingItem = null
                }
            },
            onDelete = if (!isCreatingNew) {
                {
                    val idToDelete = editingItem!!.id
                    scope.launch {
                        repository.deleteVaultItem(idToDelete)
                        editingItem = null
                    }
                }
            } else null
        )
    }
}

@Composable
private fun VaultItemCard(
    item: VaultItem,
    tick: Int,
    onClick: () -> Unit,
    onCopyPrimary: () -> Unit,
    onCopyTotp: (String) -> Unit
) {
    val icon = when (item.type) {
        VaultItemType.LOGIN -> Icons.Default.Key
        VaultItemType.CARD -> Icons.Default.CreditCard
        VaultItemType.NOTE -> Icons.Default.Note
    }

    val subtitle = when (item.type) {
        VaultItemType.LOGIN -> item.username.ifEmpty { item.uri }
        VaultItemType.CARD -> if (item.cardNumber.length >= 4) "•••• ${item.cardNumber.takeLast(4)}" else "Банковская карта"
        VaultItemType.NOTE -> item.notes.lines().firstOrNull().orEmpty()
    }

    Card(
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.55f)),
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
    ) {
        Column(modifier = Modifier.padding(14.dp)) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.fillMaxWidth()
            ) {
                Surface(
                    shape = RoundedCornerShape(12.dp),
                    color = MaterialTheme.colorScheme.primaryContainer,
                    modifier = Modifier.size(42.dp)
                ) {
                    Box(contentAlignment = Alignment.Center) {
                        Icon(
                            imageVector = icon,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.onPrimaryContainer
                        )
                    }
                }
                Spacer(modifier = Modifier.width(12.dp))
                Column(modifier = Modifier.weight(1f)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(
                            text = item.title.ifEmpty { "Без названия" },
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.SemiBold,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                            modifier = Modifier.weight(1f, fill = false)
                        )
                        if (item.isFavorite) {
                            Spacer(modifier = Modifier.width(6.dp))
                            Icon(
                                imageVector = Icons.Default.Star,
                                contentDescription = null,
                                tint = MaterialTheme.colorScheme.primary,
                                modifier = Modifier.size(16.dp)
                            )
                        }
                    }
                    if (subtitle.isNotEmpty()) {
                        Text(
                            text = subtitle,
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                    }
                }
                IconButton(onClick = onCopyPrimary) {
                    Icon(Icons.Default.ContentCopy, contentDescription = "Копировать")
                }
            }

            if (item.type == VaultItemType.LOGIN && item.totpSecret.isNotBlank()) {
                val now = System.currentTimeMillis() / 1000L + (tick * 0)
                val code = TotpGenerator.generateCode(item.totpSecret, now)
                val remaining = TotpGenerator.remainingSeconds(now)
                Spacer(modifier = Modifier.height(8.dp))
                Surface(
                    shape = RoundedCornerShape(10.dp),
                    color = MaterialTheme.colorScheme.surface,
                    modifier = Modifier
                        .fillMaxWidth()
                        .clickable { onCopyTotp(code) }
                ) {
                    Row(
                        modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Text(
                            text = "2FA: ${code.chunked(3).joinToString(" ")}",
                            style = MaterialTheme.typography.titleMedium,
                            fontFamily = FontFamily.Monospace,
                            color = MaterialTheme.colorScheme.secondary
                        )
                        Text(
                            text = "${remaining}с",
                            style = MaterialTheme.typography.labelMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun VaultItemEditorDialog(
    initial: VaultItem,
    isNew: Boolean,
    onDismiss: () -> Unit,
    onSave: (VaultItem) -> Unit,
    onDelete: (() -> Unit)?
) {
    var type by remember { mutableStateOf(initial.type) }
    var title by remember { mutableStateOf(initial.title) }
    var username by remember { mutableStateOf(initial.username) }
    var password by remember { mutableStateOf(initial.password) }
    var uri by remember { mutableStateOf(initial.uri) }
    var totpSecret by remember { mutableStateOf(initial.totpSecret) }
    var notes by remember { mutableStateOf(initial.notes) }
    var cardholderName by remember { mutableStateOf(initial.cardholderName) }
    var cardNumber by remember { mutableStateOf(initial.cardNumber) }
    var cardExpiry by remember { mutableStateOf(initial.cardExpiry) }
    var cardCvv by remember { mutableStateOf(initial.cardCvv) }
    var isFavorite by remember { mutableStateOf(initial.isFavorite) }
    var showSecret by remember { mutableStateOf(false) }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween,
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(if (isNew) "Новая запись" else "Редактировать")
                Row {
                    IconButton(onClick = { isFavorite = !isFavorite }) {
                        Icon(
                            if (isFavorite) Icons.Default.Star else Icons.Default.StarBorder,
                            contentDescription = "Избранное",
                            tint = if (isFavorite) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                    if (onDelete != null) {
                        IconButton(onClick = onDelete) {
                            Icon(
                                Icons.Default.Delete,
                                contentDescription = "Удалить",
                                tint = MaterialTheme.colorScheme.error
                            )
                        }
                    }
                }
            }
        },
        text = {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                SingleChoiceSegmentedButtonRow(modifier = Modifier.fillMaxWidth()) {
                    VaultItemType.entries.forEachIndexed { index, itemType ->
                        SegmentedButton(
                            selected = type == itemType,
                            onClick = { type = itemType },
                            shape = SegmentedButtonDefaults.itemShape(
                                index = index,
                                count = VaultItemType.entries.size
                            )
                        ) {
                            Text(
                                when (itemType) {
                                    VaultItemType.LOGIN -> "Логин"
                                    VaultItemType.CARD -> "Карта"
                                    VaultItemType.NOTE -> "Заметка"
                                }
                            )
                        }
                    }
                }

                OutlinedTextField(
                    value = title,
                    onValueChange = { title = it },
                    label = { Text("Название") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )

                when (type) {
                    VaultItemType.LOGIN -> {
                        OutlinedTextField(
                            value = username,
                            onValueChange = { username = it },
                            label = { Text("Логин / Email") },
                            singleLine = true,
                            modifier = Modifier.fillMaxWidth()
                        )
                        OutlinedTextField(
                            value = password,
                            onValueChange = { password = it },
                            label = { Text("Пароль") },
                            singleLine = true,
                            visualTransformation = if (showSecret) VisualTransformation.None else PasswordVisualTransformation(),
                            trailingIcon = {
                                Row {
                                    IconButton(onClick = {
                                        password = PasswordGenerator.generatePassword(PasswordOptions(length = 18))
                                    }) {
                                        Icon(Icons.Default.AutoAwesome, contentDescription = "Сгенерировать")
                                    }
                                    IconButton(onClick = { showSecret = !showSecret }) {
                                        Icon(
                                            if (showSecret) Icons.Default.VisibilityOff else Icons.Default.Visibility,
                                            contentDescription = null
                                        )
                                    }
                                }
                            },
                            modifier = Modifier.fillMaxWidth()
                        )
                        OutlinedTextField(
                            value = uri,
                            onValueChange = { uri = it },
                            label = { Text("Сайт (URL)") },
                            singleLine = true,
                            modifier = Modifier.fillMaxWidth()
                        )
                        OutlinedTextField(
                            value = totpSecret,
                            onValueChange = { totpSecret = it },
                            label = { Text("TOTP секрет (Base32)") },
                            singleLine = true,
                            modifier = Modifier.fillMaxWidth()
                        )
                    }
                    VaultItemType.CARD -> {
                        OutlinedTextField(
                            value = cardholderName,
                            onValueChange = { cardholderName = it },
                            label = { Text("Владелец карты") },
                            singleLine = true,
                            modifier = Modifier.fillMaxWidth()
                        )
                        OutlinedTextField(
                            value = cardNumber,
                            onValueChange = { cardNumber = it },
                            label = { Text("Номер карты") },
                            singleLine = true,
                            modifier = Modifier.fillMaxWidth()
                        )
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            OutlinedTextField(
                                value = cardExpiry,
                                onValueChange = { cardExpiry = it },
                                label = { Text("MM/YY") },
                                singleLine = true,
                                modifier = Modifier.weight(1f)
                            )
                            OutlinedTextField(
                                value = cardCvv,
                                onValueChange = { cardCvv = it },
                                label = { Text("CVV") },
                                singleLine = true,
                                visualTransformation = if (showSecret) VisualTransformation.None else PasswordVisualTransformation(),
                                modifier = Modifier.weight(1f)
                            )
                        }
                    }
                    VaultItemType.NOTE -> Unit
                }

                OutlinedTextField(
                    value = notes,
                    onValueChange = { notes = it },
                    label = { Text("Заметки") },
                    minLines = 3,
                    maxLines = 6,
                    modifier = Modifier.fillMaxWidth()
                )
            }
        },
        confirmButton = {
            TextButton(
                onClick = {
                    onSave(
                        initial.copy(
                            type = type,
                            title = title.ifBlank { "Без названия" },
                            username = username,
                            password = password,
                            uri = uri,
                            totpSecret = totpSecret,
                            notes = notes,
                            cardholderName = cardholderName,
                            cardNumber = cardNumber,
                            cardExpiry = cardExpiry,
                            cardCvv = cardCvv,
                            isFavorite = isFavorite
                        )
                    )
                }
            ) {
                Text("Сохранить")
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text("Отмена")
            }
        }
    )
}
