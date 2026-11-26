package com.meshvault.app

import android.os.Bundle
import android.view.WindowManager
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.AutoAwesome
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.PhotoLibrary
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.CenterAlignedTopAppBar
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.fragment.app.FragmentActivity
import com.meshvault.app.crypto.CryptoManager
import com.meshvault.app.data.GalleryMediaItem
import com.meshvault.app.ui.screens.GalleryScreen
import com.meshvault.app.ui.screens.GeneratorScreen
import com.meshvault.app.ui.screens.LockScreen
import com.meshvault.app.ui.screens.MediaViewerScreen
import com.meshvault.app.ui.screens.SettingsScreen
import com.meshvault.app.ui.screens.VaultScreen
import com.meshvault.app.ui.theme.MeshVaultTheme

private enum class MainTab(val title: String, val icon: ImageVector) {
    VAULT("Хранилище", Icons.Default.Lock),
    GENERATOR("Генератор", Icons.Default.AutoAwesome),
    GALLERY("Галерея", Icons.Default.PhotoLibrary),
    SETTINGS("Настройки", Icons.Default.Settings)
}

class MainActivity : FragmentActivity() {

    private var backgroundTimestamp: Long = 0L

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE
        )
        enableEdgeToEdge()

        val repository = (application as MeshVaultApp).repository

        setContent {
            MeshVaultTheme {
                val isUnlocked by repository.isUnlocked.collectAsState()
                if (!isUnlocked) {
                    LockScreen(
                        repository = repository,
                        onUnlocked = {}
                    )
                } else {
                    MainScaffold(repository = repository)
                }
            }
        }
    }

    override fun onStop() {
        super.onStop()
        backgroundTimestamp = System.currentTimeMillis()
    }

    override fun onStart() {
        super.onStart()
        val repository = (application as MeshVaultApp).repository
        if (repository.isUnlocked.value && backgroundTimestamp > 0L) {
            val elapsedSec = (System.currentTimeMillis() - backgroundTimestamp) / 1000L
            val timeoutSec = CryptoManager.getAutoLockSeconds(this)
            if (elapsedSec >= timeoutSec) {
                repository.lock()
            }
        }
        backgroundTimestamp = 0L
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun MainScaffold(
    repository: com.meshvault.app.data.VaultRepository
) {
    var currentTab by remember { mutableStateOf(MainTab.VAULT) }
    var viewerItems by remember { mutableStateOf<List<GalleryMediaItem>?>(null) }
    var viewerIndex by remember { mutableIntStateOf(0) }

    if (viewerItems != null) {
        MediaViewerScreen(
            items = viewerItems!!,
            initialIndex = viewerIndex,
            repository = repository,
            onClose = { viewerItems = null }
        )
        return
    }

    Scaffold(
        topBar = {
            CenterAlignedTopAppBar(
                title = { Text(currentTab.title) },
                actions = {
                    IconButton(onClick = { repository.lock() }) {
                        Icon(Icons.Default.Lock, contentDescription = "Заблокировать")
                    }
                }
            )
        },
        bottomBar = {
            NavigationBar {
                MainTab.entries.forEach { tab ->
                    NavigationBarItem(
                        selected = currentTab == tab,
                        onClick = { currentTab = tab },
                        icon = { Icon(tab.icon, contentDescription = tab.title) },
                        label = { Text(tab.title) }
                    )
                }
            }
        }
    ) { padding ->
        Box(modifier = Modifier.padding(padding)) {
            when (currentTab) {
                MainTab.VAULT -> VaultScreen(repository = repository)
                MainTab.GENERATOR -> GeneratorScreen()
                MainTab.GALLERY -> GalleryScreen(
                    repository = repository,
                    onOpenViewer = { items, index ->
                        viewerItems = items
                        viewerIndex = index
                    }
                )
                MainTab.SETTINGS -> SettingsScreen(
                    repository = repository,
                    onLockNow = { repository.lock() }
                )
            }
        }
    }
}
