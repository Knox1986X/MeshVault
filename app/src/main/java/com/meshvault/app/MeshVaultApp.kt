package com.meshvault.app

import android.app.Application
import com.meshvault.app.data.VaultRepository

class MeshVaultApp : Application() {
    val repository: VaultRepository by lazy { VaultRepository(this) }
}
