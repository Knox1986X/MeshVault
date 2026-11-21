package io.github.knox1986x.meshvault.security

import android.content.Intent
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService

/**
 * Android Quick Settings tile for one-tap emergency vault locking and RAM zeroization.
 */
class LockTileService : TileService() {

    override fun onStartListening() {
        super.onStartListening()
        qsTile?.apply {
            state = Tile.STATE_ACTIVE
            label = "Заблокировать сейф"
            updateTile()
        }
    }

    override fun onClick() {
        super.onClick()
        sendBroadcast(
            Intent(ACTION_EMERGENCY_LOCK).setPackage(packageName),
        )
        qsTile?.apply {
            state = Tile.STATE_INACTIVE
            updateTile()
        }
    }

    companion object {
        const val ACTION_EMERGENCY_LOCK = "io.github.knox1986x.meshvault.ACTION_EMERGENCY_LOCK"
    }
}
