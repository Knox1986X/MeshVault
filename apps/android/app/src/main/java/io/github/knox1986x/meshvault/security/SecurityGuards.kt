package io.github.knox1986x.meshvault.security

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.ComponentName
import android.content.Context
import android.content.pm.PackageManager
import android.hardware.Sensor
import android.hardware.SensorEvent
import android.hardware.SensorEventListener
import android.hardware.SensorManager
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.PersistableBundle
import io.github.knox1986x.meshvault.MainActivity

/**
 * Copies sensitive strings with EXTRA_IS_SENSITIVE (API 33+) and clears the clipboard after 30 seconds.
 */
object ClipboardGuard {
    private val handler = Handler(Looper.getMainLooper())
    private var pendingClear: Runnable? = null

    fun copySensitiveAndScheduleClear(
        context: Context,
        label: String,
        value: String,
        clearDelayMs: Long = 30_000L,
    ) {
        val manager = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager ?: return
        val clip = ClipData.newPlainText(label, value)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            clip.description.extras = PersistableBundle().apply {
                putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true)
            }
        }
        manager.setPrimaryClip(clip)

        pendingClear?.let { handler.removeCallbacks(it) }
        val clearTask = Runnable {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                manager.clearPrimaryClip()
            } else {
                manager.setPrimaryClip(ClipData.newPlainText("", ""))
            }
        }
        pendingClear = clearTask
        handler.postDelayed(clearTask, clearDelayMs)
    }
}

/**
 * Flip-to-Lock emergency guard using the accelerometer/gravity sensor (face-down Z < -8.5 m/s^2).
 */
class FlipToLockDetector(
    context: Context,
    private val onFlipDownDetected: () -> Unit,
) : SensorEventListener {

    private val sensorManager = context.getSystemService(Context.SENSOR_SERVICE) as? SensorManager
    private val accelerometer = sensorManager?.getDefaultSensor(Sensor.TYPE_ACCELEROMETER)
    private var armed = true

    fun start() {
        val sensor = accelerometer ?: return
        sensorManager?.registerListener(this, sensor, SensorManager.SENSOR_DELAY_NORMAL)
    }

    fun stop() {
        sensorManager?.unregisterListener(this)
    }

    override fun onSensorChanged(event: SensorEvent) {
        val z = event.values.getOrNull(2) ?: return
        if (armed && z < -8.5f) {
            armed = false
            onFlipDownDetected()
        } else if (z > 2.0f) {
            armed = true
        }
    }

    override fun onAccuracyChanged(sensor: Sensor?, accuracy: Int) = Unit
}

/**
 * Switches launcher icon and title between MeshVault and the disguised Notes launcher alias.
 */
object AppIconSwitcher {
    fun setDisguisedNotesMode(context: Context, disguised: Boolean) {
        val pm = context.packageManager
        val mainComponent = ComponentName(context, MainActivity::class.java)
        val notesAlias = ComponentName(
            context.packageName,
            "${context.packageName}.AliasNotesLauncher",
        )

        val mainState = if (disguised) {
            PackageManager.COMPONENT_ENABLED_STATE_DISABLED
        } else {
            PackageManager.COMPONENT_ENABLED_STATE_ENABLED
        }
        val notesState = if (disguised) {
            PackageManager.COMPONENT_ENABLED_STATE_ENABLED
        } else {
            PackageManager.COMPONENT_ENABLED_STATE_DISABLED
        }

        pm.setComponentEnabledSetting(notesAlias, notesState, PackageManager.DONT_KILL_APP)
        pm.setComponentEnabledSetting(mainComponent, mainState, PackageManager.DONT_KILL_APP)
    }
}
