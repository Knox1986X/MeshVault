package com.meshvault.app

import android.content.Context
import android.hardware.Sensor
import android.hardware.SensorEvent
import android.hardware.SensorEventListener
import android.hardware.SensorManager
import kotlin.math.sqrt

/**
 * Детектор резкой встряски (shake) → Panic Lock.
 * Срабатывает при серии из [REQUIRED_HITS] последовательных измерений выше [THRESHOLD_MS2]
 * в пределах окна [WINDOW_MS]; после срабатывания — пауза [COOLDOWN_MS].
 */
class ShakeDetector(context: Context) {

    private val sensorManager = context.getSystemService(Context.SENSOR_SERVICE) as? SensorManager
    private val accelerometer: Sensor? = sensorManager?.getDefaultSensor(Sensor.TYPE_ACCELEROMETER)

    private var listener: SensorEventListener? = null
    private var hitCount = 0
    private var windowStartMs = 0L
    private var cooldownUntilMs = 0L

    fun isAvailable(): Boolean = accelerometer != null

    fun start(onShakeDetected: () -> Unit) {
        val sm = sensorManager ?: return
        val sensor = accelerometer ?: return
        if (listener != null) return

        windowStartMs = 0L
        hitCount = 0

        listener = object : SensorEventListener {
            override fun onSensorChanged(event: SensorEvent) {
                if (event.values.size < 3) return
                val now = System.currentTimeMillis()
                if (now < cooldownUntilMs) return

                if (now - windowStartMs > WINDOW_MS) {
                    windowStartMs = now
                    hitCount = 0
                }

                val ax = event.values[0].toDouble()
                val ay = event.values[1].toDouble()
                val az = event.values[2].toDouble()
                val magnitude = sqrt(ax * ax + ay * ay + az * az)

                if (magnitude > THRESHOLD_MS2) {
                    hitCount += 1
                    if (hitCount >= REQUIRED_HITS) {
                        hitCount = 0
                        cooldownUntilMs = now + COOLDOWN_MS
                        onShakeDetected()
                    }
                }
            }

            override fun onAccuracyChanged(sensor: Sensor?, accuracy: Int) = Unit
        }
        sm.registerListener(listener, sensor, SensorManager.SENSOR_DELAY_UI)
    }

    fun stop() {
        listener?.let { sensorManager?.unregisterListener(it) }
        listener = null
        hitCount = 0
        windowStartMs = 0L
    }

    private companion object {
        const val THRESHOLD_MS2 = 26.0 // заметно выше типичной тряски при ходьбе (~12 м/с²)
        const val REQUIRED_HITS = 4
        const val WINDOW_MS = 900L
        const val COOLDOWN_MS = 3_000L
    }
}
