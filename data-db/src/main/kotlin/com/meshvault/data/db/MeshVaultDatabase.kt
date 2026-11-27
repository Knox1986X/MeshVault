package com.meshvault.data.db

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase
import com.meshvault.crypto.VaultSessionKeys
import net.zetetic.database.sqlcipher.SupportOpenHelperFactory
import java.util.concurrent.atomic.AtomicBoolean

@Database(
    entities = [
        EncryptedFolderRecord::class,
        EncryptedMediaRecord::class,
        EncryptedSecretRecord::class,
        EncryptedNoteRecord::class,
        EncryptedTombstoneRecord::class,
        PendingSyncOpRecord::class,
    ],
    version = 2,
    exportSchema = true,
)
abstract class MeshVaultDatabase : RoomDatabase() {
    abstract fun vaultDao(): MeshVaultDao

    companion object {
        private val sqlCipherLoaded = AtomicBoolean(false)

        fun ensureSqlCipherLoaded() {
            if (sqlCipherLoaded.compareAndSet(false, true)) {
                System.loadLibrary("sqlcipher")
            }
        }

        /**
         * Открывает зашифрованную SQLCipher базу данных для конкретного контура (основного или ложного дна).
         */
        fun openEncrypted(context: Context, session: VaultSessionKeys): MeshVaultDatabase {
            ensureSqlCipherLoaded()
            val dbFile = context.getDatabasePath(session.contour.dbFileName)
            dbFile.parentFile?.mkdirs()

            val passphraseCopy = session.withDbKey { it.copyOf() }
            val factory = SupportOpenHelperFactory(passphraseCopy)
            return Room.databaseBuilder(
                context.applicationContext,
                MeshVaultDatabase::class.java,
                dbFile.absolutePath,
            )
                .openHelperFactory(factory)
                .fallbackToDestructiveMigration()
                .build()
        }
    }
}
