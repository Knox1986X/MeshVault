package com.meshvault.app.data

import kotlinx.serialization.Serializable
import java.util.UUID

@Serializable
enum class VaultItemType {
    LOGIN,
    NOTE,
    CARD
}

@Serializable
data class VaultItem(
    val id: String = UUID.randomUUID().toString(),
    val type: VaultItemType = VaultItemType.LOGIN,
    val title: String,
    val username: String = "",
    val password: String = "",
    val uri: String = "",
    val totpSecret: String = "",
    val notes: String = "",
    // Поля для банковской карты
    val cardholderName: String = "",
    val cardNumber: String = "",
    val cardExpiry: String = "",
    val cardCvv: String = "",
    val folder: String = "Без папки",
    val isFavorite: Boolean = false,
    val createdAt: Long = System.currentTimeMillis(),
    val updatedAt: Long = System.currentTimeMillis()
)

@Serializable
enum class MediaType {
    IMAGE,
    VIDEO
}

@Serializable
data class GalleryMediaItem(
    val id: String = UUID.randomUUID().toString(),
    val displayName: String,
    val mimeType: String,
    val mediaType: MediaType,
    val album: String = "Основное",
    val sizeBytes: Long = 0L,
    val width: Int = 0,
    val height: Int = 0,
    val durationMs: Long = 0L,
    val isFavorite: Boolean = false,
    val addedAt: Long = System.currentTimeMillis()
)

@Serializable
data class VaultDatabase(
    val version: Int = 1,
    val items: List<VaultItem> = emptyList(),
    val mediaItems: List<GalleryMediaItem> = emptyList()
)
