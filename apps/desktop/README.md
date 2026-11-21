# MeshVault CachyOS Desktop App (Stage 6)

Нативное десктопное приложение для CachyOS Linux на Tauri v2 + Svelte + TypeScript, разделяющее общее криптографическое ядро Rust (`crates/meshvault-crypto`, `crates/meshvault-storage`, `crates/meshvault-import`, `crates/meshvault-sync`).

- Кастомный потоковый протокол Tauri без записи расшифрованных файлов в `/tmp`
- Интеграция с Secret Service (KWallet / GNOME Keyring)
- Интерфейс Dark Cockpit с фиксированным левым сайдбаром 260px и нижним статус-баром 32px
