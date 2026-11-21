# MeshVault CachyOS Desktop App (Tauri v2 + Svelte + Dark Cockpit)

Нативное десктопное приложение для CachyOS Linux, разделяющее общее криптографическое ядро Rust (`crates/meshvault-crypto`, `crates/meshvault-storage`, `crates/meshvault-import`, `crates/meshvault-sync`).

## Реализованные возможности
- Потоковый протокол `meshvault://media/<uuid>` (`DesktopVaultBridge::stream_media`) с поддержкой `Range` для 4K-видео без записи открытых файлов в `/tmp`.
- Защита ОЗУ на Linux (`prctl(PR_SET_DUMPABLE, 0)`, `mlock`, `LockedSecretBox` + `zeroize`) и маркеры `.nomedia` / `.noindex` против индексации Baloo / Tracker.
- Интеграция с Linux Secret Service (`SecretServiceBridge` через `secret-tool` для KWallet / GNOME Keyring).
- Интерфейс Dark Cockpit (`#0b0b14`, левый сайдбар `260px`, нижний статус-бар `32px`):
  - Горячие клавиши: `1–6` (переключение вкладок), `hjkl` / стрелки (навигация), `Ctrl+F` (поиск), `Ctrl+L` (экстренная блокировка), `S` (режим сравнения двух кадров Side-by-Side с синхронным зумом).
  - Шторка приватности (`onWindowBlur` / `onWindowFocus`) при потере фокуса окна.
  - Drag-and-Drop импорт файлов и рекурсивных папок (`import_dropped_paths`).

## Команды проверки и сборки
```bash
cargo test --manifest-path apps/desktop/src-tauri/Cargo.toml
node --test apps/desktop/tests/desktop_cockpit.test.mjs
# Полная GUI-сборка на CachyOS (требует webkit2gtk-4.1, gtk3, libsecret):
cargo build --release --manifest-path apps/desktop/src-tauri/Cargo.toml --features tauri-app
```
