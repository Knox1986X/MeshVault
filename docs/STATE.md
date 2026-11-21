# Текущее состояние проекта MeshVault (STATE)

- Дата контрольной точки: 2026-11-21
- Активный этап: Этап 4 — Полный функционал Android и углублённая безопасность (выполнен, проверен в CI; готов к переходу к Этапу 5)
- Репозиторий GitHub: `https://github.com/Knox1986X/MeshVault`
- Рабочая ветка: `arena/57a12259-meshvault` (фиксирована окружением сессии)
- Pull Request: `https://github.com/Knox1986X/MeshVault/pull/1` (открыт, не слит)
- Состояние Dropbox (`/MeshVault/STATE.md`): не проверено / не синхронизировано — коннектор Dropbox отключён для текущей переписки.

## Статус проверок среды и сборки

- Команды shell (bash): проверено, работает; локально в sandbox отсутствуют `rustc`, `cargo` и Android SDK.
- GitHub (`gh` и `git push`): проверено, авторизован как `Knox1986X`.
- Конвейер GitHub Actions CI (`MeshVault CI`, прогон `44898985353` на коммите `c130bd2`):
  - `Rust Format Check` (`cargo fmt --all -- --check`) — пройдено (`success`).
  - `Rust Clippy and Tests` (`cargo clippy`, `cargo test --workspace`, `cargo build --bin meshvault`, `cargo build -p meshvault-ffi`) — пройдено (`success`).
  - `Android Build and Unit Tests` (`gradle -p apps/android testDebugUnitTest assembleDebug`) — пройдено (`success`):
    * Debug APK скомпилирован и собран с новым сервисом `LockTileService`, `WorkManager` воркером и датчиками;
    * JVM unit-тесты `RussianPluralsTest`, `VaultSessionStateTest` и `SecurityGuardsTest` пройдены успешно.
- Dropbox: отключён в настройках коннекторов текущей сессии.

## Сделано на этапе 4

1. Расширена криптография и хранилище:
   - `meshvault-crypto`: добавлены `VaultHeader::add_decoy_slot` и `unlock_with_decoy_passphrase` с независимым `decoy_mvk`, гарантирующим криптографическую изоляцию Ложного сейфа;
   - `meshvault-storage`: добавлены 30-дневная зашифрованная Корзина (`move_to_trash`, `restore_from_trash`, `shred_media`, `purge_expired_trash`), операции с деревом (`move_media`, `rename_folder`, `update_media_tags_and_note`), офлайн-поиск `search_media`, группировка визуальных дубликатов `find_similar_by_dhash`, шифрованный журнал аудита `catalog/audit.mva` (`derive_audit_log_key`), счётчик перебора `BruteForceState` и диагностика `VaultLayout::doctor_report`.
2. Расширены конвейер и UniFFI:
   - `meshvault-import`: добавлена функция `strip_metadata_for_clean_export` в ОЗУ (удаление APP1..APP15 / COM с EXIF/GPS/XMP из JPEG и перекодирование чистых пикселей);
   - `meshvault-ffi`: экспортированы Decoy Vault, Safe Presentation, Корзина + криптоуничтожение, Чистый экспорт, dHash-поиск, журнал аудита и `doctor_report`.
3. Добавлена углублённая защита в Android (`apps/android`):
   - `SecurityGuards.kt`: `ClipboardGuard` (очистка буфера через 30с + `EXTRA_IS_SENSITIVE`), `FlipToLockDetector` (акселерометр), `AppIconSwitcher` (`AliasNotesLauncher`);
   - `LockTileService.kt`: плитка Quick Settings для экстренной блокировки;
   - `VaultMaintenanceWorker.kt`: периодический `WorkManager` для фонового `Vault Scrub` и очистки 30-дневной Корзины;
   - обновлены `SecurityScreen`, `ViewerScreen` (подтверждение паролем выхода из Safe Presentation, Чистый экспорт, Корзина), `MainActivity` и `SecurityGuardsTest`.

## Следующий шаг

1. Приступить к Этапу 5 — E2EE-синхронизация (`crates/meshvault-sync`) через `/MeshVault/` в Dropbox (OAuth2 PKCE + адаптер App Folder с мок-тестами), прямой LAN Wi-Fi протокол с QR-проверкой, конфликт-менеджер ревизий, выравнивание размеров (`FLAG_SIZE_PADDING`) и резервная копия сейфа.
2. При включении Dropbox синхронизировать `docs/STATE.md` в `/MeshVault/STATE.md`.
