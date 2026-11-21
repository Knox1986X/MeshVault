# Текущее состояние проекта MeshVault (STATE)

- Дата контрольной точки: 2026-11-21
- Активный этап: Этап 3 — Нативное Android-приложение (база и Dark Cockpit UI собраны, проверены в CI; готов к переходу к Этапу 4)
- Репозиторий GitHub: `https://github.com/Knox1986X/MeshVault`
- Рабочая ветка: `arena/57a12259-meshvault` (фиксирована окружением сессии)
- Pull Request: `https://github.com/Knox1986X/MeshVault/pull/1` (открыт, не слит)
- Состояние Dropbox (`/MeshVault/STATE.md`): не проверено / не синхронизировано — коннектор Dropbox отключён для текущей переписки.

## Статус проверок среды и сборки

- Команды shell (bash): проверено, работает; локально в sandbox отсутствуют `rustc`, `cargo` и Android SDK.
- GitHub (`gh` и `git push`): проверено, авторизован как `Knox1986X`.
- Конвейер GitHub Actions CI (`MeshVault CI`, прогон `44896839217` на коммите `e0cb8c3`):
  - `Rust Format Check` (`cargo fmt --all -- --check`) — пройдено (`success`).
  - `Rust Clippy and Tests` (`cargo clippy`, `cargo test --workspace`, `cargo build --bin meshvault`) — пройдено (`success`).
  - `Android Build and Unit Tests` (`gradle -p apps/android testDebugUnitTest assembleDebug`) — пройдено (`success`):
    * Debug APK `io.github.knox1986x.meshvault` скомпилирован и собран полностью;
    * JVM unit-тесты `RussianPluralsTest` и `VaultSessionStateTest` пройдены успешно.
- Dropbox: отключён в настройках коннекторов текущей сессии.

## Сделано на этапе 3

1. Расширены Rust-крейты для полноценной работы Android-клиента:
   - `meshvault-storage`: `VaultMetrics`, `breadcrumbs`, `timeline_media`, `compute_metrics`;
   - `meshvault-import`: потоковый `ImportPipeline::import_bytes_item` для импорта элементов из Android SAF `InputStream` без записи открытых файлов в `tmp`;
   - `meshvault-ffi`: добавлены слоты `HardwareKeystore`, `vault_metrics`, `list_all_media_timeline`, `get_folder_breadcrumbs`, `set_folder_pinned`, `set_folder_blur_shield`, `toggle_favorite` и расширенный тест `ffi_session_tests.rs`.
2. Создан нативный Android-проект `apps/android` (`compileSdk 35`, `minSdk 26`, Kotlin 2.0.21, Jetpack Compose + Material3, Biometric 1.1.0, Media3 1.4.1, WorkManager 2.9.1):
   - `AndroidManifest.xml`: `allowBackup="false"`, приём «Поделиться» (`ACTION_SEND` / `ACTION_SEND_MULTIPLE`), `activity-alias` для маскировки ярлыка, отсутствие глобальных разрешений вроде `READ_MEDIA_IMAGES`;
   - безопасность и медиа: `KeystoreVaultWrapper.kt` (Android Keystore + `BiometricPrompt`), `SafTreeScanner.kt` (обход дерева SAF с защитой от циклов и расчётом веток), `EncryptedMediaDataSource.kt` (потоковое воспроизведение Media3 из ОЗУ без временных файлов), `VaultBackend.kt`, `RussianPlurals.kt`;
   - визуальная система **Dark Cockpit**: `CockpitTheme.kt` (`#0b0b14`, `#12121e`, `#1e1e30`, `#7c3aed`), `CockpitComponents.kt` (`StatusPill`, `MetricCard`, `StorageDonut`, `ImportTelemetryChart`, `FolderTreeCard`);
   - экраны: `UnlockScreen`, `OverviewScreen`, `GalleryScreen`, `FoldersScreen`, `SearchScreen`, `SecurityScreen`, `ViewerScreen`, `ImportPreviewDialog`, `MainActivity` (принудительный `FLAG_SECURE`, автолок в фоне, адаптивная нижняя панель и сайдбар 260dp).

## Следующий шаг

1. Приступить к Этапу 4 — Полный функционал Android (углублённая безопасность, Decoy Vault, 30-дневная Корзина с криптоуничтожением, Blur Shield с повторным подтверждением, чистый экспорт без EXIF/GPS, WorkManager фоновые задачи Scrub/Backup, сборка нативных `.so` через `cargo-ndk` + генерация Kotlin UniFFI биндингов в CI).
2. При включении Dropbox синхронизировать `docs/STATE.md` в `/MeshVault/STATE.md`.
