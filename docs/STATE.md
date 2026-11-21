# Текущее состояние проекта MeshVault (STATE)

- Дата контрольной точки: 2026-11-21
- Активный этап: Этап 5 — E2EE-синхронизация (выполнен, проверен в CI; готов к переходу к Этапу 6)
- Репозиторий GitHub: `https://github.com/Knox1986X/MeshVault`
- Рабочая ветка: `arena/57a12259-meshvault` (фиксирована окружением сессии)
- Pull Request: `https://github.com/Knox1986X/MeshVault/pull/1` (открыт, не слит)
- Состояние Dropbox (`/MeshVault/STATE.md`): не проверено / не синхронизировано — коннектор Dropbox отключён для текущей переписки.

## Статус проверок среды и сборки

- Команды shell (bash): проверено, работает; локально в sandbox отсутствуют `rustc`, `cargo` и Android SDK.
- GitHub (`gh` и `git push`): проверено, авторизован как `Knox1986X`.
- Конвейер GitHub Actions CI (`MeshVault CI`, прогон `44900217423` на коммите `912a05f`):
  - `Rust Format Check` (`cargo fmt --all -- --check`) — пройдено (`success`, `9s`).
  - `Rust Clippy and Tests` (`cargo clippy`, `cargo test --workspace`, `cargo build --bin meshvault`, `cargo build -p meshvault-ffi`) — пройдено (`success`, `1m56s`).
  - `Android Build and Unit Tests` (`gradle -p apps/android testDebugUnitTest assembleDebug`) — пройдено (`success`, `3m03s`).
- Dropbox: отключён в настройках коннекторов текущей сессии.

## Сделано на этапе 5

1. Реализован движок E2EE-синхронизации `crates/meshvault-sync`:
   - `transport.rs`: абстракция `RemoteSyncTransport` с жёсткой проверкой префикса `/MeshVault/` (`validate_app_folder_path`), генератор OAuth2 PKCE `S256` (`PkceAuthFlow`), потокобезопасный `InMemoryMockRemote` (с докачкой `upload_chunked_resume`) и `LocalDirectoryRemote`;
   - `engine.rs`: `SyncEngine` с полным жизненным циклом эпох, проверкой `SyncPolicy` / `DeviceNetworkState` (`PausedMetered`), режимами `SyncDownloadMode::FullMirror` и `MetadataAndThumbsOnly` + `fetch_blob_on_demand`, аутентифицированным выравниванием размеров `MVPD` (`encode_padded_cloud_envelope` для `FLAG_SIZE_PADDING`) и неразрушающим слиянием каталогов `merge_catalogs_lww` (`ConflictResolved`);
   - `lan.rs`: `LanPairingSession` для прямой Wi-Fi / LAN синхронизации Android ↔ CachyOS с 6-значным SAS/QR-кодом верификации, `XChaCha20-Poly1305` и защитой от replay-атак по `seq_no`;
   - `backup.rs`: `export_verified_backup` на USB OTG / диск Btrfs/LUKS с немедленным запуском `scrub_vault` по копии;
   - `tests/sync_e2ee_tests.rs`: сквозные тесты двусторонней E2EE-синхронизации с проверкой отсутствия открытого текста на сервере, конфликта двух устройств, Selective Sync, `PausedMetered`, LAN QR-спаривания и `export_verified_backup`.

## Следующий шаг

1. Перейти к Этапу 6 — полноценный CLI `meshvault` (`init`, `unlock`, `lock`, `status`, `doctor`, `import`, `tree`, `ls`, `scrub`, `sync`, `export`), Desktop-приложение CachyOS (Tauri v2 + Svelte + TypeScript в `apps/desktop`, тёмная тема Dark Cockpit, горячие клавиши, защита памяти `mlock`/`prctl`, интеграция с Secret Service), `packaging/PKGBUILD` для Arch/CachyOS и расширение CI.
2. При включении Dropbox синхронизировать `docs/STATE.md` в `/MeshVault/STATE.md`.
