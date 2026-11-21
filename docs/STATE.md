# Текущее состояние проекта MeshVault (STATE)

- Дата контрольной точки: 2026-11-21
- Активный этап: Этап 6 — Desktop-приложение CachyOS + CLI + PKGBUILD + документация (выполнен, все 4 job в CI зелёные)
- Репозиторий GitHub: `https://github.com/Knox1986X/MeshVault`
- Рабочая ветка: `arena/57a12259-meshvault` (фиксирована окружением сессии)
- Pull Request: `https://github.com/Knox1986X/MeshVault/pull/1` (открыт, не слит)
- Состояние Dropbox (`/MeshVault/STATE.md`): не синхронизировано — коннектор Dropbox отключён для текущей переписки.

## Статус проверок среды и сборки

- Команды shell (bash): проверено, работает; локально в sandbox присутствует `node` (`node --test`) и `bash`, отсутствуют `rustc`, `cargo` и Android SDK.
- GitHub (`gh` и `git push`): проверено, авторизован как `Knox1986X`.
- Конвейер GitHub Actions CI (`MeshVault CI`, прогон `44902138152` на коммите `8c09b1a`):
  - `Rust Format Check` (`cargo fmt --all -- --check`) — пройдено (`success`, `5s`).
  - `Rust Clippy and Tests` (`cargo clippy`, `cargo test --workspace`, `cargo build --bin meshvault`, `cargo build -p meshvault-ffi`) — пройдено (`success`, `2m57s`).
  - `Android Build and Unit Tests` (`gradle -p apps/android testDebugUnitTest assembleDebug`) — пройдено (`success`, `2m55s`).
  - `CachyOS Desktop Core, Hotkey Tests & PKGBUILD` (`cargo fmt`, `cargo clippy`, `cargo test` для `apps/desktop/src-tauri`, `node --test apps/desktop/tests/desktop_cockpit.test.mjs`, `bash -n packaging/PKGBUILD`) — пройдено (`success`, `40s`).
- Dropbox: отключён в настройках коннекторов текущей сессии.

## Сделано на этапе 6 (и завершение этапов 1–6)

1. Защита памяти Linux (`crates/meshvault-crypto/src/mem_guard.rs`):
   - `disable_core_dumps()` (`prctl(PR_SET_DUMPABLE, 0)`), `lock_slice_in_ram` / `unlock_slice_in_ram` (`mlock` / `munlock`) и `LockedSecretBox<N>` с принудительным `zeroize` + `munlock` на `Drop`;
   - проверено тестом `linux_mem_guard_locks_secret_and_disables_core_dumps`.
2. Полноценный CLI (`crates/meshvault-cli`):
   - 13 подкоманд: `version`, `info`, `init`, `status`, `doctor`, `import`, `tree`, `ls`, `search`, `scrub`, `export` (включая `--clean`), `backup`, `sync-local`;
   - при `init` автоматически записываются `.nomedia` и `.noindex`;
   - сквозной E2E-тест бинарника `cli_full_lifecycle_init_import_search_scrub_export_backup_and_sync`.
3. Десктопный клиент CachyOS (`apps/desktop`):
   - `src-tauri`: `DesktopVaultBridge` с `LockedSecretBox`, потоковым протоколом `meshvault://media/<uuid>` (с поддержкой HTTP `Range` без `/tmp`), Drag-and-Drop импортом (`import_dropped_paths`), `SecretServiceBridge` (`secret-tool` для KWallet / GNOME Keyring) и `tauri.conf.json` (Tauri v2);
   - Svelte + Dark Cockpit UI (`#0b0b14`, сайдбар `260px`, статус-бар `32px`), горячие клавиши (`1–6`, `hjkl`, `Ctrl+F`, `Ctrl+L` паника, `S` — Side-by-Side сравнение с синхронным зумом), шторка скрытия окна при потере фокуса и RU плюрализация;
   - проверено Rust-тестом `desktop_bridge_unlocks_imports_streams_range_in_ram_and_locks` и JS-тестами `apps/desktop/tests/desktop_cockpit.test.mjs` (4/4).
4. Пакет для CachyOS / Arch Linux (`packaging/`):
   - добавлены `packaging/PKGBUILD` и `packaging/meshvault.desktop`, провалидированы в CI.

## Следующий шаг

1. При включении коннектора Dropbox синхронизировать `docs/STATE.md` в `/MeshVault/STATE.md`.
2. Проверить PR #1 и при необходимости выполнить слияние в `main`.
