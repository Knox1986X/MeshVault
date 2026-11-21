# Текущее состояние проекта MeshVault (STATE)

- Дата контрольной точки: 2026-11-21
- Активный этап: Этап 2 — Конвейер рекурсивного импорта и мост UniFFI (выполнен, готов к переходу к Этапу 3)
- Репозиторий GitHub: `https://github.com/Knox1986X/MeshVault`
- Рабочая ветка: `arena/57a12259-meshvault` (фиксирована окружением сессии)
- Pull Request: `https://github.com/Knox1986X/MeshVault/pull/1` (открыт, не слит)
- Состояние Dropbox (`/MeshVault/STATE.md`): не проверено / не синхронизировано — коннектор Dropbox отключён для текущей переписки.

## Статус проверок среды и сборки

- Команды shell (bash): проверено, работает; локально в sandbox отсутствуют `rustc` и `cargo`.
- GitHub (`gh` и `git push`): проверено, авторизован как `Knox1986X`.
- Конвейер GitHub Actions CI (`MeshVault CI`, прогон `44894742332` на коммите `435a59b`):
  - `cargo fmt --all -- --check` — пройдено (`success`).
  - `cargo clippy --workspace --all-targets -- -D warnings` — пройдено (`success`).
  - `cargo test --workspace --verbose` — пройдено (`success`):
    * 8 интеграционных тестов `meshvault-crypto` (`crypto_security_tests.rs`);
    * 2 модульных теста `meshvault-storage` (скрытие имён папок в каталоге, паки превью `.mvt` в ОЗУ);
    * 3 интеграционных теста `meshvault-import` (`import_stress_tests.rs`, включая стресс-тест на 5 000 объектов с имитацией падения на 2 345-м объекте, докачкой WAL, полным `scrub_vault`, карантином 0-байтных файлов, дедупликацией BLAKE3, Incremental Folder Merge, генерацией превью `.mvt` и парсингом JPEG EXIF);
    * интеграционный тест UniFFI-моста `meshvault-ffi` (`ffi_session_tests.rs`).
  - `cargo build --bin meshvault` — пройдено (`success`).
- Dropbox: отключён в настройках коннекторов текущей сессии.

## Сделано на этапе 2

1. Расширен `crates/meshvault-storage`:
   - добавлены атомарные `save_catalog` / `load_catalog`, `ensure_folder_path` (сохранение вложенного дерева подпапок любой глубины и Incremental Folder Merge), `dedup_index` по ключуемому BLAKE3;
   - реализовано шифрованное хранилище миниатюр в 4 МиБ паках `thumbs/pack_<uuid>.mvt` (`append_thumbnail` / `read_thumbnail`) с отдельным `FEK` на каждый пак и нулевым открытым текстом на диске;
   - реализован `scrub_vault` для полной проверки всех чанков и тегов Poly1305.
2. Реализован `crates/meshvault-import`:
   - `scanner.rs`: рекурсивное сканирование дерева с защитой от символьных циклов и превышения глубины, подсчёт по категориям и чекбокс-веткам;
   - `exif.rs`: pure-Rust парсер JPEG APP1 EXIF (`Make`, `Model`, `DateTimeOriginal`), 64-битный перцептивный `dHash`, генерация 32x32 микро-эскиза и 256x256 тайла в ОЗУ через `image`;
   - `wal.rs`: шифрованный `XChaCha20-Poly1305` журнал докачки `wal/import.wal` без открытых имён файлов и путей на диске;
   - `pipeline.rs`: транзакционный `ImportPipeline` с переходами `PreviewReady -> ImportingChunks -> VerifyingTags -> CatalogCommitted -> Completed`, докачкой `resume_from_wal`, карантином битых/пустых файлов, 3 политиками дедупликации BLAKE3 и генератором синтетического дерева `generate_synthetic_tree`.
3. Реализован мост UniFFI `crates/meshvault-ffi`:
   - `MeshVaultSession` (`create_new`, `unlock_with_passphrase`, `unlock_with_recovery_kit`, `lock` с немедленным `zeroize`, `add_recovery_kit_slot`, `rotate_passphrase`, `create_folder`, `list_folder_contents`, `import_directory`, `read_media_chunk` для Media3, `read_media_all_bytes`, `read_thumbnail_bytes`, `scrub_vault`);
   - сборка `cdylib` + `lib` на `uniffi 0.29.5`.

## Следующий шаг

1. Приступить к Этапу 3 — Нативное Android-приложение (`apps/android` на Kotlin + Jetpack Compose + Material3 Dark Cockpit + Android Keystore `BiometricPrompt` + `FLAG_SECURE` + SAF `DocumentsContract` мастер импорта дерева папок + экраны «Обзор», «Галерея», «Папки» и просмотрщик фото с подключением `meshvault-ffi`).
2. При включении Dropbox синхронизировать `docs/STATE.md` в `/MeshVault/STATE.md`.
