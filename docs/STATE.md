# Текущее состояние проекта MeshVault (STATE)

- Дата контрольной точки: 2026-11-21
- Активный этап: Этап 1 — Архитектура и криптографическое ядро на Rust
- Репозиторий GitHub: `https://github.com/Knox1986X/MeshVault`
- Рабочая ветка: `arena/57a12259-meshvault` (фиксирована окружением сессии)
- Состояние Dropbox (`/MeshVault/STATE.md`): не синхронизировано — интеграция Dropbox подключена пользователем, но отключена для текущей переписки.

## Статус проверок среды

- Команды shell (bash): работают; локально `rustc` и `cargo` в контейнере отсутствуют.
- GitHub (`gh` и `git push`): проверено, авторизован как `Knox1986X`.
- Компиляция и тесты Rust: запускаются через GitHub Actions CI (`.github/workflows/ci.yml`).
- Dropbox: отключён в настройках коннекторов текущей сессии (требуется включение пользователем).

## Сделано на этапе 1

1. Создан Cargo workspace из 6 крейтов: `meshvault-crypto`, `meshvault-storage`, `meshvault-import`, `meshvault-sync`, `meshvault-ffi`, `meshvault-cli`.
2. Реализовано криптографическое ядро `meshvault-crypto`:
   - потоковое AEAD-шифрование чанков по 1 МиБ (`XChaCha20-Poly1305`) с детерминированным 24-байтным нонсом (`blake3::derive_key`), AAD-привязкой (`file_id`, `chunk_index`, `is_final`, `plaintext_len`) и произвольным доступом O(1) (`ChunkedBlobReader`);
   - KDF `Argon2id` с параметрами в заголовке;
   - двойной бинарный заголовок `VaultHeader` (`vault.header` + `vault.header.bak`) со слотами ключей и мгновенной сменой мастер-пароля без перешифровки медиа;
   - Emergency Recovery Kit (24 слова BIP-39 с 8-битной контрольной суммой SHA-256);
   - обёртка ключей `MasterVaultKey`, `FileEncryptionKey`, `KeyWrappingKey`, `DerivedSubkey` с `Zeroize` / `ZeroizeOnDrop` и `secrecy::SecretBox`.
3. Написаны тесты `crates/meshvault-crypto/tests/crypto_security_tests.rs` (round-trip, O(1) чтение в произвольном порядке, отказ при подмене байта, отказ при перестановке чанков, отказ при обрезке финального чанка или удалении последнего чанка, ротация пароля, Recovery Kit, двойной заголовок, `zeroize`).
4. Реализован каркас `meshvault-storage` с зашифрованным каталогом дерева папок `VaultCatalog` (XChaCha20-Poly1305) и тестом отсутствия открытых имён папок на диске.
5. Оформлены документы `docs/FORMAT.md`, `docs/ROADMAP.md` (пункты 01–80), `docs/DECISIONS.md` и workflow `.github/workflows/ci.yml`.

## Следующий шаг

1. Включить коннектор Dropbox для сохранения зеркала `/MeshVault/STATE.md`.
2. После подтверждения зелёного прогона Stage 1 перейти к Этапу 2: реализовать конвейер рекурсивного импорта в `meshvault-import`, генератор зашифрованных паков превью `.mvt`, парсинг EXIF, журнал докачки WAL, стресс-тест на 5 000 объектов с имитацией сбоя и мост UniFFI (`meshvault-ffi`).
