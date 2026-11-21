# MeshVault

Защищённая, полностью зашифрованная галерея и медиа-сейф (Android первым, затем CachyOS Linux) на едином криптографическом ядре Rust.

## Главный инженерный инвариант: Zero Plaintext on Disk

На флеш-память смартфона, SSD компьютера и в облачное хранилище Dropbox никогда не записываются незашифрованные оригиналы из сейфа, миниатюры, имена файлов, названия папок, теги, заметки или EXIF-данные.

## Архитектура монорепозитория

- `crates/meshvault-crypto` — AEAD-шифрование чанков с произвольным доступом (XChaCha20-Poly1305), Argon2id, иерархия ключей Envelope Encryption, Recovery Kit (24 слова), зануление секретов (`zeroize`).
- `crates/meshvault-storage` — формат контейнера MeshVault Format v1 (`vault.header`, `vault.header.bak`), зашифрованный каталог дерева папок/медиа/тегов, паки превью, корзина и проверка целостности (`scrub`).
- `crates/meshvault-import` — транзакционный конвейер рекурсивного импорта файлов, папок и деревьев подпапок, дедупликация BLAKE3, pHash, EXIF, журнал докачки WAL.
- `crates/meshvault-sync` — zero-knowledge синхронизация через `/MeshVault/` в Dropbox и локальный LAN-обмен Android ↔ CachyOS.
- `crates/meshvault-ffi` — мост UniFFI для нативного Android-клиента.
- `crates/meshvault-cli` — консольный клиент и диагностика `meshvault` для CachyOS.
- `apps/android` — нативное приложение Android (Kotlin, Jetpack Compose, Media3, Android Keystore, SAF).
- `apps/desktop` — нативное приложение CachyOS (Tauri v2, Svelte, TypeScript).

## Документация проекта

- `docs/FORMAT.md` — бинарный формат хранилища и таблицы переходов трёх главных машин состояний.
- `docs/ROADMAP.md` — дорожная карта требований 01–80.
- `docs/DECISIONS.md` — журнал архитектурных решений (ADR).
- `docs/STATE.md` — текущая контрольная точка разработки.
