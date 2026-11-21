# MeshVault Test Suite Overview

Автоматические тесты проекта покрывают все 6 этапов и запускаются в GitHub Actions CI:

1. **Криптография и память (`crates/meshvault-crypto/tests/crypto_security_tests.rs`)**:
   - Argon2id + 24-словный Recovery Kit, XChaCha20-Poly1305 с произвольным доступом к чанкам, защита от подмены и обрезания последнего чанка, изоляция Decoy Vault, Linux `prctl(PR_SET_DUMPABLE, 0)` + `mlock` (`LockedSecretBox`) + `zeroize`.
2. **Хранилище и инварианты каталога (`crates/meshvault-storage`)**:
   - Скрытие имён папок/файлов на диске, паки превью `.mvt`, 30-дневная Корзина, криптоуничтожение, dHash-группировка, аудит `audit.mva`, `doctor_report`, `scrub_vault`.
3. **Рекурсивный импорт и стресс-тест (`crates/meshvault-import/tests/import_stress_tests.rs`)**:
   - Реальный EXIF/dHash/thumbnail-пайплайн + Чистый экспорт, WAL-журнал при падении на `2 345` из `5 000` синтетических объектов и бесшовной докачке без временных открытых файлов.
4. **UniFFI и Android (`crates/meshvault-ffi/tests/`, `apps/android/app/src/test/`)**:
   - Жизненный цикл сессии, Decoy Vault, Safe Presentation, Чистый экспорт, `RussianPluralsTest`, `VaultSessionStateTest`, `SecurityGuardsTest`.
5. **E2EE-синхронизация и бэкап (`crates/meshvault-sync/tests/sync_e2ee_tests.rs`)**:
   - Zero-knowledge `/MeshVault/` (OAuth2 PKCE + мок Dropbox), конфликт-менеджер (`ConflictResolved`), Selective Sync, `PausedMetered`, `MVPD` size padding, LAN QR SAS-спаривание с защитой от replay, верифицированный USB/Btrfs-бэкап.
6. **CLI и CachyOS Desktop (`crates/meshvault-cli/tests/cli_e2e_tests.rs`, `apps/desktop/src-tauri`, `apps/desktop/tests/desktop_cockpit.test.mjs`)**:
   - Полный цикл бинарника `meshvault` (`init -> import -> status -> doctor -> tree -> search -> scrub -> export -> backup -> sync-local`), `meshvault://` Range-стриминг в ОЗУ, горячие клавиши, blur-шторка и `PKGBUILD`.
