# MeshVault Android App (Stage 3–5)

Нативное Android-приложение на Kotlin + Jetpack Compose + Media3 + Android Keystore + SAF (`DocumentsContract`).

- `applicationId`: `io.github.knox1986x.meshvault`
- Дизайн-система: Dark Cockpit (`#0b0b14` фон, `#12121e` карточки, `#7c3aed` акцент)
- Связь с Rust-ядром: `crates/meshvault-ffi` (UniFFI)
- Потоковое воспроизведение видео: кастомный `Media3 DataSource`, расшифровывающий чанки по 1 МиБ исключительно в ОЗУ без временных файлов на диске.
