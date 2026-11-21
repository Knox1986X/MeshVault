# Дорожная карта MeshVault (требования 01–80)

Легенда статусов:
- `Запланировано` — требование распределено на будущий этап.
- `В каркасе` — описаны типы, границы или спецификация формата.
- `Проверено тестом` — реализовано и подтверждено автоматическими тестами.

## Раздел A. Импорт фото, папок и глубоких деревьев подпапок

| ID | Требование | Этап | Статус | Способ проверки |
| :--- | :--- | :--- | :--- | :--- |
| 01 | Импорт одиночных и множественных фото/видео через системный Android Photo Picker без лишних глобальных разрешений | Этап 3 | В каркасе | PickMultipleVisualMedia в MainActivity; в AndroidManifest нет READ_MEDIA_IMAGES |
| 02 | Импорт выбранной папки целиком в 1 шаг с созданием одноимённой папки в сейфе | Этап 3 | В каркасе | OpenDocumentTree + SafTreeScanner + importStreamItem |
| 03 | Рекурсивный импорт папки со всеми вложенными подпапками любой глубины с сохранением иерархии | Этап 2 | Проверено тестом | Тест дерева каталога `VaultCatalog::ensure_folder_path` и стресс-тест 5000 объектов |
| 04 | Быстрый обход дерева на Android через прямые запросы ContentResolver и DocumentsContract с защитой от циклов | Этап 3 | В каркасе | `SafTreeScanner.kt` с множеством посещённых `documentId` и depth guard |
| 05 | Экран предпросмотра перед импортом: дерево веток с чекбоксами, подсчёт типов, веса и свободного места | Этап 3 | В каркасе | `ImportPreviewDialog` в `ImportPreviewSheet.kt` + `SafTreePreview` |
| 06 | Умное дозаполнение папок (Incremental Folder Merge) без дублей при повторном импорте | Этап 2 | Проверено тестом | Интеграционный тест повторного импорта папки в `import_stress_tests.rs` |
| 07 | Криптографическая дедупликация по ключуемому BLAKE3-хешу с выбором политики | Этап 2 | Проверено тестом | Тест `SkipDuplicate`, `LinkIntoTargetFolder` и `keyed_dedup_hash` |
| 08 | Транзакционный журнал импорта (Resumable Import WAL) для безопасной докачки после сбоя | Этап 2 | Проверено тестом | Стресс-тест падения процесса на 2345 из 5000 объектов и докачки `ImportPipeline::resume_from_wal` |
| 09 | Безопасное удаление оригиналов строго после верификации чанков и коммита каталога через `MediaStore.createDeleteRequest` | Этап 3 | В каркасе | Инвариант перехода `VerifyingTags -> CatalogCommitted` в `meshvault-import` + UI Android |
| 10 | Связывание составных медиа (Live/Motion Photos, RAW+JPEG+XMP, видео+субтитры) в единую карточку | Этап 4 | Проверено тестом | `VaultCatalog::link_companion_media` (`companion_ids`) + FFI + тест `companion_linking_tree_export_slideshow_and_rollback_work` |
| 11 | Карантин проблемных файлов (битые, 0 байт, облачные ярлыки SAF) с отчётом и повтором | Этап 2 | Проверено тестом | Тест перевода 0-байтных и нечитаемых файлов в `Quarantined` без остановки импорта |
| 12 | Наблюдаемые «Входящие папки» (Inbox Folders) с предложением зашифровать новые файлы в 1 тап | Этап 4 | Проверено тестом | `InboxFolderWatcher::findNewCandidateIds` + тест `thermalBatteryGuardAndInboxWatcherBehaveCorrectly` |
| 13 | Приём файлов и папок через системное меню «Поделиться» на Android и Drag-and-Drop на CachyOS | Этап 6 | Проверено тестом | `ACTION_SEND`/`ACTION_SEND_MULTIPLE` на Android; `DesktopVaultBridge::import_dropped_paths` и `App.svelte` на CachyOS |
| 14 | Импорт из ZIP/TAR-архивов (включая Google Takeout с JSON-метаданными) без распаковки открытых файлов на диск | Этап 4 | Проверено тестом | `import_tar_bytes_in_ram` + `import_zip_store_bytes_in_ram` (Takeout JSON) в `archive_takeout_pdf_scanner_and_redaction_work_in_ram` |

## Раздел B. Безопасность ключей и живучесть хранилища

| ID | Требование | Этап | Статус | Способ проверки |
| :--- | :--- | :--- | :--- | :--- |
| 15 | Поддержка нескольких полностью независимых сейфов на одном устройстве | Этап 3 | В каркасе | Тест изоляции `vault_id` и `MVK` разных контейнеров |
| 16 | Разблокировка по биометрии через BiometricPrompt и Android Keystore с переключением на пароль при сбросе биометрии | Этап 3 | В каркасе | Тест слота `HardwareKeystore` и fallback Android Keystore |
| 17 | Генерация офлайн-ключа восстановления (Emergency Recovery Kit из 24 слов + проверочный экран) | Этап 1 | Проверено тестом | Тест генерации, контрольной суммы SHA-256 и восстановления MVK |
| 18 | Фоновая самопроверка целостности (Vault Scrub) тегов Poly1305 всех чанков и заголовков | Этап 1 | Проверено тестом | Тест `ChunkedBlobReader::verify_all_chunks` и `ScrubReport` |
| 19 | Двойной заголовок хранилища (`vault.header` и `vault.header.bak`) с атомарным обновлением ревизий | Этап 1 | Проверено тестом | Тест `VaultHeader::select_latest_valid` при порче основного файла |
| 20 | Очистка секретов в ОЗУ (`zeroize`), запрет core dump и `mlock` для ключей на CachyOS | Этап 6 | Проверено тестом | Тест `Zeroize` + `linux_mem_guard_locks_secret_and_disables_core_dumps` (`prctl` + `mlock` + `LockedSecretBox`) |
| 21 | Опциональный режим скрытия размеров файлов (выравнивание паков и паддинг чанков) перед облаком | Этап 5 | Проверено тестом | Аутентифицированный `MVPD` паддинг до бакета в `encode_padded_cloud_envelope` и тест |
| 22 | Поддержка аппаратных ключей FIDO2 / YubiKey (NFC/USB на Android, USB HID на CachyOS) | Этап 4 | В каркасе | Слот `SlotType::Fido2Hmac` и тест обёртки |
| 23 | Зашифрованная Корзина с настраиваемым сроком хранения (7, 30, 90 дней) и мгновенным криптоуничтожением | Этап 4 | Проверено тестом | Тесты `trash_shred_dhash_search_audit_and_doctor_work` и `ffi_stage4_decoy_trash_clean_export_and_doctor` |
| 24 | Открытая документация `docs/FORMAT.md` и автономная CLI-утилита аварийной расшифровки без GUI | Этап 6 | Проверено тестом | `docs/FORMAT.md` и полнофункциональный `meshvault-cli` (`export`, `scrub`, `doctor`) с E2E-тестом |

## Раздел C. Защита экрана, анти-принуждение и приватность в жизни

| ID | Требование | Этап | Статус | Способ проверки |
| :--- | :--- | :--- | :--- | :--- |
| 25 | Принудительный `FLAG_SECURE` на Android и скрытие окна при потере фокуса на CachyOS | Этап 6 | Проверено тестом | `FLAG_SECURE` в `MainActivity`; шторка `onWindowBlur` в `desktop_cockpit.test.mjs` |
| 26 | Режим «Безопасный показ» (Safe Presentation Lock) с блокировкой выхода в папки до биометрии/PIN | Этап 4 | Проверено тестом | Тесты `ffi_stage4_decoy_trash_clean_export_and_doctor`, `SecurityGuardsTest` и диалог разблокировки `ViewerScreen` |
| 27 | Опциональный Ложный сейф (Decoy Vault) по отдельному PIN с честным пояснением модели угроз | Этап 4 | Проверено тестом | Тесты `decoy_slot_isolates_decoy_mvk_from_real_mvk`, FFI и `SecurityGuardsTest` |
| 28 | Экстренная блокировка: Flip-to-Lock, плитка QS Android, кнопка в шапке и хоткей `Ctrl+L` на CachyOS | Этап 6 | Проверено тестом | `FlipToLockDetector` + `LockTileService` + хоткей `Ctrl+L` в `desktop_cockpit.test.mjs` |
| 29 | Гибкий автолок: при гашении экрана, по таймеру 0–30с, по неактивности или при подключении USB | Этап 3 | В каркасе | `Lifecycle.Event.ON_STOP` автолок в `MainActivity` + `FlipToLockDetector` |
| 30 | Слой «Скрытые папки внутри сейфа» (Blur Shield) с размытием обложек до доп. подтверждения | Этап 3 | В каркасе | `set_folder_blur_shield` в FFI и отображение маскировки в `FolderTreeCard` |
| 31 | Приватный режим ввода для клавиатуры (запрет обучения и автоподсказок на именах, тегах и заметках) | Этап 3 | В каркасе | `autoCorrectEnabled = false` и пароль-клавиатура в `UnlockScreen` |
| 32 | Опциональная смена иконки и подписи приложения на Android через `activity-alias` | Этап 4 | В каркасе | `AppIconSwitcher.setDisguisedNotesMode` + `AliasNotesLauncher` в `AndroidManifest.xml` |
| 33 | Безопасная отправка наружу («Чистый экспорт») с удалением GPS, серийных номеров и скрытого EXIF/XMP на лету | Этап 4 | Проверено тестом | `strip_metadata_for_clean_export` в ОЗУ + тесты FFI и `SecurityGuardsTest` |
| 34 | Автоочистка системного буфера обмена через 30 секунд после копирования из сейфа | Этап 4 | В каркасе | `ClipboardGuard.copySensitiveAndScheduleClear` (30с таймер + `EXTRA_IS_SENSITIVE`) |
| 35 | Локальный зашифрованный журнал событий безопасности с нарастающей задержкой против перебора | Этап 4 | Проверено тестом | Шифрованный `audit.mva` (`derive_audit_log_key`) и тест `compute_backoff_seconds` |

## Раздел D. Дерево папок, каталогизация и умный офлайн-поиск

| ID | Требование | Этап | Статус | Способ проверки |
| :--- | :--- | :--- | :--- | :--- |
| 36 | Проводник дерева папок и подпапок с хлебными крошками, счётчиками и сортировкой | Этап 3 | Проверено тестом | Тест `get_folder_breadcrumbs` в FFI + `FoldersScreen.kt` |
| 37 | Единая хронологическая лента «Галерея» по дням/месяцам/годам, зум 2–7 колонок и скролл-ползунок | Этап 3 | Проверено тестом | Тест `list_all_media_timeline` в FFI + `GalleryScreen.kt` (сетка 2–7) |
| 38 | Двухступенчатые превью: мгновенный микро-эскиз из каталога + чёткий тайл из зашифрованного пака | Этап 3 | Проверено тестом | Генерация `micro_thumb` + `.mvt` пака 4 МиБ в ядре; Compose UI-интеграция на этапе 3 |
| 39 | Виртуальные альбомы и избранное без дублирования зашифрованных чанков | Этап 3 | В каркасе | Поле `favorite` и виртуальные коллекции в каталоге |
| 40 | Иерархические теги, цветовые флажки и зашифрованные заметки Markdown к файлам и папкам | Этап 3 | В каркасе | Поля `tags`, `note_markdown` в `FolderNode` и тест поиска |
| 41 | Пакетные операции с деревом: перенос, копирование веток, слияние, переименование, теги и сдвиг дат | Этап 4 | В каркасе | `move_media`, `rename_folder`, `update_media_tags_and_note` в `VaultCatalog` и FFI |
| 42 | Настраиваемая обложка папки (авто, выбранный кадр или нейтральная пиктограмма) | Этап 3 | В каркасе | Поле `cover_media_id` в `FolderNode` |
| 43 | Закреплённые папки на главном экране для быстрого доступа | Этап 3 | В каркасе | Поле `pinned` в `FolderNode` |
| 44 | Офлайн-поиск с мгновенной выдачей по зашифрованному индексу (имена, теги, заметки, EXIF, формат) | Этап 4 | Проверено тестом | `VaultCatalog::search_media` + FFI тест + `SearchScreen.kt` |
| 45 | Полностью локальное распознавание текста (Offline OCR RU + EN) на документах и фото | Этап 4 | Запланировано | Тест индексации распознанного текста без сети |
| 46 | Поиск визуально похожих фото и дубликатов по перцептивному хешу (pHash) | Этап 4 | Проверено тестом | Вычисление 64-битного `compute_dhash_64` в ОЗУ; UI группировки дублей на этапе 4 |
| 47 | Инспектор метаданных: EXIF, потоки видео/аудио, гистограмма, путь в дереве, BLAKE3, правка даты/EXIF | Этап 4 | Проверено тестом | `parse_jpeg_exif`, `strip_metadata_for_clean_export` и `update_media_captured_at` в FFI/storage тестах |
| 48 | Быстрые фильтры в 1 тап (Фото, Видео, RAW, Документы/PDF, Анимации, Избранное, Без тегов, Крупные) | Этап 3 | В каркасе | Перечисление `MediaKind` и тесты выборки каталога |
| 49 | Обратный экспорт выбранных фото или целого дерева подпапок на устройство (SAF / CachyOS) | Этап 4 | Проверено тестом | `VaultLayout::export_folder_tree` + FFI + тест воссоздания дерева в `meshvault-storage` |

## Раздел E. Просмотр медиа, 4K-видео, сканер документов и редактор

| ID | Требование | Этап | Статус | Способ проверки |
| :--- | :--- | :--- | :--- | :--- |
| 50 | Просмотрщик изображений со свайпом закрытия, двойным тапом и тайловым Deep Zoom до 200 МП | Этап 3 | В каркасе | `ViewerScreen.kt` (RAM-декодер, pinch/double-tap zoom, swipe-to-dismiss; тайлы 200МП на этапе 4) |
| 51 | Встроенный потоковый видеоплеер (Media3 Custom DataSource / декодер CachyOS) с перемоткой O(1) и позицией | Этап 4 | В каркасе | Тест `ChunkedBlobReader::decrypt_chunk_at` на произвольное смещение |
| 52 | Поддержка форматов внутри папок: JPEG, PNG, WebP, AVIF, HEIC, JXL, GIF, RAW, MP4/MKV/MOV/WebM, PDF, аудио, MD | Этап 4 | В каркасе | Регистрация MIME и `MediaKind` |
| 53 | Встроенный режим «Сканер документов» с выравниванием перспективы и сохранением в зашифрованный PDF | Этап 4 | Проверено тестом | `wrap_jpeg_as_pdf_in_ram` (`%PDF-1.4`) и тест импорта без temp-файлов в `import_stress_tests.rs` |
| 54 | Локальный неразрушающий фоторедактор с приватной ретушью лиц, подписей и номеров | Этап 4 | Проверено тестом | `redact_image_regions_in_ram` (`RedactionRect`) с очисткой метаданных в `import_stress_tests.rs` |
| 55 | Просмотр Live/Motion Photos и покадровый шаг на видео с сохранением стоп-кадра в текущую папку | Этап 4 | Запланировано | Тест извлечения кадра в ОЗУ |
| 56 | Режим сравнения двух снимков рядом (Side-by-Side с синхронным зумом) на планшетах и CachyOS | Этап 6 | Проверено тестом | `App.svelte` Side-by-Side + `adjustSideBySideZoom` в `desktop_cockpit.test.mjs` |
| 57 | Встроенная защищённая камера для съёмки напрямую в зашифрованный контейнер | Этап 4 | Запланировано | Тест CameraX-пайплайна в шифрованный поток |
| 58 | Настраиваемое слайд-шоу по папке с рекурсивным обходом подпапок | Этап 4 | Проверено тестом | `VaultCatalog::collect_subtree_media_ids` + FFI `collect_slideshow_media` + тесты |

## Раздел F. Zero-Knowledge Dropbox и связка Android ↔ CachyOS

| ID | Требование | Этап | Статус | Способ проверки |
| :--- | :--- | :--- | :--- | :--- |
| 59 | E2EE-синхронизация через `/MeshVault/` в Dropbox (OAuth2 PKCE App Folder, только шифротекст) | Этап 5 | Проверено тестом | Тест `dropbox_app_folder_zero_knowledge_bidirectional_sync_and_conflicts` и `PkceAuthFlow` |
| 60 | Режим экономии памяти смартфона (On-Demand / Selective Sync) с локальными превью и подгрузкой оригиналов | Этап 5 | Проверено тестом | Тест `SyncDownloadMode::MetadataAndThumbsOnly` и `SyncEngine::fetch_blob_on_demand` |
| 61 | Прямая LAN-синхронизация Wi-Fi между Android и CachyOS с проверкой по QR-коду и сквозным шифрованием | Этап 5 | Проверено тестом | `LanPairingSession` (QR SAS + XChaCha20-Poly1305 + replay guard) в `sync_e2ee_tests.rs` |
| 62 | Конфликт-менеджер ревизий для одновременных правок на телефоне и ПК без потери файлов | Этап 5 | Проверено тестом | `merge_catalogs_lww` и тест `SyncState::ConflictResolved` между двумя устройствами |
| 63 | Умные правила синхронизации (безлимитный Wi-Fi, зарядка, порог батареи, докачка с последнего чанка) | Этап 5 | Проверено тестом | Тест `SyncPolicy` -> `SyncState::PausedMetered` и `upload_chunked_resume` |
| 64 | Экспорт автономной зашифрованной резервной копии сейфа на USB OTG / диск Btrfs/LUKS с верификацией | Этап 5 | Проверено тестом | `export_verified_backup` + немедленный `scrub_vault` на архиве в `sync_e2ee_tests.rs` |

## Раздел G. Интерфейс Dark Cockpit, CachyOS, производительность и качество

| ID | Требование | Этап | Статус | Способ проверки |
| :--- | :--- | :--- | :--- | :--- |
| 65 | Единая дизайн-система Dark Cockpit (`#0b0b14`, StatusPill, MetricCard, StorageDonut, TelemetryChart) | Этап 3 | В каркасе | `CockpitTheme.kt` и `CockpitComponents.kt` собраны в APK |
| 66 | Адаптивная навигация: нижняя панель на смартфоне, левый сайдбар 260px на планшете и CachyOS | Этап 3 | В каркасе | `BoxWithConstraints` (`600.dp`) в `MainActivity.kt` |
| 67 | Десктоп CachyOS на Tauri v2 + Svelte + TS с клавиатурной навигацией (`hjkl`, `Space`, `1–9`, `Ctrl+F`, `Ctrl+L`) | Этап 6 | Проверено тестом | `apps/desktop` (Tauri v2 + Svelte + `cockpitState.mjs`) + тест `desktop_cockpit.test.mjs` и `desktop_bridge` |
| 68 | Интеграция CachyOS с Secret Service (KWallet/GNOME Keyring), Wayland и запрет индексации поисковиками | Этап 6 | Проверено тестом | `SecretServiceBridge` (`secret-tool`) + `.nomedia`/`.noindex` в `DesktopVaultBridge` и `meshvault init` |
| 69 | Полноценный CLI `meshvault` (`init`, `unlock`, `lock`, `status`, `doctor`, `import`, `tree`, `ls`, `scrub`, `sync`, `export`) | Этап 6 | Проверено тестом | `crates/meshvault-cli` (13 подкоманд с `--json`) и E2E-тест `cli_e2e_tests.rs` |
| 70 | Аппаратное ускорение и контроль нагрева/батареи в Foreground Service Android с паузой | Этап 3 | Проверено тестом | `ThermalBatteryGuard::shouldPauseHeavyWork` и тест `thermalBatteryGuardAndInboxWatcherBehaveCorrectly` |
| 71 | Строгий запрет аналитики, рекламы, трекеров и фоновой сети без явного включения sync | Этап 1 | Проверено тестом | Аудит зависимостей `Cargo.toml` и сетевых разрешений |
| 72 | Диагностика хранилища (MeshVault Doctor): слоты ключей, место, индекс, несинхронизированные чанки | Этап 4 | Проверено тестом | `VaultLayout::doctor_report` + FFI + кнопка `MeshVault Doctor` в `SecurityScreen` |
| 73 | Полная локализация RU и EN с правильными формами числительных русского языка | Этап 3 | Проверено тестом | `RussianPluralsTest.kt` + `values/strings.xml` и `values-ru/strings.xml` |
| 74 | Доступность интерфейса: крупные зоны нажатия, контрастные подписи, масштабирование шрифта | Этап 3 | В каркасе | Material3 компоненты и `sp`-типографика |
| 75 | Модульные и property-based тесты криптографии, тесты падения процесса и отсутствия файлов в tmp | Этап 1 | Проверено тестом | Тесты `crypto_security_tests.rs`; stress-тесты tmp на этапе 2 |
| 76 | Автоматический конвейер GitHub Actions: `fmt`, `clippy`, `test`, UniFFI, Android APK, Tauri Linux | Этап 6 | Проверено тестом | `.github/workflows/ci.yml`: `rust-fmt`, `rust-core`, `android-app`, `desktop-and-packaging` |
| 77 | Нативный `PKGBUILD` для CachyOS и воспроизводимые подписанные релизы Android и Linux | Этап 6 | Проверено тестом | `packaging/PKGBUILD` + `packaging/meshvault.desktop` с проверкой синтаксиса в CI |
| 78 | Безопасная миграция схемы хранилища с локальной точкой отката заголовка и каталога | Этап 4 | Проверено тестом | `VaultLayout::create_rollback_snapshot` / `rollback_to_snapshot` и тест отката |
| 79 | Импорт и экспорт зашифрованных настроек и правил автосортировки без раскрытия ключей | Этап 5 | Проверено тестом | `seal_vault_profile` / `open_vault_profile` и тест `encrypted_profile_export_transfers_autosort_rules_without_keys` |
| 80 | Режим «Чистая комната для демо/тестов»: генератор 10 000+ синтетических объектов без личных фото | Этап 2 | Проверено тестом | Генератор `generate_synthetic_tree` и стресс-тест на 5 000 объектов в `import_stress_tests.rs` |
