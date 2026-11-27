# MeshVault

**Zero-Knowledge зашифрованное хранилище референсов для художников на Android.**
Фото и видео шифруются на устройстве контейнерами **MVCH v2** (XChaCha20-Poly1305, побайтовая случайность),
метаданные — в **SQLCipher**-базе, мастер-ключ (VMK) никогда не покидает ОЗУ и не хранится в открытом виде.
Синхронизация с Dropbox — протокольно blinded: на сервер уходят только шифртексты с HMAC-«слепыми» именами.

## Карта модулей

| Модуль | Назначение |
|---|---|
| `:app` | Android-приложение (`com.meshvault.app`): Activity, DI-less wiring, настройки, просмотрщик, импорт SAF |
| `:ui` | Compose-экраны: разблокировка, галерея (masonry/квадраты/список), компоненты |
| `:crypto` | Чистая криптография: Argon2id KDF, конверты ключей, MVCH v2 потоковый шифр, HKDF/HMAC |
| `:domain` | Доменная модель, CRDT-мерджеры синка, вычисление дельт, хэши (dHash/pHash/BLAKE3-HMAC) |
| `:data-db` | Room + SQLCipher, Android Keystore (VMK envelope, биометрия), репозиторий |
| `:data-media` | Файловое хранилище `.mvbin`/`.mvthumb`, декодирование, Import-Pipeline, QR, Media3-источник |
| `:data-sync-dropbox` | OAuth 2.0 PKCE, дельта-синхронизация (WorkManager), HTTP API Dropbox |

## Сборка (на машине разработчика)

Требования: **JDK 21** (AGP 8.7.3), **Android SDK 35**, Gradle Wrapper (`./gradlew` в репозитории).
На CachyOS / Arch Linux:

```bash
./scripts/cachyos-setup.sh   # ставит JDK 21, Android cmdline-tools, udev-правила, local.properties
make apk-debug               # или: ./gradlew :app:assembleDebug
make install-adb             # установка и запуск через adb
```

Из Android Studio: открыть корень репозитория → дождаться синка Gradle → Run `app`.

APK: `app/build/outputs/apk/debug/app-debug.apk` (applicationId `com.meshvault.app`, minSdk 28).

> ⚠️ APK **нельзя** собрать в песочнице без Android SDK и доступа к Maven/Google —
> проект верифицирован статически (см. «Проверка» ниже); первый настоящий билд выполняется локально.

## Настройка Dropbox-синхронизации (опционально)

1. https://www.dropbox.com/developers → Create app → Scoped access → App folder.
2. Разрешить permission `files.content.write` и `files.content.read`.
3. В поле **Redirect URIs** добавить `meshvault://oauth2redirect`.
4. Скопировать **App key** → в приложении: Настройки хранилища → Dropbox → вставить App Key → «Подключить Dropbox».

Токены (access + refresh) хранятся только в Android Keystore на устройстве; MeshVault не видит пароль Dropbox.

## Архитектура безопасности (кратко)

- **Envelope Encryption**: мастер-пароль → Argon2id → KEK → unwrap VMK (32 Б, память only).
  VMK нигде не персистится; производные субключи — через HKDF-SHA256.
- **Двойное дно (Decoy)**: два неотличимых слота ключа в `vault_header.json`; Argon2 одинаков для обоих.
- **Panic Lock**: встряска / сворачивание (настраиваемо) → немедленное зануление VMK и субключей в ОЗУ,
  очистка LruCache битмапов, отключение SQLCipher-соединения.
- **Zero-knowledge sync**: файлы `.mvbin` шифруются чанками по 64 КБ (MVCH v2), имена файлов —
  HMAC-BLAKE3 "blind index", манифест синка — CRDT (LWW + Tombstones).
- **FLAG_SECURE** (опционально): запрет скриншотов и превью в recents.
- **Биометрия**: VMK запечатывается ключом `ANDROID_KEYSTORE` с `setUserAuthenticationRequired`.
- Внешних аналитик, рекламы и прослушивания нет; единственная сеть — Dropbox API (по желанию).

## Проверка, выполненная в песочнице

Сандбокс не имеет доступа к Android SDK / Maven (dl.google.com, repo.maven.apache.org закрыты),
поэтому сборка через Gradle там невозможна. Вместо этого все модули (`:crypto`, `:domain`, `:data-*`, `:ui`, `:app`)
прогнаны через **K2JVMCompiler** (Kotlin 2.0.21) против вручную поддерживаемых type-check стабов
(`android.*`, `androidx.*`, media3, okhttp3, zxing, sqlcipher, room, work) — **0 ошибок компиляции**.
Манифест, ресурсы, Gradle-конфигурация проверены статически; runtime-проверка выполняется на устройстве.

## Лицензия

Proprietary / проприетарная. Все права защищены.
