#!/usr/bin/env bash
# ==============================================================================
# MeshVault — Скрипт подготовки среды разработки и сборки на CachyOS / Arch Linux
# Настраивает JDK 21, Android SDK 35, правила udev/adb и окружение fish/zsh/bash.
# ==============================================================================
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ANDROID_SDK_DIR="${ANDROID_HOME:-$HOME/Android/Sdk}"
JAVA_DIR="/usr/lib/jvm/java-21-openjdk"
CMDLINE_TOOLS_URL="https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip"

log()  { printf "\033[1;32m[MeshVault]\033[0m %s\n" "$*"; }
warn() { printf "\033[1;33m[MeshVault]\033[0m %s\n" "$*"; }
err()  { printf "\033[1;31m[MeshVault ОШИБКА]\033[0m %s\n" "$*" >&2; exit 1; }

if ! command -v pacman >/dev/null 2>&1; then
    err "Этот скрипт предназначен для CachyOS / Arch Linux (не найден пакетный менеджер pacman)."
fi

log "1/6. Установка базовых пакетов через pacman (JDK 21, adb/fastboot, android-udev)..."
sudo pacman -S --needed --noconfirm \
    jdk21-openjdk \
    android-tools \
    android-udev \
    unzip \
    curl \
    git \
    make

if command -v archlinux-java >/dev/null 2>&1; then
    CURRENT_JAVA="$(archlinux-java get || true)"
    if [[ "$CURRENT_JAVA" != "java-21-openjdk" && -d "$JAVA_DIR" ]]; then
        log "Переключение системной JVM на java-21-openjdk..."
        sudo archlinux-java set java-21-openjdk
    fi
fi

log "2/6. Настройка правил android-udev и прав доступа к ADB..."
if getent group adbusers >/dev/null 2>&1; then
    if ! id -nG "$USER" | grep -qw "adbusers"; then
        sudo usermod -aG adbusers "$USER"
        warn "Пользователь $USER добавлен в группу adbusers (перелогиньтесь для применения без sudo)."
    fi
fi
sudo udevadm control --reload-rules
sudo udevadm trigger

log "3/6. Развёртывание Android Command-Line Tools в ${ANDROID_SDK_DIR}..."
mkdir -p "${ANDROID_SDK_DIR}/cmdline-tools"

if [[ ! -x "${ANDROID_SDK_DIR}/cmdline-tools/latest/bin/sdkmanager" ]]; then
    if command -v paru >/dev/null 2>&1 && paru -Si android-sdk-cmdline-tools-latest >/dev/null 2>&1; then
        log "Найден AUR-хелпер paru. Загрузка официального Android SDK Command-Line Tools в ${ANDROID_SDK_DIR}..."
    fi
    TMP_ZIP="$(mktemp --suffix=.zip)"
    TMP_DIR="$(mktemp -d)"
    trap 'rm -rf "$TMP_ZIP" "$TMP_DIR"' EXIT
    curl -fL "$CMDLINE_TOOLS_URL" -o "$TMP_ZIP"
    unzip -q "$TMP_ZIP" -d "$TMP_DIR"
    rm -rf "${ANDROID_SDK_DIR}/cmdline-tools/latest"
    mv "${TMP_DIR}/cmdline-tools" "${ANDROID_SDK_DIR}/cmdline-tools/latest"
fi

export JAVA_HOME="$JAVA_DIR"
export ANDROID_HOME="$ANDROID_SDK_DIR"
export ANDROID_SDK_ROOT="$ANDROID_SDK_DIR"
export PATH="${JAVA_HOME}/bin:${ANDROID_HOME}/cmdline-tools/latest/bin:${ANDROID_HOME}/platform-tools:${PATH}"

log "4/6. Принятие лицензий и установка Android SDK Platform 35 + Build-Tools 35.0.0..."
yes | sdkmanager --sdk_root="${ANDROID_SDK_DIR}" --licenses >/dev/null || true
sdkmanager --sdk_root="${ANDROID_SDK_DIR}" \
    "platform-tools" \
    "platforms;android-35" \
    "build-tools;35.0.0"

log "5/6. Прописывание JAVA_HOME и ANDROID_HOME для fish, zsh и bash..."

# Fish (оболочка по умолчанию в CachyOS)
FISH_CONF_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/fish/conf.d"
mkdir -p "$FISH_CONF_DIR"
cat > "${FISH_CONF_DIR}/meshvault-android.fish" <<EOF
# MeshVault Android SDK & JDK environment (CachyOS)
set -gx JAVA_HOME "${JAVA_DIR}"
set -gx ANDROID_HOME "${ANDROID_SDK_DIR}"
set -gx ANDROID_SDK_ROOT "${ANDROID_SDK_DIR}"
fish_add_path -g "\$JAVA_HOME/bin" "\$ANDROID_HOME/cmdline-tools/latest/bin" "\$ANDROID_HOME/platform-tools"
EOF

# Помощник идемпотентной записи блока для bash и zsh
upsert_posix_rc() {
    local rc_file="$1"
    touch "$rc_file"
    if ! grep -q "# >>> meshvault-android >>>" "$rc_file"; then
        cat >> "$rc_file" <<EOF

# >>> meshvault-android >>>
export JAVA_HOME="${JAVA_DIR}"
export ANDROID_HOME="${ANDROID_SDK_DIR}"
export ANDROID_SDK_ROOT="${ANDROID_SDK_DIR}"
export PATH="\${JAVA_HOME}/bin:\${ANDROID_HOME}/cmdline-tools/latest/bin:\${ANDROID_HOME}/platform-tools:\${PATH}"
# <<< meshvault-android <<<
EOF
    fi
}

upsert_posix_rc "$HOME/.bashrc"
upsert_posix_rc "$HOME/.zshrc"

log "6/6. Генерация local.properties и запуск демона ADB..."
printf "sdk.dir=%s\n" "${ANDROID_SDK_DIR}" > "${PROJECT_ROOT}/local.properties"
adb start-server || true

log "Готово! Среда CachyOS успешно настроена. Запустите: make test && make apk-debug"
