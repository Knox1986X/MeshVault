# Packaging (CachyOS / Arch Linux)

Каталог содержит `PKGBUILD` и `.desktop`-файл для нативной установки `meshvault` (CLI + Tauri v2 desktop) на CachyOS / Arch Linux.

## Сборка пакета локально на CachyOS
```bash
cd packaging
makepkg -si
```

Синтаксис `packaging/PKGBUILD` проверяется автоматически в CI (`bash -n packaging/PKGBUILD`).
