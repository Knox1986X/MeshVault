.PHONY: setup test lint apk-debug apk-release install-adb clean

GRADLE := ./gradlew
ADB    ?= adb
PKG    := com.meshvault.app
DEBUG_APK := app/build/outputs/apk/debug/app-debug.apk
RELEASE_APK := app/build/outputs/apk/release/app-release.apk

setup:
	chmod +x ./scripts/cachyos-setup.sh ./gradlew
	./scripts/cachyos-setup.sh

test:
	$(GRADLE) test testDebugUnitTest --stacktrace

lint:
	$(GRADLE) lintDebug --stacktrace

apk-debug:
	$(GRADLE) assembleDebug --stacktrace
	@echo "Debug APK собран: $(DEBUG_APK)"

apk-release:
	$(GRADLE) assembleRelease --stacktrace
	@echo "Release APK собран: $(RELEASE_APK)"

install-adb: apk-debug
	$(ADB) wait-for-device
	$(ADB) install -r $(DEBUG_APK)
	$(ADB) shell am start -n $(PKG)/.MainActivity

clean:
	$(GRADLE) clean
