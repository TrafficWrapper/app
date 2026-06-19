# Build scripts

[English](README.md)

Чистые public build helpers:

- `build-transport-aar.sh` собирает gomobile transport AAR из `core/`.
- `prepare-xray-android.sh` скачивает и проверяет pinned Xray Android binary.
- `build-apk.sh` собирает public debug APK.
- `build-release.sh` собирает и подписывает public release APK вашим keystore.
- `make-manifest.sh` создаёт signed `apk-update-v1` manifest для загрузки в
  orchestrator.
- `verify-release.sh` проверяет локальный release APK hash/certificate,
  optional minisign manifest и optional rebuild из git tag.

Ни один script не содержит deployment secrets. Передавайте signing material
через environment variables и держите keys вне repository.
