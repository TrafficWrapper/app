# Build scripts

[Русский](README.ru.md)

Clean public build helpers:

- `build-transport-aar.sh` builds the gomobile transport AAR from `core/`.
- `prepare-xray-android.sh` downloads and verifies the pinned Xray Android
  binary.
- `build-apk.sh` builds a public debug APK.
- `build-release.sh` builds and signs a public release APK with your keystore.
- `make-manifest.sh` creates a signed `apk-update-v1` manifest for upload to the
  orchestrator.
- `verify-release.sh` verifies a local release APK hash/certificate, optional
  minisign manifest, and optional rebuild from a git tag.

No script contains deployment secrets. Provide signing material through
environment variables and keep keys outside the repository.
