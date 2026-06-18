# Changelog

🇬🇧 English: [CHANGELOG.md](CHANGELOG.md)

Все заметные изменения этого repository документируются здесь.

Формат основан на [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), а
project следует [Semantic Versioning](https://semver.org/spec/v2.0.0.html) для
public releases.

## [Unreleased]

### Added

- Repository CODEOWNERS и secret-scan workflow.
- Ссылка из app README на канонический orchestrator troubleshooting guide.

## [0.1.10] - 2026-06-18

### Changed

- Пересобран public APK с `versionCode=11`.
- Обновлены AmneziaWG/gVisor transport dependencies, чтобы clean builds больше
  не требовали netstack patch workaround.
- Удалены `build/patch-awg-netstack.sh` и его build hook.

## [0.1.9] - 2026-06-18

### Changed

- SOCKS router concurrency безопасно повышен: accept loop вынесен из worker
  pool и добавлен bounded session cap.
- Обновлена APK checksum documentation для artifact v0.1.9.

### Fixed

- Startup Xray render path теперь отслеживает restart-pending state и не
  игнорирует restart failures.

## [0.1.8] - 2026-06-18

### Changed

- External public bootstrap import усилен explicit user confirmation.
- Снижена probe и routing pressure вокруг public app health checks.

## [0.1.7] - 2026-06-18

### Added

- QR bootstrap scanner для public device enrollment.

## [0.1.6] - 2026-06-18

### Fixed

- Public carry стабилизирован на low-MTU links.

## [0.1.5] - 2026-06-18

### Changed

- Использован plain REALITY flow для public routes.

## [0.1.4] - 2026-06-18

### Changed

- То же code state, что и v0.1.5, согласно видимым git tags.

## [0.1.3] - 2026-06-18

### Changed

- Применены public route parameters и strict carry gate behavior.

## [0.1.2] - 2026-06-18

### Changed

- Улучшены bootstrap import UX и documentation.

## [0.1.1] - 2026-06-18

### Fixed

- Исправлены public app route bootstrap blockers.

## [0.1.0] - 2026-06-18

### Added

- Initial TrafficWrapper app split и public Android client structure.
- App signing и build-variable documentation.
- Public APK release documentation.
