# Changelog

🇷🇺 Русская версия: [CHANGELOG.ru.md](CHANGELOG.ru.md)

All notable changes to this repository are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
for public releases.

## [Unreleased]

### Added

- Secret-scan workflow.
- Link from the app README to the canonical orchestrator troubleshooting guide.

## [0.1.10] - 2026-06-18

### Changed

- Rebuilt the public APK with `versionCode=11`.
- Upgraded AmneziaWG/gVisor transport dependencies so clean builds no longer
  need the netstack patch workaround.
- Removed `build/patch-awg-netstack.sh` and its build hook.

## [0.1.9] - 2026-06-18

### Changed

- Raised SOCKS router concurrency safely by moving the accept loop off the
  worker pool and adding a bounded session cap.
- Updated APK checksum documentation for the v0.1.9 artifact.

### Fixed

- Startup Xray render path now tracks restart-pending state and does not ignore
  restart failures.

## [0.1.8] - 2026-06-18

### Changed

- Hardened external public bootstrap import with explicit user confirmation.
- Reduced probe and routing pressure around public app health checks.

## [0.1.7] - 2026-06-18

### Added

- QR bootstrap scanner for public device enrollment.

## [0.1.6] - 2026-06-18

### Fixed

- Stabilized public carry on low-MTU links.

## [0.1.5] - 2026-06-18

### Changed

- Used plain REALITY flow for public routes.

## [0.1.4] - 2026-06-18

### Changed

- Same code state as v0.1.5 in the visible git tags.

## [0.1.3] - 2026-06-18

### Changed

- Applied public route parameters and strict carry gate behavior.

## [0.1.2] - 2026-06-18

### Changed

- Improved bootstrap import UX and documentation.

## [0.1.1] - 2026-06-18

### Fixed

- Fixed public app route bootstrap blockers.

## [0.1.0] - 2026-06-18

### Added

- Initial TrafficWrapper app split and public Android client structure.
- App signing and build-variable documentation.
- Public APK release documentation.
