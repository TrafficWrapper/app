# Архитектура App

[English](ARCHITECTURE.md)

Каноническая architecture платформы находится в репозитории orchestrator:
<https://github.com/TrafficWrapper/orchestrator/blob/master/ARCHITECTURE.md>.

Этот репозиторий реализует Android public client:

- `core/transport/public_platform.go` выполняет public device enrollment через
  orchestrator Noise_XK HTTPS envelope, pinned по `orch_noise_public`.
- `client/app/src/main/java/pro/trafficwrapper/MainActivity.kt`
  импортирует QR/Base64/JSON bootstrap payloads, требует user confirmation для
  external imports и запускает enrollment.
- `PublicPlatformConfig.kt` проверяет signed `client-config-v1` через minisign
  перед parsing routes и update metadata.
- `AutoTransportService.kt` открывает local SOCKS front-end, probe'ит worker x
  route candidates и выбирает REALITY или AWG по health и policy.
- Optional builds с `TW_VPN_ENABLED=true` включают `TwVpnService.kt` и
  `core/transport/vpnbridge.go`: Android `VpnService` TUN traffic bridge'ится в
  тот же local SOCKS/front transport path.
- APK self-updates проверяют и update minisign manifest, и pinned APK signing
  certificate fingerprint.

Default app не является Android VPN. Он переносит только traffic, отправленный
в local SOCKS front-end или через user-selected integrations. VPN mode — это
отдельный compile-time и runtime opt-in path для операторов, которым нужен
full-device или split-app routing.
