# App Architecture

Canonical platform architecture lives in the orchestrator repository:
<https://github.com/TrafficWrapper/orchestrator/blob/master/ARCHITECTURE.md>.

This repository implements the Android public client:

- `core/transport/public_platform.go` performs public device enrollment over
  the orchestrator Noise_XK HTTPS envelope pinned by `orch_noise_public`.
- `client/app/src/main/java/pro/netcloud/trafficwrapper/MainActivity.kt`
  imports QR/Base64/JSON bootstrap payloads, requires user confirmation for
  external imports, and starts enrollment.
- `PublicPlatformConfig.kt` verifies signed `client-config-v1` with minisign
  before parsing routes and update metadata.
- `AutoTransportService.kt` exposes a local SOCKS front-end, probes worker x
  route candidates, and selects REALITY or AWG according to health and policy.
- APK self-updates verify both the update minisign manifest and the pinned APK
  signing certificate fingerprint.

The app is not an Android VPN. It only carries traffic sent to its local SOCKS
front-end or through user-selected integrations.
