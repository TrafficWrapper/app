# App Threat Model

[Русский](THREAT_MODEL.ru.md)

Canonical platform threat model:
<https://github.com/TrafficWrapper/orchestrator/blob/master/THREAT_MODEL.md>.

App-specific risks and controls:

- Bootstrap payloads contain deployment trust pins and one-time enrollment
  material. External imports must be confirmed by the user before enrollment.
- `client-config-v1` is accepted only after minisign verification against the
  pinned config public key.
- SOCKS domain targets are resolved through AWG netstack DNS inside the tunnel.
  Client configs may provide `dns_servers`; otherwise the app injects a public
  in-tunnel default (`1.1.1.1`, `1.0.0.1`). The app must not fall back to the
  host OS plaintext resolver for proxied domain names.
- APK self-updates are accepted only when the update manifest verifies and the
  downloaded APK certificate matches the pinned SHA-256 fingerprint.
- Optional VPN mode is compiled only when `TW_VPN_ENABLED=true` and remains
  runtime opt-in through Android `VpnService` consent. Full mode binds the app
  process to a non-VPN underlying network to avoid self-looping; if full VPN is
  enabled and no such network is available, the default kill switch establishes
  a blackhole VPN instead of falling back to clear traffic.
- Split VPN mode relies on Android `addAllowedApplication`; apps outside the
  selected set are intentionally not routed through TrafficWrapper.
- Workers remain exit/decryption points for AWG. The app can enforce signatures
  and pins, but it cannot make an untrusted worker trustworthy.
- Logs, screenshots, bug reports, and copied config must not include real
  orchestrator URLs, worker domains/IPs/SNI values, tokens, bootstrap payloads,
  or per-device credentials.
