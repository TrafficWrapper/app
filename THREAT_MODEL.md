# App Threat Model

Canonical platform threat model:
<https://github.com/TrafficWrapper/orchestrator/blob/master/THREAT_MODEL.md>.

App-specific risks and controls:

- Bootstrap payloads contain deployment trust pins and one-time enrollment
  material. External imports must be confirmed by the user before enrollment.
- `client-config-v1` is accepted only after minisign verification against the
  pinned config public key.
- APK self-updates are accepted only when the update manifest verifies and the
  downloaded APK certificate matches the pinned SHA-256 fingerprint.
- Workers remain exit/decryption points for AWG. The app can enforce signatures
  and pins, but it cannot make an untrusted worker trustworthy.
- Logs, screenshots, bug reports, and copied config must not include real
  orchestrator URLs, worker domains/IPs/SNI values, tokens, bootstrap payloads,
  or per-device credentials.
