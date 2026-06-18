# Модель угроз App

[English](THREAT_MODEL.md)

Каноническая threat model платформы:
<https://github.com/TrafficWrapper/orchestrator/blob/master/THREAT_MODEL.md>.

App-specific risks and controls:

- Bootstrap payloads содержат deployment trust pins и one-time enrollment
  material. External imports должны подтверждаться user'ом до enrollment.
- `client-config-v1` принимается только после minisign verification против
  pinned config public key.
- APK self-updates принимаются только когда update manifest проходит verify и
  certificate скачанного APK совпадает с pinned SHA-256 fingerprint.
- Workers остаются exit/decryption points для AWG. App может enforce signatures
  и pins, но не может сделать untrusted worker доверенным.
- Logs, screenshots, bug reports и copied config не должны включать реальные
  orchestrator URLs, worker domains/IPs/SNI values, tokens, bootstrap payloads
  или per-device credentials.
