# TrafficWrapper core

[English](README.md)

Go transport core, используемый Android client TrafficWrapper.

Собрать и протестировать из этой директории `core/`:

```sh
docker run --rm -v "$PWD":/src -w /src golang:1.24-bookworm go test ./...
docker run --rm -v "$PWD":/src -w /src golang:1.24-bookworm go build ./...
```

Для Android AAR, используемого app, запускайте `build/build-transport-aar.sh`
из app repository root. Этот script запускает gomobile внутри
project-specific build environment.

`awg_src` копируется в `core/awg/device` без правок. Недостающие файлы из того
же package `device` взяты из `github.com/amnezia-vpn/amneziawg-go` tag
`v0.2.18`, commit `f4f4c999267437c3eb909e8d0e5278fb4596d9a7`.

Imported packages `conn`, `tun`, `ipc`, `ratelimiter`, `tai64n` и `rwcancel`
идут из dependency `github.com/amnezia-vpn/amneziawg-go` pseudo-version
`v0.2.13-0.20250623202557-6a7c878409f3`, commit
`6a7c878409f32dc39a82bc597766c81304ab9840`. Эта revision удаляет obsolete
`PacketBuffer.IsNil()` call и нативно собирается с gVisor
`v0.0.0-20250503011706-39ed1f5ac29c` на Go 1.24.

## Заметки по Client API

- `ApplyDiscoveredEndpoints` проверяет rendezvous-бандлы только закреплённым
  minisign-ключом. Закрепить его можно полем `rendezvous_public_key` в
  `ApplyPublicPlatformConfig` (может сменить ключ; передавайте
  `discovery_pubkey` из проверенного client config) или вызовом
  `SetRendezvousPublicKey(key)` (не заменяет уже закреплённый другой ключ).
  `public_key` в запросе необязателен и должен совпадать с закреплённым.
  Закрепление живёт до конца процесса.
- Наибольший принятый `seq` запоминается для закреплённого ключа; граница
  отката — `max(запомненный, max_seen_seq)`. Пустой `now` означает часы
  устройства; истечение всегда проверяется по `max(now, часы устройства)`.
- С `base_config_json` результат считается только из него; без него
  сохранённый provisioned config сливается и обновляется атомарно.
- `ApplyPublicPlatformConfig` не стирает сохранённый конфиг маршрута, если
  маршрут в запросе не передан.
- `socks_listen` должен быть loopback-адресом; `socks_max_conns` ограничивает
  число одновременных SOCKS-соединений (по умолчанию 1024). AWG `h1`..`h4` и
  поля конфига, попадающие в UAPI, не допускают пробельных/управляющих
  символов и переводов строк.
- Ошибки, пришедшие вне Noise-канала, получают префикс
  `unauthenticated server response:`, очищаются от управляющих символов и
  обрезаются примерно до 200 символов.
