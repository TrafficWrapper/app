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
- `PublicDeviceEnroll` передаёт оркестратору необязательные
  `client_capabilities` (массив строк) и `client_version_code` (целое). В
  результат без изменений попадают `awg_profiles` (карта имя AWG-профиля →
  `{awg_public_key, internal_ip, psk2}`) и `reality_flow` (присутствует, в том
  числе как `""`, только если его прислал оркестратор).
- `ApplyPublicPlatformConfig` принимает `awg_profiles` в том же формате.
  Маршрут `awg` / `awg_ru` может содержать `awg_profile` (иначе берётся
  `profile`), `endpoint_v6` (`"[addr]:port"`), `ip_family` (`"v4"` по
  умолчанию или `"v6"`) и `dns` (список IP). Если профиль маршрута не
  `""`/`"awg"` и есть в `awg_profiles`, используются его `internal_ip`/`psk2`
  (и его `endpoint_v6`, если задан), иначе — общие. `"v6"` берёт IPv6-endpoint,
  если он известен, иначе IPv4. Непустой `dns` маршрута заменяет `dns_servers`
  для этого конфига; значение, не являющееся IP, — ошибка apply.
- AWG-диалекты принимают расширенные диапазоны воркера: `jc` 3..16, `jmin`
  8..64, `jmax` 40..264 (и `< mtu`), `jmin < jmax`; старые диалекты остаются
  валидными.
- Rendezvous описывает только базовый IPv4 AWG-endpoint, поэтому discovery не
  сливается в сохранённый конфиг другого AWG-профиля или с IPv6-endpoint (с
  `base_config_json` — с IPv6-endpoint). Такой результат `ok` с неизменным
  `config_json` и `awg_merge_skipped: true`.
- Ошибки, пришедшие вне Noise-канала, получают префикс
  `unauthenticated server response:`, очищаются от управляющих символов и
  обрезаются примерно до 200 символов.
