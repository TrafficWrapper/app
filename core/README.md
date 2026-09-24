# TrafficWrapper core

[Русский](README.ru.md)

Go transport core used by the TrafficWrapper Android client.

Build and test from this `core/` directory:

```sh
docker run --rm -v "$PWD":/src -w /src golang:1.24-bookworm go test ./...
docker run --rm -v "$PWD":/src -w /src golang:1.24-bookworm go build ./...
```

For the Android AAR used by the app, run `build/build-transport-aar.sh` from the
app repository root. That script drives gomobile inside the project-specific
build environment.

`awg_src` is copied into `core/awg/device` without edits. Missing files from the
same `device` package are taken from `github.com/amnezia-vpn/amneziawg-go` tag
`v0.2.18`, commit `f4f4c999267437c3eb909e8d0e5278fb4596d9a7`.

Imported packages `conn`, `tun`, `ipc`, `ratelimiter`, `tai64n`, and `rwcancel`
come from the dependency `github.com/amnezia-vpn/amneziawg-go` pseudo-version
`v0.2.13-0.20250623202557-6a7c878409f3`, commit
`6a7c878409f32dc39a82bc597766c81304ab9840`. This revision removes the obsolete
`PacketBuffer.IsNil()` call and builds natively with gVisor
`v0.0.0-20250503011706-39ed1f5ac29c` using Go 1.24.

## Client API notes

- `ApplyDiscoveredEndpoints` verifies rendezvous bundles only against a pinned
  minisign key. Pin it with `rendezvous_public_key` in
  `ApplyPublicPlatformConfig` (may rotate the pin; use the `discovery_pubkey`
  of the verified client config) or with `SetRendezvousPublicKey(key)` (cannot
  replace a different pinned key). A `public_key` in the request is optional
  and must equal the pin. The pin lives for the process lifetime.
- The highest accepted rendezvous `seq` is remembered per pinned key; the
  effective rollback bound is `max(remembered, max_seen_seq)`. An empty `now`
  means the device clock; expiry is always checked against
  `max(now, device clock)`.
- With `base_config_json` the result is computed from it alone; without it the
  stored provisioned config is merged and updated atomically.
- `ApplyPublicPlatformConfig` never clears a stored route config because the
  request omits that route.
- `socks_listen` must be a loopback address; `socks_max_conns` caps concurrent
  SOCKS connections (default 1024). AWG `h1`..`h4` and the UAPI-bound config
  fields reject whitespace/control characters and line breaks.
- `PublicDeviceEnroll` forwards the optional `client_capabilities` (string
  array) and `client_version_code` (integer) to the orchestrator. The result
  passes through `awg_profiles` (map of AWG profile name to
  `{awg_public_key, internal_ip, psk2}`) and `reality_flow` (present, even
  as `""`, only when the orchestrator sent it).
- `ApplyPublicPlatformConfig` accepts `awg_profiles` in the same format. An
  `awg` / `awg_ru` route may carry `awg_profile` (falls back to `profile`),
  `endpoint_v6` (`"[addr]:port"`), `ip_family` (`"v4"` by default or `"v6"`)
  and `dns` (IP list). A route whose profile is not `""`/`"awg"` and is present
  in `awg_profiles` uses that profile's `internal_ip`/`psk2` (and its
  `endpoint_v6`, if any); otherwise the top-level credentials. `"v6"` uses the
  IPv6 endpoint when one is known, else the IPv4 endpoint. A non-blank route
  `dns` replaces `dns_servers` for that config; a non-IP value fails the apply.
- AWG dialects accept the wider worker ranges: `jc` 3..16, `jmin` 8..64,
  `jmax` 40..264 (and `< mtu`), `jmin < jmax`; older dialects stay valid.
- Rendezvous discovery only describes the base IPv4 AWG endpoint, so it does
  not merge into a stored config built for another AWG profile or an IPv6
  endpoint (with `base_config_json`: an IPv6 endpoint). Such a result is `ok`
  with the unchanged `config_json` and `awg_merge_skipped: true`.
- Errors that come from outside the Noise channel are prefixed with
  `unauthenticated server response:`, stripped of control characters and
  truncated to about 200 characters.
