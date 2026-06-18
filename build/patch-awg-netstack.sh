#!/usr/bin/env bash
set -euo pipefail

awg_dir="${1:-}"
if [[ -z "${awg_dir}" ]]; then
  awg_version="$(go list -m -f '{{.Version}}' github.com/amnezia-vpn/amneziawg-go)"
  awg_dir="$(go env GOMODCACHE)/github.com/amnezia-vpn/amneziawg-go@${awg_version}"
fi

target="${awg_dir}/tun/netstack/tun.go"
if [[ ! -f "${target}" ]]; then
  echo "amneziawg-go netstack file not found: ${target}" >&2
  exit 1
fi

if grep -q 'pkt.IsNil()' "${target}"; then
  sed -i 's/pkt.IsNil()/pkt == nil/' "${target}"
fi

if ! grep -q 'pkt == nil' "${target}"; then
  echo "amneziawg-go netstack patch was not applied: ${target}" >&2
  exit 1
fi

echo "patched_awg_netstack=${target}"
