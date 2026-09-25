#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
ANDROID_IMAGE="${TW_ANDROID_IMAGE:-trafficwrapper/android-builder:api36}"

APK="${APK:-}"
EXPECTED_APK_SHA256="${EXPECTED_APK_SHA256:-}"
EXPECTED_CERT_SHA256="${EXPECTED_CERT_SHA256:-}"
MANIFEST="${MANIFEST:-}"
MINISIG="${MINISIG:-}"
MINISIGN_PUBKEY="${MINISIGN_PUBKEY:-}"
TAG="${TAG:-}"

usage() {
  cat <<'EOF'
Usage:
  APK=TrafficWrapper-app.apk EXPECTED_APK_SHA256=<sha256> EXPECTED_CERT_SHA256=<cert-sha256> \
    build/verify-release.sh

  APK=TrafficWrapper-app.apk MANIFEST=update-manifest.json \
    MINISIG=update-manifest.json.minisig MINISIGN_PUBKEY=RW... build/verify-release.sh

  TAG=v0.1.11 APK=TrafficWrapper-app.apk EXPECTED_APK_SHA256=<sha256> \
    TW_RELEASE_*... TW_PUBLIC_SIGNING_CERT_SHA256=<cert-sha256> build/verify-release.sh

An APK is only accepted against an expected SHA-256 and an expected signing
certificate digest. Both come from EXPECTED_APK_SHA256 / EXPECTED_CERT_SHA256 or
from a minisign-verified manifest (apk_sha256 / signing_cert_sha256); explicit
values must agree with the manifest when both are given. Certificate digests may
be given in keytool form (colons, upper case).

TAG mode rebuilds the app from a temporary git worktree and requires the rebuilt
APK to be byte-identical to EXPECTED_APK_SHA256 and to APK when it is given.
This needs the same signing keystore and build inputs.
EOF
}

fail() {
  echo "verify: $*" >&2
  exit 1
}

sha256_file() {
  sha256sum "$1" | awk '{print $1}'
}

# Canonical digest form: no colons or whitespace, lower-case hex.
normalize_sha256() {
  printf '%s' "$1" | tr -d ':[:space:]' | tr 'A-F' 'a-f'
}

require_sha256() {
  local label="$1" value="$2"
  [[ "${value}" =~ ^[0-9a-f]{64}$ ]] || fail "${label} must be a SHA-256 digest (64 hex chars)"
}

manifest_field() {
  python3 - "$1" "$2" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8")).get(sys.argv[2], "")
print("" if value is None else value)
PY
}

apk_cert_sha256() {
  local apk="$1" apk_dir
  apk_dir="$(cd "$(dirname "${apk}")" && pwd)"
  docker build -f "${REPO_ROOT}/build/android.Dockerfile" -t "${ANDROID_IMAGE}" "${REPO_ROOT}" >/dev/null
  docker run --rm -v "${apk_dir}:/apk:ro" "${ANDROID_IMAGE}" \
    apksigner verify --print-certs "/apk/$(basename "${apk}")" \
    | sed -n 's/^Signer #1 certificate SHA-256 digest: *//Ip' | head -1
}

CHECKS=()

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

if [[ -z "${APK}" && -z "${TAG}" && -z "${MANIFEST}${MINISIG}${MINISIGN_PUBKEY}" ]]; then
  usage
  fail "set APK, MANIFEST and/or TAG"
fi

EXPECTED_APK_SHA256="$(normalize_sha256 "${EXPECTED_APK_SHA256}")"
EXPECTED_CERT_SHA256="$(normalize_sha256 "${EXPECTED_CERT_SHA256}")"
[[ -z "${EXPECTED_APK_SHA256}" ]] || require_sha256 EXPECTED_APK_SHA256 "${EXPECTED_APK_SHA256}"
[[ -z "${EXPECTED_CERT_SHA256}" ]] || require_sha256 EXPECTED_CERT_SHA256 "${EXPECTED_CERT_SHA256}"

if [[ -n "${MANIFEST}${MINISIG}${MINISIGN_PUBKEY}" ]]; then
  [[ -f "${MANIFEST}" ]] || fail "manifest not found: ${MANIFEST}"
  [[ -f "${MINISIG}" ]] || fail "minisig not found: ${MINISIG}"
  [[ -n "${MINISIGN_PUBKEY}" ]] || fail "MINISIGN_PUBKEY is required for manifest verification"
  command -v minisign >/dev/null || fail "minisign is not installed"
  minisign -Vm "${MANIFEST}" -x "${MINISIG}" -P "${MINISIGN_PUBKEY}" >/dev/null \
    || fail "manifest signature is invalid"
  CHECKS+=("manifest-signature")

  MANIFEST_APK_SHA256="$(normalize_sha256 "$(manifest_field "${MANIFEST}" apk_sha256)")"
  require_sha256 "manifest apk_sha256" "${MANIFEST_APK_SHA256}"
  if [[ -n "${EXPECTED_APK_SHA256}" && "${EXPECTED_APK_SHA256}" != "${MANIFEST_APK_SHA256}" ]]; then
    fail "EXPECTED_APK_SHA256 does not match manifest apk_sha256 ${MANIFEST_APK_SHA256}"
  fi
  EXPECTED_APK_SHA256="${MANIFEST_APK_SHA256}"

  MANIFEST_CERT_SHA256="$(normalize_sha256 "$(manifest_field "${MANIFEST}" signing_cert_sha256)")"
  if [[ -n "${MANIFEST_CERT_SHA256}" ]]; then
    require_sha256 "manifest signing_cert_sha256" "${MANIFEST_CERT_SHA256}"
    if [[ -n "${EXPECTED_CERT_SHA256}" && "${EXPECTED_CERT_SHA256}" != "${MANIFEST_CERT_SHA256}" ]]; then
      fail "EXPECTED_CERT_SHA256 does not match manifest signing_cert_sha256 ${MANIFEST_CERT_SHA256}"
    fi
    EXPECTED_CERT_SHA256="${MANIFEST_CERT_SHA256}"
  fi
fi

if [[ -n "${APK}" ]]; then
  [[ -f "${APK}" ]] || fail "APK not found: ${APK}"
  [[ -n "${EXPECTED_APK_SHA256}" ]] || fail "EXPECTED_APK_SHA256 (or a verified MANIFEST) is required"
  [[ -n "${EXPECTED_CERT_SHA256}" ]] || fail "EXPECTED_CERT_SHA256 (or manifest signing_cert_sha256) is required"
  APK_SHA="$(sha256_file "${APK}")"
  echo "apk_sha256=${APK_SHA}"
  [[ "${APK_SHA}" == "${EXPECTED_APK_SHA256}" ]] \
    || fail "APK SHA-256 mismatch: expected ${EXPECTED_APK_SHA256}"
  CHECKS+=("apk-sha256")
  if [[ -n "${MANIFEST}" ]]; then
    MANIFEST_APK_SIZE="$(manifest_field "${MANIFEST}" apk_size)"
    [[ "${MANIFEST_APK_SIZE}" == "$(stat -c%s "${APK}")" ]] || fail "manifest apk_size does not match APK"
    CHECKS+=("manifest-apk-size")
  fi
  CERT_SHA="$(normalize_sha256 "$(apk_cert_sha256 "${APK}")")"
  echo "certificate_sha256=${CERT_SHA}"
  require_sha256 "APK signing certificate digest" "${CERT_SHA}"
  [[ "${CERT_SHA}" == "${EXPECTED_CERT_SHA256}" ]] \
    || fail "APK cert SHA-256 mismatch: expected ${EXPECTED_CERT_SHA256}"
  CHECKS+=("apk-certificate")
fi

if [[ -n "${TAG}" ]]; then
  [[ -n "${EXPECTED_APK_SHA256}" ]] || fail "TAG mode requires EXPECTED_APK_SHA256 (or a verified MANIFEST)"
  TMP="$(mktemp -d)"
  cleanup() {
    git -C "${REPO_ROOT}" worktree remove --force "${TMP}/src" >/dev/null 2>&1 || true
    rm -rf "${TMP}"
  }
  trap cleanup EXIT
  git -C "${REPO_ROOT}" worktree add --detach "${TMP}/src" "${TAG}" >/dev/null
  (
    cd "${TMP}/src"
    ./build/build-release.sh >/dev/null
  )
  BUILT="${TMP}/src/client/app/build/outputs/apk/public/release/app-public-release.apk"
  [[ -f "${BUILT}" ]] || fail "rebuilt APK not found"
  BUILT_SHA="$(sha256_file "${BUILT}")"
  echo "rebuilt_apk_sha256=${BUILT_SHA}"
  [[ "${BUILT_SHA}" == "${EXPECTED_APK_SHA256}" ]] \
    || fail "rebuilt APK SHA-256 mismatch: expected ${EXPECTED_APK_SHA256}"
  if [[ -n "${APK}" ]]; then
    cmp -s "${BUILT}" "${APK}" || fail "rebuilt APK differs from ${APK}"
  fi
  CHECKS+=("rebuild")
fi

if [[ "${#CHECKS[@]}" -eq 0 ]]; then
  fail "nothing was verified"
fi
echo "verify: ok (${CHECKS[*]})"
