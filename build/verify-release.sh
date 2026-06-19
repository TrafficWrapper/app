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

Optional:
  MANIFEST=update-manifest.json MINISIG=update-manifest.json.minisig MINISIGN_PUBKEY=RW... \
    build/verify-release.sh

  TAG=v0.1.11 APK=TrafficWrapper-app.apk EXPECTED_APK_SHA256=<sha256> \
    TW_RELEASE_*... TW_PUBLIC_SIGNING_CERT_SHA256=<cert-sha256> build/verify-release.sh

TAG mode rebuilds the app from a temporary git worktree. Byte-for-byte APK
comparison requires the same signing keystore and build inputs.
EOF
}

fail() {
  echo "verify: $*" >&2
  exit 1
}

sha256_file() {
  sha256sum "$1" | awk '{print $1}'
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

if [[ -z "${APK}" && -z "${TAG}" ]]; then
  usage
  fail "set APK and/or TAG"
fi

if [[ -n "${APK}" ]]; then
  [[ -f "${APK}" ]] || fail "APK not found: ${APK}"
  APK_SHA="$(sha256_file "${APK}")"
  echo "apk_sha256=${APK_SHA}"
  if [[ -n "${EXPECTED_APK_SHA256}" && "${APK_SHA}" != "${EXPECTED_APK_SHA256}" ]]; then
    fail "APK SHA-256 mismatch: expected ${EXPECTED_APK_SHA256}"
  fi
  if [[ -n "${EXPECTED_CERT_SHA256}" ]]; then
    docker build -f "${REPO_ROOT}/build/android.Dockerfile" -t "${ANDROID_IMAGE}" "${REPO_ROOT}" >/dev/null
    CERT_LINE="$(
      docker run --rm -v "$(cd "$(dirname "${APK}")" && pwd):/apk:ro" "${ANDROID_IMAGE}" \
        apksigner verify --print-certs "/apk/$(basename "${APK}")" \
        | grep -i 'Signer #1 certificate SHA-256 digest' || true
    )"
    echo "${CERT_LINE}"
    printf '%s\n' "${CERT_LINE}" | grep -qi "${EXPECTED_CERT_SHA256}" || fail "APK cert SHA-256 mismatch"
  fi
fi

if [[ -n "${MANIFEST}${MINISIG}${MINISIGN_PUBKEY}" ]]; then
  [[ -f "${MANIFEST}" ]] || fail "manifest not found: ${MANIFEST}"
  [[ -f "${MINISIG}" ]] || fail "minisig not found: ${MINISIG}"
  [[ -n "${MINISIGN_PUBKEY}" ]] || fail "MINISIGN_PUBKEY is required for manifest verification"
  command -v minisign >/dev/null || fail "minisign is not installed"
  minisign -Vm "${MANIFEST}" -x "${MINISIG}" -P "${MINISIGN_PUBKEY}"
  if [[ -n "${APK:-}" ]]; then
    MANIFEST_SHA="$(python3 - "${MANIFEST}" <<'PY'
import json, sys
print(json.load(open(sys.argv[1], encoding="utf-8")).get("apk_sha256", ""))
PY
)"
    [[ "${MANIFEST_SHA}" == "$(sha256_file "${APK}")" ]] || fail "manifest apk_sha256 does not match APK"
  fi
fi

if [[ -n "${TAG}" ]]; then
  TMP="$(mktemp -d)"
  trap 'rm -rf "${TMP}"' EXIT
  git -C "${REPO_ROOT}" worktree add --detach "${TMP}/src" "${TAG}" >/dev/null
  (
    cd "${TMP}/src"
    ./build/build-release.sh >/dev/null
  )
  BUILT="${TMP}/src/client/app/build/outputs/apk/public/release/app-public-release.apk"
  [[ -f "${BUILT}" ]] || fail "rebuilt APK not found"
  BUILT_SHA="$(sha256_file "${BUILT}")"
  echo "rebuilt_apk_sha256=${BUILT_SHA}"
  if [[ -n "${EXPECTED_APK_SHA256}" && "${BUILT_SHA}" != "${EXPECTED_APK_SHA256}" ]]; then
    fail "rebuilt APK SHA-256 mismatch: expected ${EXPECTED_APK_SHA256}"
  fi
fi

echo "verify: ok"
