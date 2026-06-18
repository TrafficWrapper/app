#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

XRAY_VERSION="${TW_XRAY_VERSION:-v26.3.27}"
XRAY_ASSET="${TW_XRAY_ASSET:-Xray-android-arm64-v8a.zip}"
XRAY_SHA256="${TW_XRAY_SHA256:-57149ffd48b629c07bf76938e73ab2729fde5910091497eab3e93d1c190f4c1b}"
XRAY_URL="${TW_XRAY_URL:-https://github.com/XTLS/Xray-core/releases/download/${XRAY_VERSION}/${XRAY_ASSET}}"

CACHE_DIR="${REPO_ROOT}/.artifacts/xray/${XRAY_VERSION}"
ZIP_PATH="${CACHE_DIR}/${XRAY_ASSET}"
OUT_DIR="${REPO_ROOT}/client/app/src/main/jniLibs/arm64-v8a"
OUT_PATH="${OUT_DIR}/libxray.so"

mkdir -p "${CACHE_DIR}" "${OUT_DIR}"

if [[ ! -f "${ZIP_PATH}" ]]; then
  curl -fL "${XRAY_URL}" -o "${ZIP_PATH}"
fi

actual_sha="$(sha256sum "${ZIP_PATH}" | awk '{print $1}')"
if [[ "${actual_sha}" != "${XRAY_SHA256}" ]]; then
  echo "Xray asset sha256 mismatch: got ${actual_sha}, expected ${XRAY_SHA256}" >&2
  rm -f "${ZIP_PATH}"
  exit 1
fi

tmp_dir="$(mktemp -d)"
cleanup() {
  rm -rf "${tmp_dir}"
}
trap cleanup EXIT

python3 -m zipfile -e "${ZIP_PATH}" "${tmp_dir}"

if [[ ! -f "${tmp_dir}/xray" ]]; then
  echo "Xray binary not found in ${XRAY_ASSET}" >&2
  exit 1
fi

install -m 0755 "${tmp_dir}/xray" "${OUT_PATH}"
ls -lh "${OUT_PATH}"
