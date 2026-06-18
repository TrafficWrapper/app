#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

APK_PATH="${1:-${REPO_ROOT}/client/app/build/outputs/apk/public/release/app-public-release.apk}"
OUT_DIR="${TW_UPDATE_OUT_DIR:-${REPO_ROOT}/build/update-release}"
ANDROID_IMAGE="${TW_ANDROID_IMAGE:-trafficwrapper/android-builder:api36}"

require_env() {
  local name="$1"
  if [[ -z "${!name:-}" ]]; then
    echo "missing required env: ${name}" >&2
    exit 2
  fi
}

require_env TW_UPDATE_MANIFEST_KEY
require_env TW_PUBLIC_SIGNING_CERT_SHA256

if [[ ! -f "${APK_PATH}" ]]; then
  echo "release APK not found: ${APK_PATH}" >&2
  exit 2
fi
if [[ ! -f "${TW_UPDATE_MANIFEST_KEY}" ]]; then
  echo "update minisign secret key not found: ${TW_UPDATE_MANIFEST_KEY}" >&2
  exit 2
fi

APK_ABS="$(cd "$(dirname "${APK_PATH}")" && pwd)/$(basename "${APK_PATH}")"
APK_REL="${APK_ABS#${REPO_ROOT}/}"
if [[ "${APK_REL}" == "${APK_ABS}" ]]; then
  echo "APK must be inside repo for aapt docker mount: ${APK_ABS}" >&2
  exit 2
fi

docker build \
  -f "${REPO_ROOT}/build/android.Dockerfile" \
  -t "${ANDROID_IMAGE}" \
  "${REPO_ROOT}" >/dev/null

BADGING="$(
  docker run --rm \
    -v "${REPO_ROOT}:/workspace:ro" \
    -w /workspace \
    "${ANDROID_IMAGE}" \
    aapt dump badging "/workspace/${APK_REL}"
)"

PACKAGE_LINE="$(printf '%s\n' "${BADGING}" | sed -n "s/^package: //p" | head -1)"
VERSION_CODE="$(printf '%s\n' "${PACKAGE_LINE}" | sed -n "s/.*versionCode='\([^']*\)'.*/\1/p")"
VERSION_NAME="$(printf '%s\n' "${PACKAGE_LINE}" | sed -n "s/.*versionName='\([^']*\)'.*/\1/p")"
if [[ -z "${VERSION_CODE}" || -z "${VERSION_NAME}" ]]; then
  echo "failed to parse APK version from aapt badging" >&2
  exit 1
fi

APK_NAME="app-public-${VERSION_CODE}.apk"
RELEASE_DIR="${OUT_DIR}/${VERSION_CODE}"
mkdir -p "${RELEASE_DIR}"
cp -f "${APK_ABS}" "${RELEASE_DIR}/${APK_NAME}"

APK_SIZE="$(stat -c%s "${RELEASE_DIR}/${APK_NAME}")"
APK_SHA256="$(sha256sum "${RELEASE_DIR}/${APK_NAME}" | awk '{print $1}')"
ISSUED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
MANIFEST_PATH="${RELEASE_DIR}/update-manifest.json"
MINISIG_PATH="${RELEASE_DIR}/update-manifest.json.minisig"
MIN_VERSION="${TW_MIN_SUPPORTED_VERSION:-1}"
MANDATORY="${TW_UPDATE_MANDATORY:-false}"
NOTES="${TW_UPDATE_NOTES:-Bug fixes and improvements.}"
SEQ="${TW_UPDATE_SEQ:-${VERSION_CODE}}"

python3 - "${MANIFEST_PATH}" \
  "${SEQ}" "${VERSION_CODE}" "${VERSION_NAME}" "${APK_NAME}" "${APK_SIZE}" "${APK_SHA256}" \
  "${TW_PUBLIC_SIGNING_CERT_SHA256}" "${MIN_VERSION}" "${MANDATORY}" "${NOTES}" "${ISSUED_AT}" <<'PY'
import json
import sys

(
    path,
    seq,
    version_code,
    version_name,
    apk_name,
    apk_size,
    apk_sha256,
    signing_cert_sha256,
    min_supported,
    mandatory,
    notes,
    issued_at,
) = sys.argv[1:]

manifest = {
    "schema": 1,
    "ns": "apk-update-v1",
    "seq": int(seq),
    "version_code": int(version_code),
    "version_name": version_name,
    "apk_url": apk_name,
    "apk_size": int(apk_size),
    "apk_sha256": apk_sha256,
    "signing_cert_sha256": signing_cert_sha256,
    "min_version": int(min_supported),
    "mandatory": mandatory == "true",
    "notes": notes,
    "issued_at": issued_at,
}
with open(path, "w", encoding="utf-8") as f:
    json.dump(manifest, f, ensure_ascii=False, indent=2)
    f.write("\n")
PY

minisign -S -W \
  -s "${TW_UPDATE_MANIFEST_KEY}" \
  -m "${MANIFEST_PATH}" \
  -x "${MINISIG_PATH}" \
  -t "seq=${SEQ} versionCode=${VERSION_CODE} issuedAt=${ISSUED_AT}" >/dev/null

echo "release_dir=${RELEASE_DIR}"
echo "manifest=${MANIFEST_PATH}"
echo "minisig=${MINISIG_PATH}"
echo "apk=${RELEASE_DIR}/${APK_NAME}"
echo "versionCode=${VERSION_CODE}"
echo "versionName=${VERSION_NAME}"
echo "apkSha256=${APK_SHA256}"
