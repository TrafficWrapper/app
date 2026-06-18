#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
IMAGE_NAME="${TW_ANDROID_IMAGE:-trafficwrapper/android-builder:api36}"
GRADLE_CACHE="${REPO_ROOT}/.gradle-cache"
APK_DIR="${REPO_ROOT}/client/app/build/outputs/apk/public/release"
UNSIGNED_APK="${APK_DIR}/app-public-release-unsigned.apk"
ALIGNED_APK="${APK_DIR}/app-public-release-aligned.apk"
SIGNED_APK="${APK_DIR}/app-public-release.apk"
VERIFY_LOG="${APK_DIR}/app-public-release.apksigner.txt"

require_env() {
  local name="$1"
  if [[ -z "${!name:-}" ]]; then
    echo "missing required env: ${name}" >&2
    exit 2
  fi
}

require_env TW_RELEASE_KEYSTORE
require_env TW_RELEASE_KEY_ALIAS
require_env TW_RELEASE_STORE_PASSWORD
require_env TW_RELEASE_KEY_PASSWORD
require_env TW_PUBLIC_SIGNING_CERT_SHA256

if [[ ! -f "${TW_RELEASE_KEYSTORE}" ]]; then
  echo "release keystore not found: ${TW_RELEASE_KEYSTORE}" >&2
  exit 2
fi

KEYSTORE_DIR="$(cd "$(dirname "${TW_RELEASE_KEYSTORE}")" && pwd)"
KEYSTORE_FILE="$(basename "${TW_RELEASE_KEYSTORE}")"

mkdir -p "${GRADLE_CACHE}" "${APK_DIR}"

"${SCRIPT_DIR}/build-transport-aar.sh"
"${SCRIPT_DIR}/prepare-xray-android.sh"

docker build \
  -f "${REPO_ROOT}/build/android.Dockerfile" \
  -t "${IMAGE_NAME}" \
  "${REPO_ROOT}"

docker run --rm \
  -v "${REPO_ROOT}:/workspace" \
  -v "${GRADLE_CACHE}:/gradle-cache" \
  -e GRADLE_USER_HOME=/gradle-cache \
  -e TW_APPLICATION_ID="${TW_APPLICATION_ID:-org.trafficwrapper.app}" \
  -e TW_VERSION_CODE="${TW_VERSION_CODE:-1001}" \
  -e TW_VERSION_NAME="${TW_VERSION_NAME:-public-1.0.0}" \
  -e TW_PUBLIC_SIGNING_CERT_SHA256 \
  -w /workspace/client \
  "${IMAGE_NAME}" \
  ./gradlew --no-daemon assemblePublicRelease

if [[ ! -f "${UNSIGNED_APK}" ]]; then
  echo "unsigned release APK not found: ${UNSIGNED_APK}" >&2
  exit 1
fi

rm -f "${ALIGNED_APK}" "${SIGNED_APK}" "${VERIFY_LOG}"

docker run --rm \
  -v "${REPO_ROOT}:/workspace" \
  -v "${KEYSTORE_DIR}:/release-keystore:ro" \
  -e TW_RELEASE_KEY_ALIAS \
  -e TW_RELEASE_STORE_PASSWORD \
  -e TW_RELEASE_KEY_PASSWORD \
  -w /workspace/client \
  "${IMAGE_NAME}" \
  bash -lc "
    set -euo pipefail
    zipalign -f -P 16 4 \
      /workspace/client/app/build/outputs/apk/public/release/app-public-release-unsigned.apk \
      /workspace/client/app/build/outputs/apk/public/release/app-public-release-aligned.apk
    apksigner sign \
      --ks /release-keystore/${KEYSTORE_FILE} \
      --ks-key-alias \"\${TW_RELEASE_KEY_ALIAS}\" \
      --ks-pass env:TW_RELEASE_STORE_PASSWORD \
      --key-pass env:TW_RELEASE_KEY_PASSWORD \
      --v1-signing-enabled false \
      --v2-signing-enabled true \
      --v3-signing-enabled true \
      --out /workspace/client/app/build/outputs/apk/public/release/app-public-release.apk \
      /workspace/client/app/build/outputs/apk/public/release/app-public-release-aligned.apk
    apksigner verify --verbose --print-certs \
      /workspace/client/app/build/outputs/apk/public/release/app-public-release.apk \
      | tee /workspace/client/app/build/outputs/apk/public/release/app-public-release.apksigner.txt
  "

if [[ ! -f "${SIGNED_APK}" ]]; then
  echo "signed release APK not found: ${SIGNED_APK}" >&2
  exit 1
fi

echo "release_apk=${SIGNED_APK}"
ls -lh "${SIGNED_APK}"
echo "certificate_sha256:"
grep -i "Signer #1 certificate SHA-256 digest" "${VERIFY_LOG}" || true
