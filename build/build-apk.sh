#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
IMAGE_NAME="${TW_ANDROID_IMAGE:-trafficwrapper/android-builder:api36}"
GRADLE_CACHE="${REPO_ROOT}/.gradle-cache"
APK_PATH="${REPO_ROOT}/client/app/build/outputs/apk/public/debug/app-public-debug.apk"

mkdir -p "${GRADLE_CACHE}"

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
  -e TW_PUBLIC_SIGNING_CERT_SHA256="${TW_PUBLIC_SIGNING_CERT_SHA256:-}" \
  -w /workspace/client \
  "${IMAGE_NAME}" \
  ./gradlew --no-daemon assemblePublicDebug

if [[ ! -f "${APK_PATH}" ]]; then
  echo "debug APK not found: ${APK_PATH}" >&2
  exit 1
fi

ls -lh "${APK_PATH}"
