#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
IMAGE_NAME="${TW_ANDROID_IMAGE:-trafficwrapper/android-builder:api36}"
GRADLE_CACHE="${REPO_ROOT}/.gradle-cache"
GO_CACHE="${REPO_ROOT}/.go-cache"
AAR_PATH="${REPO_ROOT}/client/app/libs/transport.aar"

mkdir -p "${GRADLE_CACHE}" "${GO_CACHE}" "$(dirname "${AAR_PATH}")"

docker build \
  -f "${REPO_ROOT}/build/android.Dockerfile" \
  -t "${IMAGE_NAME}" \
  "${REPO_ROOT}"

docker run --rm \
  -v "${REPO_ROOT}:/workspace" \
  -v "${GRADLE_CACHE}:/gradle-cache" \
  -v "${GO_CACHE}:/go-cache" \
  -e GRADLE_USER_HOME=/gradle-cache \
  -e GOPATH=/go-cache/gopath \
  -e GOCACHE=/go-cache/build \
  -e GOMODCACHE=/go-cache/mod \
  -w /workspace/core \
  "${IMAGE_NAME}" \
  bash -lc '
    set -euo pipefail
    export CGO_LDFLAGS="-Wl,-z,max-page-size=16384 -Wl,-z,common-page-size=16384 ${CGO_LDFLAGS:-}"
    go mod download
    gomobile init
    gomobile bind -v \
      -target=android/arm64 \
      -androidapi=26 \
      -javapkg=pro.trafficwrapper.go \
      -o /workspace/client/app/libs/transport.aar \
      ./transport
  '

if [[ ! -f "${AAR_PATH}" ]]; then
  echo "AAR not found: ${AAR_PATH}" >&2
  exit 1
fi

ls -lh "${AAR_PATH}"
