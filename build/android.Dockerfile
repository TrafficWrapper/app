FROM golang:1.27.1-bookworm@sha256:69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195 AS go-toolchain

FROM eclipse-temurin:25-jdk-jammy@sha256:0cbcd13ae550a9c8334d5ef4483a4247625f47067f16127e28638fdafaeb35ea

ARG ANDROID_CMDLINE_TOOLS_ZIP=commandlinetools-linux-14742923_latest.zip
ARG ANDROID_CMDLINE_TOOLS_SHA1=48833c34b761c10cb20bcd16582129395d121b27
ARG ANDROID_NDK_VERSION=26.3.11579264
ARG GOMOBILE_VERSION=a1d90793fc63015513ae877a689ddcc0903750ae

ENV ANDROID_HOME=/opt/android-sdk
ENV ANDROID_SDK_ROOT=/opt/android-sdk
ENV ANDROID_NDK_HOME="${ANDROID_HOME}/ndk/${ANDROID_NDK_VERSION}"
ENV PATH="/usr/local/go/bin:/root/go/bin:${ANDROID_HOME}/cmdline-tools/latest/bin:${ANDROID_HOME}/platform-tools:${ANDROID_HOME}/build-tools/36.0.0:${PATH}"

COPY --from=go-toolchain /usr/local/go /usr/local/go

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl unzip zip \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p "${ANDROID_HOME}/cmdline-tools" /tmp/android-tools \
    && curl -fsSL "https://dl.google.com/android/repository/${ANDROID_CMDLINE_TOOLS_ZIP}" -o /tmp/android-tools/cmdline-tools.zip \
    && echo "${ANDROID_CMDLINE_TOOLS_SHA1}  /tmp/android-tools/cmdline-tools.zip" | sha1sum -c - \
    && unzip -q /tmp/android-tools/cmdline-tools.zip -d /tmp/android-tools \
    && mv /tmp/android-tools/cmdline-tools "${ANDROID_HOME}/cmdline-tools/latest" \
    && rm -rf /tmp/android-tools

RUN yes | sdkmanager --licenses >/dev/null \
    && sdkmanager --install \
        "platform-tools" \
        "platforms;android-36" \
        "build-tools;36.0.0" \
        "ndk;${ANDROID_NDK_VERSION}"

RUN go install "golang.org/x/mobile/cmd/gomobile@${GOMOBILE_VERSION}" \
    && go install "golang.org/x/mobile/cmd/gobind@${GOMOBILE_VERSION}"

WORKDIR /workspace/client
