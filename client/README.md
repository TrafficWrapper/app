# Android client

[Русский](README.ru.md)

This export contains only the public platform client flavor plus shared main
code. Private/play flavors, keystores, generated AARs, and generated native
libraries are intentionally not included.

Build from the repository root:

```sh
./build/build-apk.sh
```

Release builds require your own Android keystore and
`TW_PUBLIC_SIGNING_CERT_SHA256`; see the root README.
