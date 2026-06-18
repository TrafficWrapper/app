# Android client

[English](README.md)

Этот export содержит только public platform client flavor плюс общий main code.
Private/play flavors, keystores, generated AARs и generated native libraries
намеренно не включены.

Сборка из repository root:

```sh
./build/build-apk.sh
```

Release builds требуют ваш собственный Android keystore и
`TW_PUBLIC_SIGNING_CERT_SHA256`; см. root README.
