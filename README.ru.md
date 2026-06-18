# TrafficWrapper App

[English](README.md)

Android public client платформы TrafficWrapper. Приложение не является Android
VPN: оно поднимает локальный SOCKS front-end и гонит трафик выбранных приложений
через платформенные user-space transports.

TrafficWrapper разделён на три репозитория:

- [orchestrator](https://github.com/TrafficWrapper/orchestrator) — control plane.
- [worker](https://github.com/TrafficWrapper/worker) — REALITY + AmneziaWG data plane nodes.
- [app](https://github.com/TrafficWrapper/app) — этот Android client.

Обычный workflow: развернуть orchestrator, enroll'ить workers, собрать/установить
это приложение и импортировать bootstrap payload из orchestrator.

## Что внутри

- `client/` — Android application, public flavor.
- `core/` — Go transport code для сборки `transport.aar`.
- `build/` — Docker build scripts для AAR, APK и update manifest.

В репозитории нет keystore, generated AAR, APK или private update key.

## Требования

- Docker или локальные Go 1.23+, Android SDK, JDK 17 и gomobile.
- Собственный Android release keystore.
- Собственный update minisign key для update manifests.
- Только для runtime orchestrator/worker может хватить 1 CPU и 1 GB RAM со swap.
- Для сборки APK учитывайте Docker Android builder image, Android NDK и Xray
  artifacts: нужно минимум 15-20 GB свободного диска и 4 GB+ RAM со swap.

Установка Docker на чистом Linux host:

```sh
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker "$USER"
```

## Ключи и подпись

TrafficWrapper использует отдельные корни доверия для разных задач:

| Ключ | Кто генерит | Где хранить private material | Куда идёт public part |
| --- | --- | --- | --- |
| Android release keystore | Вы, один раз на app lineage | Offline или CI secret storage | SHA-256 сертификата идёт в `TW_PUBLIC_SIGNING_CERT_SHA256`; Android проверяет APK signatures. |
| Update minisign key | Вы, один раз на update channel | Offline; не храните на orchestrator, если подписываете manifests сами | `update.pub` pin'ится в bootstrap/orchestrator как `update_pubkey`. |
| Config-signing key | Orchestrator signer process | Orchestrator state / signer process | Public config key pin'ится в bootstrap payloads. |
| Orchestrator Noise static key | Orchestrator | Orchestrator state | Public key попадает в bootstrap payloads как `orch_noise_public`. |

Android release keystore создаётся вами и хранится вне Git:

```sh
keytool -genkeypair \
  -keystore /secure/path/trafficwrapper-release.jks \
  -alias trafficwrapper-release \
  -keyalg RSA -keysize 4096 -validity 10000 \
  -dname "CN=TrafficWrapper App, O=Your Organization, C=US"
```

SHA-256 сертификата подписи APK из этого keystore pin'ится в приложении через
`TW_PUBLIC_SIGNING_CERT_SHA256`. Public client принимает self-updates только
если скачанный APK подписан тем же сертификатом.

Update minisign key создаётся вами:

```sh
minisign -G -s update.key -p update.pub
```

`update.key` используется только для подписи update manifests. `update.pub`
передаётся в orchestrator/bootstrap как update public key, чтобы приложение
проверяло manifests перед скачиванием APK.

Если использовать orchestrator seed-on-first-run, orchestrator генерирует
update key внутри своего state. Это удобно для первого demo APK, но не подходит
для управляемого владельцем update-канала: дальнейшая публикация APK требует
manifests, подписанных настроенным update public key. Для реального deployment
сгенерируйте свой offline minisign key и задайте его public key в orchestrator с
первого старта.

## Сборка

Debug build:

```sh
./build/build-apk.sh
```

Release build требует ваш signing key и expected signing certificate hash:

```sh
export TW_RELEASE_KEYSTORE=/path/to/release.keystore
export TW_RELEASE_KEY_ALIAS=your_alias
read -r -s TW_RELEASE_STORE_PASSWORD
export TW_RELEASE_STORE_PASSWORD
read -r -s TW_RELEASE_KEY_PASSWORD
export TW_RELEASE_KEY_PASSWORD
export TW_PUBLIC_SIGNING_CERT_SHA256=<your-release-cert-sha256>
./build/build-release.sh
```

Не коммитьте keystore, passwords, generated AAR, APK или manifests.

## Переменные сборки

Эти переменные читаются Gradle или scripts в `build/`:

| Переменная | Что это | Обязательна | Откуда брать / примечания |
| --- | --- | --- | --- |
| `TW_APPLICATION_ID` | Android package name. | Опц. | Дефолт `org.trafficwrapper.app`. |
| `TW_VERSION_CODE` | Android integer version code. | Опц. | Дефолт `1001`; для releases используйте монотонные значения. |
| `TW_VERSION_NAME` | Android version name. | Опц. | Дефолт `public-1.0.0`; перекрывает `TW_PUBLIC_VERSION_NAME`. |
| `TW_PUBLIC_VERSION_NAME` | Legacy/public fallback version name. | Опц. | Используется только если `TW_VERSION_NAME` не задан. |
| `TW_ENROLLMENT_SECRET` | Optional BuildConfig enrollment secret. | Опц. | Обычно empty для public platform builds. |
| `TW_RELEASE_KEYSTORE` | Путь к Android release keystore. | Обяз. для release | Генерируете сами через `keytool -genkeypair`. |
| `TW_RELEASE_KEY_ALIAS` | Alias внутри release keystore. | Обяз. для release | Значение `-alias` из `keytool`. |
| `TW_RELEASE_STORE_PASSWORD` | Keystore password. | Обяз. для release | Хранить в CI secrets или вводить интерактивно; не коммитить. |
| `TW_RELEASE_KEY_PASSWORD` | Key password. | Обяз. для release | Для PKCS12 keystore часто совпадает со store password. |
| `TW_PUBLIC_SIGNING_CERT_SHA256` | SHA-256 APK signing certificate, pin'ится в app и update verifier. | Обяз. для release и update manifest | Первый pass подписывает APK, затем `apksigner verify --print-certs app-public-release.apk`; второй pass пересобирает APK с lowercase digest. Это нужно, чтобы приложение pin'ило свой update signing certificate. |
| `TW_ANDROID_IMAGE` | Docker image name для Android builder. | Опц. | Дефолт `trafficwrapper/android-builder:api36`. |
| `TW_UPDATE_MANIFEST_KEY` | Minisign secret key для `build/make-manifest.sh`. | Обяз. для manifest | Генерируется `minisign -G -s update.key -p update.pub`. |
| `TW_UPDATE_OUT_DIR` | Output directory для generated update artifacts. | Опц. | Дефолт `build/update-release`. |
| `TW_MIN_SUPPORTED_VERSION` | Minimum supported version в update manifest. | Опц. | Дефолт `1`. |
| `TW_UPDATE_MANDATORY` | Помечать update как mandatory. | Опц. | Дефолт `false`. |
| `TW_UPDATE_NOTES` | Release notes внутри update manifest. | Опц. | Дефолт `Bug fixes and improvements.` |
| `TW_UPDATE_SEQ` | Monotonic update manifest sequence. | Опц. | Дефолт APK `versionCode`; увеличивайте при каждой публикации. |
| `TW_XRAY_VERSION` | Xray-core Android release tag. | Опц. | Дефолт `v26.3.27`. |
| `TW_XRAY_ASSET` | Имя Xray Android asset. | Опц. | Дефолт `Xray-android-arm64-v8a.zip`. |
| `TW_XRAY_SHA256` | Expected SHA-256 Xray zip. | Опц. | Дефолт pinned в `prepare-xray-android.sh`. |
| `TW_XRAY_URL` | Full Xray asset URL. | Опц. | По умолчанию строится из `TW_XRAY_VERSION` и `TW_XRAY_ASSET`. |
| `CGO_LDFLAGS` | Extra CGO linker flags при сборке `transport.aar`. | Опц. | Только advanced native build tuning. |
| `JAVA_OPTS`, `GRADLE_OPTS`, `DEFAULT_JVM_OPTS` | Standard Gradle wrapper JVM options. | Опц. | Только для local build tuning. |
| `GRADLE_USER_HOME`, `GOPATH`, `GOCACHE`, `GOMODCACHE` | Internal cache paths внутри build container. | Internal | Задаются scripts; обычно не переопределяются. |
| `ANDROID_CMDLINE_TOOLS_ZIP`, `ANDROID_CMDLINE_TOOLS_SHA1`, `ANDROID_NDK_VERSION`, `GOMOBILE_VERSION` | Docker build args в `build/android.Dockerfile`. | Optional build args | Переопределяйте через `docker build --build-arg ...` только для custom builder. |
| `ANDROID_HOME`, `ANDROID_SDK_ROOT`, `ANDROID_NDK_HOME` | Android SDK paths внутри builder image. | Internal | Задаются `build/android.Dockerfile`. |

## Где забрать готовый APK

Публичный APK доступен в GitHub Releases:

- Release: <https://github.com/TrafficWrapper/app/releases/tag/v0.1.9>
- Файл: `TrafficWrapper-app-v0.1.9.apk`
- APK SHA-256: `899f687d74e7a8a321d0e12646d031738b53f1754b6b73d6741132e21788d6dc`
- SHA-256 signing certificate: `bb8fcd34383b32c595c7d28a09cf7b89b473b86b632f3c1f5e722b4fa36e97d8`
- Application ID: `org.trafficwrapper.app`
- Версия: `0.1.9` (`versionCode=10`)

Чтобы установить APK: скачайте файл на телефон, разрешите установку из
неизвестных источников для браузера или файлового менеджера, откройте
скачанный файл и подтвердите установку. На Android 13+ разрешите уведомления
при первом запуске: они нужны foreground tunnel service.

Для полного self-trust соберите APK самостоятельно своим release key по разделу
[Сборка](#сборка). Orchestrator может опубликовать через платформенный канал
обновлений как этот готовый APK, так и ваш собственный APK.

## Bootstrap

Установите APK, откройте приложение и импортируйте bootstrap payload, который
создал владелец orchestrator. В web-админке orchestrator откройте
**Устройства** -> **+ Новое устройство** и выберите QR, Base64 или скачанный
`.json`. Payload pin'ит Noise key orchestrator и config minisign key.
Приложение enroll'ится, получает per-device credentials, проверяет signed
`client-config-v1` и подключается через настроенные workers.

Поддерживаемые способы импорта:

- Нажмите **Сканировать QR** в приложении и наведите камеру на QR из web-админки.
- Вставьте Base64 или JSON в поле bootstrap и нажмите **Импортировать**.
- Скачайте `.json` или `.txt` из web-админки, откройте файл на телефоне или
  нажмите **Открыть файл bootstrap** в приложении.
- Поделитесь bootstrap-текстом в TrafficWrapper через Android Share.

## Безопасность

- Используйте собственный release keystore и update minisign key.
- Signing keys держите offline или в CI secret storage.
- Public telemetry выключена по умолчанию и включается только пользователем.
- Updates проверяются по minisign подписи manifest, APK SHA-256 и APK signing
  certificate.

## 💚 Поддержать проект

Проект бесплатный и развивается на энтузиазме. Если он вам помогает — спасибо за
любую поддержку!

- **Bitcoin (BTC):** `bc1qdlqer9rtej6tpzdjzljdwltj7vxr4h6tv9eucp`
- **Ethereum (ETH):** `0xbe945043EaB956149ca24793c01d4927E90F878d`
- **USDT (ERC-20):** `0xbe945043EaB956149ca24793c01d4927E90F878d`
- **TRON (TRX):** `TGo4JyQnwH9Zb4ZZ37T3oaWuboy9qE7siq`
- **USDT (TRC-20):** `TGo4JyQnwH9Zb4ZZ37T3oaWuboy9qE7siq`

С благодарностью за вашу поддержку! 🙏

## Лицензия

MIT. См. `LICENSE`.
