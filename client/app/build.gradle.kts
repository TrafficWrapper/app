plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.plugin.compose")
}

fun String.asBuildConfigString(): String =
    "\"" + replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n") + "\""

fun String.asBuildConfigBoolean(): String =
    if (equals("true", ignoreCase = true) || this == "1") "true" else "false"

android {
    namespace = "pro.trafficwrapper"
    compileSdk = 36

    defaultConfig {
        applicationId = providers.environmentVariable("TW_APPLICATION_ID")
            .orElse(providers.gradleProperty("tw.applicationId"))
            .getOrElse("org.trafficwrapper.app")
        minSdk = 26
        targetSdk = 36
        versionCode = providers.environmentVariable("TW_VERSION_CODE").map(String::toInt).getOrElse(31)
        versionName = providers.environmentVariable("TW_VERSION_NAME")
            .orElse(providers.environmentVariable("TW_PUBLIC_VERSION_NAME"))
            .getOrElse("0.1.31")

        // NOTE: ENROLLMENT_SECRET is compiled into BuildConfig and can be extracted from any APK
        // (it is a plain string constant in classes.dex). It is a public build-time identifier,
        // not a secret: the server must never treat it as proof of anything beyond "some build of
        // this app"; device authentication relies on the Keystore-backed device identity instead.
        val enrollmentSecret = providers.environmentVariable("TW_ENROLLMENT_SECRET")
            .orElse(providers.gradleProperty("tw.enrollmentSecret"))
            .getOrElse("")
        buildConfigField("String", "ENROLLMENT_SECRET", enrollmentSecret.asBuildConfigString())
        buildConfigField("String", "TELEMETRY_ENDPOINT", "\"\"")
        buildConfigField("long", "TELEMETRY_EXPIRY_UNIX_MS", "0L")

        val publicSigningCertSha256 = providers.environmentVariable("TW_PUBLIC_SIGNING_CERT_SHA256")
            .orElse(providers.gradleProperty("tw.publicSigningCertSha256"))
            .getOrElse("")
        buildConfigField("String", "PUBLIC_UPDATE_SIGNING_CERT_SHA256", publicSigningCertSha256.asBuildConfigString())

        val vpnEnabled = providers.environmentVariable("TW_VPN_ENABLED")
            .orElse(providers.gradleProperty("tw.vpnEnabled"))
            .getOrElse("false")
        buildConfigField("boolean", "VPN_ENABLED", vpnEnabled.asBuildConfigBoolean())
        manifestPlaceholders["twVpnServiceEnabled"] = vpnEnabled.asBuildConfigBoolean()

        ndk {
            abiFilters += "arm64-v8a"
        }
    }

    flavorDimensions += "channel"
    productFlavors {
        create("public") {
            dimension = "channel"
        }
    }

    androidResources {
        localeFilters += listOf("ru")
    }

    buildFeatures {
        buildConfig = true
    }

    buildTypes {
        getByName("release") {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
        }
    }

    packaging {
        jniLibs {
            useLegacyPackaging = true
            // libxray.so is the upstream Xray *executable* (sha256-pinned in
            // build/prepare-xray-android.sh), already built with -s -w, so this does not add size;
            // it only stops AGP from running strip on a verified prebuilt binary.
            keepDebugSymbols += "**/libxray.so"
        }
    }
}

kotlin {
    jvmToolchain(17)
}

dependencies {
    implementation(files("libs/transport.aar"))
    implementation(platform("androidx.compose:compose-bom:2026.09.00"))
    implementation("androidx.activity:activity-compose:1.13.0")
    implementation("androidx.camera:camera-camera2:1.5.0")
    implementation("androidx.camera:camera-lifecycle:1.5.0")
    implementation("androidx.camera:camera-view:1.5.0")
    implementation("androidx.compose.foundation:foundation")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("com.android.tools.build:apksig:9.2.1")
    implementation("com.google.zxing:core:3.5.3")
    implementation("com.squareup.okhttp3:okhttp:5.4.0")
    implementation("androidx.work:work-runtime:2.11.2")

    testImplementation("junit:junit:4.13.2")
    testImplementation("org.json:json:20240303")

    debugImplementation("androidx.compose.ui:ui-tooling")
}
