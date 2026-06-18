plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.plugin.compose")
}

fun String.asBuildConfigString(): String =
    "\"" + replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n") + "\""

android {
    namespace = "pro.netcloud.trafficwrapper"
    compileSdk = 36

    defaultConfig {
        applicationId = providers.environmentVariable("TW_APPLICATION_ID")
            .orElse(providers.gradleProperty("tw.applicationId"))
            .getOrElse("org.trafficwrapper.app")
        minSdk = 26
        targetSdk = 36
        versionCode = providers.environmentVariable("TW_VERSION_CODE").map(String::toInt).getOrElse(1001)
        versionName = providers.environmentVariable("TW_VERSION_NAME")
            .orElse(providers.environmentVariable("TW_PUBLIC_VERSION_NAME"))
            .getOrElse("public-1.0.0")

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

    packaging {
        jniLibs {
            useLegacyPackaging = true
            keepDebugSymbols += "**/libxray.so"
        }
    }
}

kotlin {
    jvmToolchain(17)
}

dependencies {
    implementation(files("libs/transport.aar"))
    implementation(platform("androidx.compose:compose-bom:2026.05.01"))
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

    testImplementation("junit:junit:4.13.2")
    testImplementation("org.json:json:20240303")

    debugImplementation("androidx.compose.ui:ui-tooling")
}
