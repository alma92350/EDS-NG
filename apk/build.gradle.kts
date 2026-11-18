plugins {
    id("com.android.application")
    kotlin("android")
}

android {
    namespace = "org.openvault.app"
    compileSdk = 35

    defaultConfig {
        applicationId = "org.openvault.app"
        minSdk = 26
        targetSdk = 34
        versionCode = 2
        versionName = "0.1.1-test"
    }

    // Public debug key (committed on purpose: test builds only) so that new builds can update old installs.
    signingConfigs {
        create("test") {
            storeFile = file("../app/debug.keystore")
            storePassword = "openvault-debug"; keyAlias = "debug"; keyPassword = "openvault-debug"
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false // no reflection-heavy libs; keep stack traces readable in test builds
            signingConfig = signingConfigs.getByName("test")
        }
        debug { signingConfig = signingConfigs.getByName("test") }
    }

    // One source of truth: compile the Maven modules' Kotlin sources + the app sources into this APK.
    sourceSets.getByName("main") {
        java.srcDirs(
            "../core/io/src/main/kotlin", "../core/crypto/src/main/kotlin", "../core/veracrypt/src/main/kotlin",
            "../core/fs-api/src/main/kotlin", "../core/fs-fat/src/main/kotlin", "../core/fs-exfat/src/main/kotlin",
            "../core/vault/src/main/kotlin", "../app/src/main/kotlin",
        )
        res.srcDirs("../app/src/main/res")
    }

    compileOptions { sourceCompatibility = JavaVersion.VERSION_17; targetCompatibility = JavaVersion.VERSION_17 }
    kotlinOptions { jvmTarget = "17" }
    lint { abortOnError = false; checkReleaseBuilds = false }
    packaging { resources.excludes += setOf("META-INF/versions/**", "META-INF/*.kotlin_module") }
}

dependencies {
    implementation("org.bouncycastle:bcprov-jdk18on:1.78.1")
}
