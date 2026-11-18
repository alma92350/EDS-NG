// Gradle is used ONLY for the Android APK (built in CI, where Google's Maven and the Android SDK are reachable).
// The JVM core is built and tested with Maven (pom.xml); the Gradle module compiles the same sources.
pluginManagement { repositories { google(); gradlePluginPortal(); mavenCentral() } }
dependencyResolutionManagement { repositories { google(); mavenCentral() } }
rootProject.name = "openvault"
include(":apk")
