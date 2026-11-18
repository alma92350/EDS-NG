plugins { alias(libs.plugins.kotlin.jvm) apply false }

// Convention for every :core:* module: plain Kotlin/JVM (so android.* cannot compile), JUnit 5.
subprojects {
    if (path.startsWith(":core:") ) {
        apply(plugin = "org.jetbrains.kotlin.jvm")
        extensions.configure<org.jetbrains.kotlin.gradle.dsl.KotlinJvmProjectExtension> {
            compilerOptions { jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17) }
        }
        tasks.withType<JavaCompile> { options.release.set(17) }
        dependencies {
            "testImplementation"(rootProject.libs.junit.jupiter)
            "testRuntimeOnly"(rootProject.libs.junit.platform.launcher)
        }
        tasks.withType<Test> {
            useJUnitPlatform()
            testLogging { events("failed"); showStandardStreams = false }
        }
    }
}
