dependencies {
    api(project(":core:io"))
    api(rootProject.libs.bouncycastle)
    testImplementation(project(":core:testkit"))
    testImplementation(libs.junit.jupiter.params)
}
