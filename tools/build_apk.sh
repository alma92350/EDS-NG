#!/usr/bin/env bash
# Builds a debug-signed test APK using only Ubuntu packages (aapt, dalvik-exchange/dx, zipalign, apksigner,
# android-sdk-platform-23) + Maven. No Gradle, no Google SDK download needed.
#   sudo apt-get install aapt apksigner zipalign dalvik-exchange android-sdk-platform-23
set -euo pipefail
cd "$(dirname "$0")/.."
ANDROID_JAR=/usr/lib/android-sdk/platforms/android-23/android.jar
DX=/usr/lib/android-sdk/build-tools/debian/dx
OUT=app/build; DIST=app/dist
rm -rf "$OUT"; mkdir -p "$OUT/dex" "$DIST"

# 1. compile everything as Java-8-level bytecode (dx cannot read newer class files), skip tests
mvn -B -q clean package -DskipTests -Dkotlin.compiler.jvmTarget=1.8 -Dmaven.compiler.release=8 2>&1 | grep -v '^Picked' || true
M2=${HOME}/.m2/repository
CP="$M2/org/jetbrains/kotlin/kotlin-stdlib/2.0.21/kotlin-stdlib-2.0.21.jar $M2/org/bouncycastle/bcprov-jdk18on/1.78.1/bcprov-jdk18on-1.78.1.jar $M2/org/jetbrains/annotations/13.0/annotations-13.0.jar"
for j in $CP; do [ -f "$j" ] || { echo "missing dependency jar: $j" >&2; exit 1; }; done
JARS="$(ls core/*/target/openvault-*.jar app/target/openvault-app-*.jar | tr '\n' ' ') $CP"

# 2. strip multi-release / signature metadata from third-party jars, then dex (multi-dex: BouncyCastle is large)
mkdir -p "$OUT/jars"
for j in $JARS; do
  b="$OUT/jars/$(basename "$j")"; cp "$j" "$b"
  zip -q -d "$b" 'META-INF/versions/*' 'META-INF/*.SF' 'META-INF/*.RSA' 'META-INF/*.DSA' 'module-info.class' >/dev/null 2>&1 || true
done
"$DX" --dex --multi-dex --min-sdk-version=26 --output="$OUT/dex" "$OUT"/jars/*.jar 2>&1 | grep -v '^Picked' || true
ls "$OUT"/dex/classes*.dex >/dev/null

# 3. package resources + manifest, add dex
aapt package -f -M app/src/main/AndroidManifest.xml -S app/src/main/res -I "$ANDROID_JAR" \
     --min-sdk-version 26 --target-sdk-version 28 --version-code 1 --version-name 0.1.0-test -F "$OUT/unsigned.apk"
( cd "$OUT/dex" && aapt add -f ../unsigned.apk classes*.dex >/dev/null )

# 4. align + sign with the (public) debug key
zipalign -f -p 4 "$OUT/unsigned.apk" "$OUT/aligned.apk"
KS=app/debug.keystore
[ -f "$KS" ] || keytool -genkeypair -keystore "$KS" -storepass openvault-debug -keypass openvault-debug -alias debug \
     -keyalg RSA -keysize 2048 -validity 10000 -dname "CN=OpenVault Debug" >/dev/null 2>&1
apksigner sign --ks "$KS" --ks-pass pass:openvault-debug --key-pass pass:openvault-debug --out "$DIST/openvault-0.1.0-test.apk" "$OUT/aligned.apk"
apksigner verify --verbose "$DIST/openvault-0.1.0-test.apk" | head -4
aapt dump badging "$DIST/openvault-0.1.0-test.apk" | grep -E "^package|sdkVersion|targetSdk|uses-permission|launchable" || true
ls -la "$DIST/openvault-0.1.0-test.apk"
