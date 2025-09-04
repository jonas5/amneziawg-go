#!/bin/bash

export PATH=/opt/cmake/bin:$PATH

export ANDROID_HOME=/usr/lib/android-sdk
export PATH=$ANDROID_HOME/cmdline-tools/latest/bin:$PATH
export JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64
export PATH=$JAVA_HOME/bin:$PATH

source ~/.bashrc

# === PRE-FLIGHT CHECK ===
JAVA_VERSION=$(java -version 2>&1 | awk -F[\".] '/version/ {print $2}')

if [[ "$JAVA_VERSION" != "17" ]]; then
  echo "❌ Java version is not 17. Detected: $JAVA_VERSION"
  echo "Please switch to Java 17 before running this script."
  exit 1
fi

echo "✅ Java version 17 detected. Proceeding..."


./gradlew --stop
./gradlew clean
rm -rf ~/.gradle/caches/
./gradlew assembleRelease --stacktrace --no-daemon


status=$?
 
if test $status -eq 0
then
	cp ui/build/outputs/apk/release/ui-universal-release*.apk .
fi

