@file:Suppress("UnstableApiUsage")

import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

val pkg: String = providers.gradleProperty("amneziawgPackageName").get()

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.kapt) // or use id("org.jetbrains.kotlin.kapt")
}

kapt {
    javacOptions {
        option("--add-exports", "jdk.compiler/com.sun.tools.javac.main=ALL-UNNAMED")
    }
}


android {
	splits {

	    // Configures multiple APKs based on ABI (Application Binary Interface)
	    abi {

	        // Enables building multiple APKs per ABI.
	        isEnable = true

	        // By default, all ABIs are included, but you can specify a list.
	        // If you want to clean out any previous settings, you can reset it.
	        reset()

	        // Specify the ABIs you want to build for. The most common are:
	        include("arm64-v8a", "armeabi-v7a", "x86_64", "x86")

	        // By default, this will generate an APK for each ABI specified in `include`.
	        // For example: ui-arm64-v8a-release.apk, ui-armeabi-v7a-release.apk, etc.

	        // OPTIONAL: You can also generate a "universal" APK that contains all architectures.
	        // This is useful for local testing or direct distribution, but it will be larger.
	        isUniversalApk = true
	    }
	}


    sourceSets {
        getByName("main").java.srcDirs("src/main/java")
        getByName("release").java.srcDirs("src/release/java")
    }
    buildFeatures {
        buildConfig = true
        dataBinding = true
        viewBinding = true
    }
    namespace = pkg
    defaultConfig {
        applicationId = pkg
        targetSdk = 34
        versionCode = providers.gradleProperty("amneziawgVersionCode").get().toInt()
        versionName = providers.gradleProperty("amneziawgVersionName").get()
        buildConfigField("int", "MIN_SDK_VERSION", minSdk.toString())
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
        isCoreLibraryDesugaringEnabled = true
    }
    signingConfigs {
        create("release") {
            // Read credentials from gradle.properties.
            // You must set these in your `~/.gradle/gradle.properties` file or another secure location.
            val storeFile = providers.gradleProperty("MY_RELEASE_KEYSTORE_FILE")
            if (storeFile.isPresent && rootProject.file(storeFile.get()).exists()) {
                this.storeFile = rootProject.file(storeFile.get())
                this.storePassword = providers.gradleProperty("MY_RELEASE_KEYSTORE_PASSWORD").get()
                this.keyAlias = providers.gradleProperty("MY_RELEASE_KEY_ALIAS").get()
                this.keyPassword = providers.gradleProperty("MY_RELEASE_KEY_PASSWORD").get()
            } else {
                println("Release keystore not found, release builds will not be signed.")
                // Fallback to debug signing for release builds if no keystore is found,
                // to allow building without a private key. The APK will not be installable as a release update.
                initWith(getByName("debug"))
            }
        }
    }

    buildTypes {
        getByName("release") {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles("proguard-android-optimize.txt")
            signingConfig = signingConfigs.getByName("release")
            packaging {
                resources {
                    excludes += "DebugProbesKt.bin"
                    excludes += "kotlin-tooling-metadata.json"
                    excludes += "META-INF/*.version"
                }
            }
        }
        getByName("debug") {
            applicationIdSuffix = ".debug"
            versionNameSuffix = "-debug"
        }
        create("googleplay") {
            initWith(getByName("release"))
            matchingFallbacks += "release"
        }
    }
    androidResources {
        generateLocaleConfig = true
    }
    lint {
        disable += "LongLogTag"
        warning += "MissingTranslation"
        warning += "ImpliedQuantity"
    }

    splits {
        abi {
            isEnable = true
            reset()
            include("arm64-v8a", "armeabi-v7a", "x86_64", "x86")
            isUniversalApk = true
        }
    }

}

dependencies {
    implementation(project(":tunnel"))
    implementation(libs.androidx.activity.ktx)
    implementation(libs.androidx.annotation)
    implementation(libs.androidx.appcompat)
    implementation(libs.androidx.constraintlayout)
    implementation(libs.androidx.coordinatorlayout)
    implementation(libs.androidx.biometric)
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.fragment.ktx)
    implementation(libs.androidx.preference.ktx)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.androidx.datastore.preferences)
    implementation(libs.google.material)
    implementation(libs.zxing.android.embedded)
    implementation(libs.kotlinx.coroutines.android)
    coreLibraryDesugaring(libs.desugarJdkLibs)
    compileOnly("org.projectlombok:lombok:1.18.24")
    annotationProcessor("org.projectlombok:lombok:1.18.24")
    kapt("org.projectlombok:lombok:1.18.24")
    kapt("com.squareup.moshi:moshi-kotlin-codegen:1.15.0") // example
}

tasks.withType<JavaCompile>().configureEach {
    options.compilerArgs.add("-Xlint:unchecked")
    options.isDeprecation = true
}

tasks.withType<KotlinCompile>().configureEach {
    compilerOptions.jvmTarget.set(JvmTarget.JVM_17)
}



