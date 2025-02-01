plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.jetbrains.kotlin.android)
    alias(libs.plugins.kotlin.serialization)
    id("maven-publish")
    id("signing")
    jacoco
}

jacoco {
    toolVersion = "0.8.11"
    reportsDirectory = layout.buildDirectory.dir("reports/jacoco")
}

android {
    namespace = "io.mosip.openid4vp"
    compileSdk = 34

    defaultConfig {
        minSdk = 23

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        consumerProguardFiles("consumer-rules.pro")
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    java {
        toolchain {
            languageVersion = JavaLanguageVersion.of(17)
        }
    }

    kotlinOptions {
        jvmTarget = "17"
    }
}

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.jetbrains.kotlinx.serialization.json)
    implementation(libs.okhttp3)
    implementation(libs.commons.codec)
    implementation(libs.jackson.module.kotlin)
    implementation(libs.jackson.databind)
    implementation(libs.jackson.core)
    implementation(libs.jackson.annotations)
    implementation (libs.nimbus.jose.jwt)
    implementation(libs.bouncyCastle)

    testImplementation(libs.junit)
    testImplementation(libs.mockk)
    testImplementation(libs.mockwebserver)
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)
    testImplementation(libs.jupiter.junit)
}

tasks {
    register<JacocoReport>("jacocoTestReport") {
        dependsOn(
            listOf(
                "testDebugUnitTest",
                "compileReleaseUnitTestKotlin",
                "testReleaseUnitTest"
            )
        )

        reports {
            html.required = true
        }
        sourceDirectories.setFrom(layout.projectDirectory.dir("src/main/java"))
        classDirectories.setFrom(
            files(
                fileTree(layout.buildDirectory.dir("intermediates/javac/debug")),
                fileTree(layout.buildDirectory.dir("tmp/kotlin-classes/debug"))
            )
        )
        executionData.setFrom(files(
            fileTree(layout.buildDirectory) { include(listOf("**/testDebug**.exec")) }
        ))

    }

    register<Wrapper>("wrapper") {
        gradleVersion = "8.6"
        setProperty("validateDistributionUrl", true)
    }
}

tasks.build {
    finalizedBy("jacocoTestReport")
}

apply {
    from("publish-artifact.gradle")
}