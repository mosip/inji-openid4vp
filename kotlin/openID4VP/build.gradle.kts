plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.jetbrains.kotlin.android)
    alias(libs.plugins.kotlin.serialization)
    id("maven-publish")
    id("signing")
    id("org.jetbrains.dokka") version "1.9.20"
    alias(libs.plugins.sonarqube)
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
    implementation(libs.nimbus.jose.jwt)
    implementation(libs.bouncyCastle)
    implementation(libs.identity.credential)
    implementation(libs.ld.signatures.java)
    implementation(libs.jsonld.common.java)
    implementation(libs.vcverifier)
    implementation(libs.bcpkix)
    implementation(libs.google.tink)
    implementation("com.augustcellars.cose:cose-java:1.1.0")

    testImplementation(libs.junit)
    testImplementation(libs.mockk)
    testImplementation(libs.mockwebserver)
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)
    testImplementation(libs.jupiter.junit)
    testImplementation(libs.assertj)
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
            xml.required = true
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
tasks.register<Jar>("javadocJar") {
    dependsOn("dokkaJavadoc")
    archiveClassifier.set("javadoc")
    from(tasks.named("dokkaHtml").get().outputs.files)
}
tasks.register<Jar>("sourcesJar") {
    archiveClassifier.set("sources")
    from(android.sourceSets["main"].java.srcDirs)
}
tasks.build {
    finalizedBy("jacocoTestReport")
}
tasks.register("prepareKotlinBuildScriptModel"){}
sonarqube {
    properties {
        property( "sonar.java.binaries", "build/intermediates/javac/debug")
        property( "sonar.language", "kotlin")
        property( "sonar.exclusions", "**/build/**, **/*.kt.generated, **/R.java, **/BuildConfig.java")
        property( "sonar.scm.disabled", "true")
        property( "sonar.coverage.jacoco.xmlReportPaths", "build/reports/jacoco/jacocoTestReport/jacocoTestReport.xml")
    }
}
tasks.withType<Jar>().configureEach {
    doLast {
        ant.withGroovyBuilder {
            "checksum"(
                "algorithm" to "md5",
                "file" to archiveFile.get().asFile
            )
            "checksum"(
                "algorithm" to "sha1",
                "file" to archiveFile.get().asFile
            )
        }
    }
}
apply {
    from("publish-artifact.gradle")
}