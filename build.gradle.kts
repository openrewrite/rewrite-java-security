import com.github.jk1.license.LicenseReportExtension
import nebula.plugin.contacts.Contact
import nebula.plugin.contacts.ContactsExtension
//import nl.javadude.gradle.plugins.license.LicenseExtension
import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
    `java-library`
    `maven-publish`
    signing

    id("org.jetbrains.kotlin.jvm") version "1.6.21"
    id("nebula.maven-resolved-dependencies") version "17.3.2"
    id("nebula.release") version "15.3.1"
    id("io.github.gradle-nexus.publish-plugin") version "1.0.0"

//    id("com.github.hierynomus.license") version "0.16.1"
    id("com.github.jk1.dependency-license-report") version "1.16"
    id("org.owasp.dependencycheck") version "latest.release"

    id("nebula.maven-publish") version "17.3.2"
    id("nebula.contacts") version "5.1.0"
    id("nebula.info") version "11.1.0"

    id("nebula.javadoc-jar") version "17.3.2"
    id("nebula.source-jar") version "17.3.2"
    id("nebula.maven-apache-license") version "17.3.2"

    id("org.openrewrite.rewrite") version "latest.release"
}

apply(plugin = "nebula.publish-verification")

rewrite {
    activeRecipe("org.openrewrite.java.format.AutoFormat", "org.openrewrite.java.cleanup.Cleanup")
}

configure<nebula.plugin.release.git.base.ReleasePluginExtension> {
    defaultVersionStrategy = nebula.plugin.release.NetflixOssStrategies.SNAPSHOT(project)
}

dependencyCheck {
    analyzers.nodeAuditEnabled = false
    analyzers.nodeEnabled = false
    analyzers.assemblyEnabled = false
    failBuildOnCVSS = 9.0F
    suppressionFile = "suppressions.xml"
    format = org.owasp.dependencycheck.reporting.ReportGenerator.Format.valueOf(project.properties["dependencyCheckFormat"] as String? ?: "HTML")
}

group = "org.openrewrite.recipe"
description = "Enforce logging best practices and migrate between logging frameworks. Automatically."

repositories {
    if (!project.hasProperty("releasing")) {
        mavenLocal()
        maven {
            url = uri("https://oss.sonatype.org/content/repositories/snapshots/")
        }
    }
    mavenCentral()
}

nexusPublishing {
    repositories {
        sonatype()
    }
}

signing {
    setRequired({
        !project.version.toString().endsWith("SNAPSHOT") || project.hasProperty("forceSigning")
    })
    val signingKey: String? by project
    val signingPassword: String? by project
    useInMemoryPgpKeys(signingKey, signingPassword)
    sign(publishing.publications["nebula"])
}

configurations.all {
    resolutionStrategy {
        cacheChangingModulesFor(0, TimeUnit.SECONDS)
        cacheDynamicVersionsFor(0, TimeUnit.SECONDS)
    }
}

val rewriteVersion = if (project.hasProperty("releasing")) {
    "latest.release"
} else {
    "latest.integration"
}

dependencies {
    compileOnly("org.projectlombok:lombok:latest.release")
    annotationProcessor("org.projectlombok:lombok:latest.release")

    implementation("org.openrewrite:rewrite-java:${rewriteVersion}")
    implementation("org.openrewrite:rewrite-maven:${rewriteVersion}")
    runtimeOnly("org.openrewrite:rewrite-java-11:${rewriteVersion}")

    runtimeOnly("org.springframework:spring-context:latest.release")
    runtimeOnly("org.springframework.security:spring-security-config:latest.release")
    runtimeOnly("org.springframework.security:spring-security-web:latest.release")
    runtimeOnly("jakarta.servlet:jakarta.servlet-api:4.+")

    // eliminates "unknown enum constant DeprecationLevel.WARNING" warnings from the build log
    // see https://github.com/gradle/kotlin-dsl-samples/issues/1301 for why (okhttp is leaking parts of kotlin stdlib)
    compileOnly("org.jetbrains.kotlin:kotlin-stdlib-jdk8")

    testImplementation("org.jetbrains.kotlin:kotlin-reflect")
    testImplementation("org.jetbrains.kotlin:kotlin-stdlib-jdk8")

    testImplementation("org.junit.jupiter:junit-jupiter-api:latest.release")
    testImplementation("org.junit.jupiter:junit-jupiter-params:latest.release")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:latest.release")

    testRuntimeOnly("org.springframework.boot:spring-boot-starter:latest.release")

    testImplementation("org.openrewrite:rewrite-test:${rewriteVersion}")

    testImplementation("org.assertj:assertj-core:latest.release")

    testRuntimeOnly("org.openrewrite:rewrite-java-11:${rewriteVersion}")
    testRuntimeOnly("org.openrewrite:rewrite-java-8:${rewriteVersion}")

    testRuntimeOnly("com.fasterxml.jackson.core:jackson-databind:latest.release")
}

tasks.withType(KotlinCompile::class.java).configureEach {
    kotlinOptions {
        jvmTarget = "1.8"
    }
}

tasks.named<Test>("test") {
    useJUnitPlatform()
    jvmArgs = listOf("-XX:+UnlockDiagnosticVMOptions", "-XX:+ShowHiddenFrames")
}

tasks.named<JavaCompile>("compileJava") {
    sourceCompatibility = JavaVersion.VERSION_1_8.toString()
    targetCompatibility = JavaVersion.VERSION_1_8.toString()

    options.isFork = true
    options.compilerArgs.addAll(listOf("--release", "8"))
    options.encoding = "UTF-8"
    options.compilerArgs.add("-parameters")
}


configure<ContactsExtension> {
    val j = Contact("team@moderne.io")
    j.moniker("Team Moderne")

    people["team@moderne.io"] = j
}

//configure<LicenseExtension> {
//    ext.set("year", Calendar.getInstance().get(Calendar.YEAR))
//    skipExistingHeaders = true
//    header = project.rootProject.file("gradle/licenseHeader.txt")
//    mapping(mapOf("kt" to "SLASHSTAR_STYLE", "java" to "SLASHSTAR_STYLE"))
//    exclude("src/main/resources/*.java")
//    strictCheck = true
//}

configure<LicenseReportExtension> {
    renderers = arrayOf(com.github.jk1.license.render.CsvReportRenderer())
}

configure<PublishingExtension> {
    publications {
        named("nebula", MavenPublication::class.java) {
            suppressPomMetadataWarningsFor("runtimeElements")
        }
    }
}
