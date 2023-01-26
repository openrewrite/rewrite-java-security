plugins {
    id("org.openrewrite.build.recipe-library") version "latest.release"
}

group = "org.openrewrite.recipe"
description = "Enforce logging best practices and migrate between logging frameworks. Automatically."

val rewriteVersion = if (project.hasProperty("releasing")) {
    "latest.release"
} else {
    "latest.integration"
}

dependencies {
    compileOnly("org.projectlombok:lombok:latest.release")
    annotationProcessor("org.projectlombok:lombok:latest.release")

    implementation(platform("org.openrewrite:rewrite-bom:${rewriteVersion}"))
    implementation("org.openrewrite:rewrite-java")
    implementation("org.openrewrite:rewrite-maven")
    implementation("org.openrewrite:rewrite-yaml")
    implementation("org.openrewrite:rewrite-xml")
    implementation("com.nimbusds:nimbus-jose-jwt:9.+")

    runtimeOnly("org.openrewrite:rewrite-java-17")
    runtimeOnly("org.springframework:spring-context:5.+")
    runtimeOnly("org.springframework.security:spring-security-config:5.+")
    runtimeOnly("org.springframework.security:spring-security-web:5.+")
    runtimeOnly("jakarta.servlet:jakarta.servlet-api:4.+")

    testImplementation("org.junit.jupiter:junit-jupiter-api:latest.release")
    testImplementation("org.junit.jupiter:junit-jupiter-params:latest.release")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:latest.release")

    testRuntimeOnly("org.springframework.boot:spring-boot-starter:2.+")

    testImplementation("org.openrewrite:rewrite-test:${rewriteVersion}")
    testImplementation("org.openrewrite:rewrite-java-tck:${rewriteVersion}")

    testImplementation("org.assertj:assertj-core:latest.release")

    testRuntimeOnly("org.openrewrite:rewrite-java-17:${rewriteVersion}")
    testRuntimeOnly("junit:junit:latest.release")

    testRuntimeOnly("com.fasterxml.jackson.core:jackson-databind:2.13.4")
}
