/*
 * Copyright (C) 2024-2024 OnixByte.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
import java.net.URI

plugins {
    java
    id("java-library")
    id("maven-publish")
    id("signing")
}

val artefactVersion: String by project
val projectUrl: String by project
val projectGithubUrl: String by project
val licenseName: String by project
val licenseUrl: String by project

group = "com.onixbyte"
version = artefactVersion

repositories {
    mavenCentral()
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
    withSourcesJar()
    withJavadocJar()
}

tasks.withType<JavaCompile> {
    options.encoding = "UTF-8"
}

tasks.withType<Jar> {
    exclude("logback.xml")
}

dependencies {
    val slf4jVersion: String by project
    val logbackVersion: String by project
    val junitVersion: String by project
    val jacksonVersion: String by project
    val javaJwtVersion: String by project

    compileOnly("org.slf4j:slf4j-api:$slf4jVersion")
    implementation("ch.qos.logback:logback-classic:$logbackVersion")

    implementation(project(":devkit-utils"))
    implementation(project(":guid"))
    implementation(project(":key-pair-loader"))
    implementation(project(":simple-jwt-facade"))
    implementation("com.fasterxml.jackson.core:jackson-databind:$jacksonVersion")
    implementation("com.auth0:java-jwt:$javaJwtVersion")

    testCompileOnly("org.slf4j:slf4j-api:$slf4jVersion")
    testImplementation("org.junit.jupiter:junit-jupiter:$junitVersion")
}

tasks.test {
    useJUnitPlatform()
}

publishing {
    publications {
        create<MavenPublication>("simpleJwtAuthzero") {
            groupId = group.toString()
            artifactId = "simple-jwt-authzero"
            version = artefactVersion

            pom {
                name = "Simple JWT :: Auth0"
                description = "Simple JWT implemented with com.auth0:java-jwt."
                url = projectUrl

                licenses {
                    license {
                        name = licenseName
                        url = licenseUrl
                    }
                }

                scm {
                    connection = "scm:git:git://github.com:OnixByte/JDevKit.git"
                    developerConnection = "scm:git:git://github.com:OnixByte/JDevKit.git"
                    url = projectGithubUrl
                }

                developers {
                    developer {
                        id = "zihluwang"
                        name = "Zihlu Wang"
                        email = "really@zihlu.wang"
                        timezone = "Asia/Hong_Kong"
                    }
                }
            }

            from(components["java"])

            signing {
                sign(publishing.publications["simpleJwtAuthzero"])
            }
        }

        repositories {
            maven {
                name = "sonatypeNexus"
                url = URI(providers.gradleProperty("repo.maven-central.host").get())
                credentials {
                    username = providers.gradleProperty("repo.maven-central.username").get()
                    password = providers.gradleProperty("repo.maven-central.password").get()
                }
            }
        }
    }
}