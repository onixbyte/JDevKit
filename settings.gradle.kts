/*
 * Copyright (C) 2024-2025 OnixByte.
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

rootProject.name = "JDevKit"

include(
    "devkit-bom",
    "devkit-core",
    "devkit-utils",
    "guid",
    "key-pair-loader",
    "map-util-unsafe",
    "num4j",
    "simple-jwt",
    "simple-jwt-facade",
    "simple-jwt-authzero",
    "simple-jwt-spring-boot-starter",
    "property-guard-spring-boot-starter",
    "simple-serial-spring-boot-starter"
)

include("icalendar")