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

package com.onixbyte.jwt.constant;

/**
 * Utility class defining standard header claim names for JSON Web Tokens (JWTs).
 * <p>
 * Provides constants representing the recognised header claims as specified in the JWT standard.
 * These claims are used in the header section of a JWT to describe its structure and cryptographic
 * properties.
 *
 * @author zihluwang
 */
public final class HeaderClaims {

    /**
     * Private constructor to prevent instantiation of this utility class.
     */
    private HeaderClaims() {
    }

    /**
     * The algorithm used to sign a JWT.
     */
    public static final String ALGORITHM = "alg";

    /**
     * The content type of the JWT.
     */
    public static final String CONTENT_TYPE = "cty";

    /**
     * The media type of the JWT.
     */
    public static final String TYPE = "typ";

    /**
     * The key ID of a JWT used to specify the key for signature validation.
     */
    public static final String KEY_ID = "kid";

}
