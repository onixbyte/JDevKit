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

import java.util.List;

/**
 * Utility class defining standard registered claim names for JSON Web Tokens (JWTs).
 * <p>
 * Provides constants representing the registered claims as defined in RFC 7519. These claims are
 * used in the payload section of a JWT to convey metadata about the token, such as its issuer,
 * subject, and validity period. All claims are optional but widely recognised in
 * JWT implementations.
 *
 * @author zihluwang
 */
public final class RegisteredClaims {

    /**
     * Private constructor to prevent instantiation of this utility class.
     */
    private RegisteredClaims() {
    }

    /**
     * The "iss" (issuer) claim identifies the principal that issued the JWT.
     * Refer RFC 7529 <a href="https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.1">Section 4.1.1</a>
     */
    public static final String ISSUER = "iss";

    /**
     * The "sub" (subject) claim identifies the principal that is the subject of the JWT.
     * Refer RFC 7529 <a href="https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.2">Section 4.1.2</a>
     */
    public static final String SUBJECT = "sub";

    /**
     * The "aud" (audience) claim identifies the recipients that the JWT is intended for.
     * Refer RFC 7529 <a href="https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.3">Section 4.1.3</a>
     */
    public static final String AUDIENCE = "aud";

    /**
     * The "exp" (expiration time) claim identifies the expiration time on or after which the JWT MUST NOT be
     * accepted for processing.
     * Refer RFC 7529 <a href="https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.4">Section 4.1.4</a>
     */
    public static final String EXPIRES_AT = "exp";

    /**
     * The "nbf" (not before) claim identifies the time before which the JWT MUST NOT be accepted for processing.
     * Refer RFC 7529 <a href="https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.5">Section 4.1.5</a>
     */
    public static final String NOT_BEFORE = "nbf";

    /**
     * The "iat" (issued at) claim identifies the time at which the JWT was issued.
     * Refer RFC 7529 <a href="https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.6">Section 4.1.6</a>
     */
    public static final String ISSUED_AT = "iat";

    /**
     * The "jti" (JWT ID) claim provides a unique identifier for the JWT.
     * Refer RFC 7529 <a href="https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.7">Section 4.1.7</a>
     */
    public static final String TOKEN_ID = "jti";

    /**
     * An immutable list of all registered claim names defined in this class.
     * <p>
     * Contains the values of {@link #ISSUER}, {@link #SUBJECT}, {@link #AUDIENCE},
     * {@link #EXPIRES_AT}, {@link #NOT_BEFORE}, {@link #ISSUED_AT}, and {@link #TOKEN_ID} for
     * convenient iteration or lookup.
     */
    public static final List<String> VALUES = List.of(ISSUER, SUBJECT, AUDIENCE, EXPIRES_AT, NOT_BEFORE, ISSUED_AT, TOKEN_ID);

}
