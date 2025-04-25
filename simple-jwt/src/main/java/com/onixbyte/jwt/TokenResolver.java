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

package com.onixbyte.jwt;

import com.onixbyte.jwt.constant.RegisteredClaims;
import com.onixbyte.jwt.data.DecodedToken;
import com.onixbyte.jwt.data.RawToken;

import java.util.Map;

/**
 * Interface for resolving and verifying JSON Web Tokens (JWTs).
 * <p>
 * Defines a contract for implementations that parse, verify, and extract components from JWTs.
 * Provides methods to validate the token's signature, retrieve its header and payload, and split it
 * into raw components. Implementations are expected to handle cryptographic verification and JSON
 * deserialisation specific to their signing algorithm.
 *
 * @author zihluwang
 */
public interface TokenResolver {

    /**
     * Verifies the signature of the provided JWT.
     * <p>
     * Splits the token into its components and checks the signature's validity using the
     * implementation's configured algorithm and key. If the signature does not match, an exception
     * is thrown.
     *
     * @param token the JWT string to verify
     * @throws IllegalArgumentException if the token is malformed or the signature verification
     *                                  fails due to an invalid algorithm, key, or
     *                                  mismatched signature
     */
    DecodedToken verify(String token);

    /**
     * Splits a JWT into its raw components: header, payload, and signature.
     * <p>
     * Provides a default implementation that separates the token string into its three parts using
     * dot separators and returns them as a {@link RawToken}.
     *
     * @param token the JWT string to split
     * @return a {@link RawToken} containing the header, payload, and signature as strings
     * @throws IllegalArgumentException if the token does not consist of exactly three parts
     *                                  separated by dots
     */
    default RawToken splitToken(String token) {
        var tokenTuple = token.split("\\.");

        if (tokenTuple.length != 3) {
            throw new IllegalArgumentException(
                    "The provided JWT is invalid: it must consist of exactly three parts separated by dots.");
        }

        return new RawToken(tokenTuple[0], tokenTuple[1], tokenTuple[2]);
    }

}
