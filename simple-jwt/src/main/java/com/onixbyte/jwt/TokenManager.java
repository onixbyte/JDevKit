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

/**
 * Interface for managing JSON Web Tokens (JWTs) with support for signing, verification, and
 * payload extraction.
 * <p>
 * Combines the functionality of {@link TokenCreator} for creating signed JWTs and
 * {@link TokenResolver} for verifying and parsing them, while adding the ability to extract the
 * payload as a custom type {@code T}. Implementations are expected to handle both token generation
 * and resolution, providing a unified interface for JWT operations.
 *
 * @param <T> the type of object to which the token payload will be converted
 * @author zihluwang
 */
public interface TokenManager<T> extends TokenCreator, TokenResolver {

    /**
     * Extracts the payload from a JWT and converts it to an object of type {@code T}.
     * <p>
     * Retrieves the payload from the token and transforms it into the specified type using an
     * implementation-specific mechanism, such as an adapter or mapper.
     *
     * @param token the JWT string from which to extract the payload
     * @return the payload converted to an object of type {@code T}
     * @throws IllegalArgumentException if the token is malformed, the signature is invalid, or the
     *                                  payload cannot be deserialised or converted to
     *                                  type {@code T}
     */
    T extract(String token);
}