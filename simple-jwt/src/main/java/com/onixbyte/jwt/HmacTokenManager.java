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

import com.onixbyte.devkit.utils.MapUtil;
import com.onixbyte.devkit.utils.ObjectMapAdapter;
import com.onixbyte.jwt.constant.Algorithm;
import com.onixbyte.jwt.data.DecodedToken;
import com.onixbyte.jwt.data.RawToken;

import java.util.Map;

/**
 * A generic token manager implementation for creating, verifying, and extracting data from
 * HMAC-signed JSON Web Tokens (JWTs).
 * <p>
 * This class integrates an {@link HmacTokenCreator} for signing tokens and an
 * {@link HmacTokenResolver} for verification and parsing, using a specified HMAC algorithm. It
 * supports converting token payloads to a custom type {@code T} via an {@link ObjectMapAdapter}.
 *
 * @param <T> the type of object to which the token payload will be converted
 * @author zihluwang
 */
public class HmacTokenManager<T> implements TokenManager<T> {

    private final TokenCreator tokenCreator;
    private final TokenResolver tokenResolver;
    private final ObjectMapAdapter<T> adapter;

    /**
     * Constructs an HMAC token manager with the specified algorithm, issuer, secret, and adapter.
     * <p>
     * Initialises the {@link TokenCreator} and {@link TokenResolver} with the provided HMAC
     * algorithm and secret key, and associates an adapter for converting token payloads to the
     * generic type {@code T}.
     *
     * @param algorithm the HMAC algorithm to use for signing and verification
     * @param issuer    the issuer identifier to include in the token payload if not already present
     * @param secret    the secret key as a string, used to sign and verify the HMAC signature
     * @param adapter   the {@link ObjectMapAdapter} for converting payload maps to objects of
     *                  type {@code T}
     * @throws IllegalArgumentException if the secret key is too short for the specified algorithm
     */
    public HmacTokenManager(Algorithm algorithm, String issuer, String secret, ObjectMapAdapter<T> adapter) {
        this.tokenCreator = new HmacTokenCreator(algorithm, issuer, secret);
        this.tokenResolver = new HmacTokenResolver(algorithm, secret);
        this.adapter = adapter;
    }

    /**
     * Extracts the payload from a JWT and converts it to an object of type {@code T}.
     * <p>
     * Retrieves the payload as a map and uses the configured {@link ObjectMapAdapter} to transform
     * it into the desired type.
     *
     * @param token the JWT string from which to extract the payload
     * @return the payload converted to an object of type {@code T}
     * @throws IllegalArgumentException if the token is malformed, the signature is invalid, or the
     *                                  payload cannot be deserialised
     */
    @Override
    public T extract(String token) {
        var payloadMap = getPayload(token);
        return MapUtil.mapToObject(payloadMap, adapter);
    }

    /**
     * Signs a token payload to create a JWT.
     * <p>
     * Delegates to the {@link TokenCreator} to generate a signed JWT string from the
     * provided payload.
     *
     * @param payload the {@link TokenPayload} containing claims to include in the token
     * @return the signed JWT as a string in the format "header.payload.signature"
     * @throws IllegalArgumentException if the payload cannot be serialised to JSON due to invalid
     *                                  data or structure
     */
    @Override
    public String sign(TokenPayload payload) {
        return tokenCreator.sign(payload);
    }

    /**
     * Verifies the validity of a JWT.
     * <p>
     * Delegates to the {@link TokenResolver} to check the token's signature and structure.
     *
     * @param token the JWT string to verify
     * @throws IllegalArgumentException if the token is malformed or the signature
     *                                  verification fails
     */
    @Override
    public DecodedToken verify(String token) {
        return tokenResolver.verify(token);
    }

    @Override
    public Map<String, String> getHeader(RawToken token) {
        return tokenResolver.getHeader(token);
    }

    /**
     * Retrieves the header claims from the provided JWT.
     * <p>
     * Decodes the Base64-encoded header and deserialises it into a map of strings.
     *
     * @param token the JWT string from which to extract the header
     * @return a map containing the header claims as key-value pairs
     * @throws IllegalArgumentException if the token is malformed or the header cannot be
     *                                  deserialised due to invalid JSON format
     */
    @Override
    public Map<String, String> getHeader(String token) {
        return tokenResolver.getHeader(token);
    }

    @Override
    public Map<String, Object> getPayload(RawToken token) {
        return tokenResolver.getPayload(token);
    }

    /**
     * Retrieves the payload claims from a JWT.
     * <p>
     * Delegates to the {@link TokenResolver} to extract and deserialise the payload into a map,
     * excluding registered claims.
     *
     * @param token the JWT string from which to extract the payload
     * @return a map containing the custom payload claims as key-value pairs
     * @throws IllegalArgumentException if the token is malformed or the payload cannot
     *                                  be deserialised
     */
    @Override
    public Map<String, Object> getPayload(String token) {
        return tokenResolver.getPayload(token);
    }
}
