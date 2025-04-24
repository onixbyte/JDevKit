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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.onixbyte.jwt.constant.Algorithm;
import com.onixbyte.jwt.constant.RegisteredClaims;
import com.onixbyte.jwt.holder.ObjectMapperHolder;
import com.onixbyte.jwt.util.CryptoUtil;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

/**
 * Implementation of {@link TokenResolver} that resolves and verifies HMAC-signed JSON Web
 * Tokens (JWTs).
 * <p>
 * This class splits a JWT into its components, verifies its signature using an HMAC algorithm, and
 * deserialises the header and payload into usable data structures. It ensures the secret key meets
 * the minimum length requirement for the specified algorithm.
 *
 * @author zihluwang
 */
public class HmacTokenResolver implements TokenResolver {

    private final Algorithm algorithm;
    private final byte[] secret;

    private final ObjectMapper objectMapper;

    /**
     * Constructs an HMAC token resolver with the specified algorithm and secret key.
     * <p>
     * Validates that the secret key length meets the minimum requirement for the chosen algorithm.
     *
     * @param algorithm the HMAC algorithm used for signature verification (e.g., HS256,
     *                  HS384, HS512)
     * @param secret    the secret key as a string, used to verify the HMAC signature
     * @throws IllegalArgumentException if the secret key is shorter than the minimum required
     *                                  length for the specified algorithm
     */
    public HmacTokenResolver(Algorithm algorithm, String secret) {
        var _minSecretLength = algorithm.getShaLength() >> 3;
        var secretBytesLength = secret.getBytes(StandardCharsets.UTF_8).length;
        if (secretBytesLength < _minSecretLength) {
            throw new IllegalArgumentException("Secret key too short for HS%d: minimum %d bytes required, got %d"
                    .formatted(algorithm.getShaLength(), _minSecretLength, secretBytesLength)
            );
        }

        this.algorithm = algorithm;
        this.secret = secret.getBytes(StandardCharsets.UTF_8);
        this.objectMapper = ObjectMapperHolder.getInstance().getObjectMapper();
    }

    /**
     * Verifies the HMAC signature of the provided JWT.
     * <p>
     * Splits the token into its components and uses the configured algorithm and secret to check
     * the signature's validity. If the signature does not match, an exception is thrown by the
     * underlying cryptographic utility.
     *
     * @param token the JWT string to verify
     * @throws IllegalArgumentException if the token is malformed or the signature verification
     *                                  fails due to an invalid algorithm, key, or
     *                                  mismatched signature
     */
    @Override
    public void verify(String token) {
        var _token = splitToken(token);

        var isValid = CryptoUtil.verifySignatureFor(algorithm,
                secret,
                _token.header(),
                _token.payload(),
                _token.signature().getBytes(StandardCharsets.UTF_8)
        );
        if (!isValid) throw new IllegalArgumentException(
                "JWT signature verification failed: the token may be tampered with or invalid.");
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
        var _token = splitToken(token);

        var headerBytes = Base64.getDecoder().decode(_token.header());
        var headerJson = new String(headerBytes);

        try {
            return objectMapper.readValue(headerJson, new TypeReference<>() {
            });
        } catch (JsonProcessingException e) {
            throw new IllegalArgumentException(
                    "Failed to deserialise JWT header: the header JSON is invalid or malformed.", e
            );
        }
    }

    /**
     * Retrieves the payload claims from the provided JWT, excluding registered claims.
     * <p>
     * Decodes the Base64-encoded payload, deserialises it into a map, and removes any registered
     * claims as defined in {@link RegisteredClaims}.
     *
     * @param token the JWT string from which to extract the payload
     * @return a map containing the custom payload claims as key-value pairs
     * @throws IllegalArgumentException if the token is malformed or the payload cannot be
     *                                  deserialised due to invalid JSON format
     */
    @Override
    public Map<String, Object> getPayload(String token) {
        var _token = splitToken(token);

        var payloadBytes = Base64.getDecoder().decode(_token.payload());
        var payloadJson = new String(payloadBytes);

        try {
            var payloadMap = objectMapper.readValue(payloadJson, new TypeReference<Map<String, Object>>() {
            });

            payloadMap.keySet().removeIf(RegisteredClaims.VALUES::contains);
            return payloadMap;
        } catch (JsonProcessingException e) {
            throw new IllegalArgumentException(
                    "Failed to deserialise JWT payload: the payload JSON is invalid or malformed.", e
            );
        }
    }
}
