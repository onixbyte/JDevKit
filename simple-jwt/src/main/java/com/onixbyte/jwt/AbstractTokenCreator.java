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
import com.fasterxml.jackson.databind.ObjectMapper;
import com.onixbyte.jwt.constant.Algorithm;
import com.onixbyte.jwt.constant.HeaderClaims;
import com.onixbyte.jwt.holder.ObjectMapperHolder;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;

/**
 * Abstract base class for JWT token creators that handles common functionality.
 * <p>
 * This class implements common token creation logic including header preparation, payload
 * processing, and final token assembly. Concrete subclasses need to implement the signature
 * generation logic specific to their algorithm.
 *
 * @author zihluwang
 */
public abstract class AbstractTokenCreator implements TokenCreator {

    protected final Algorithm algorithm;
    protected final String issuer;
    protected final ObjectMapper objectMapper;

    /**
     * Constructs a token creator with the specified algorithm and issuer.
     *
     * @param algorithm the algorithm to use for signing
     * @param issuer    the issuer identifier to include in the token payload if not already present
     */
    protected AbstractTokenCreator(Algorithm algorithm, String issuer) {
        this.algorithm = algorithm;
        this.issuer = issuer;
        this.objectMapper = ObjectMapperHolder.getInstance().getObjectMapper();
    }

    /**
     * Creates and signs a JWT using the configured algorithm.
     *
     * @param payload the {@link TokenPayload} containing claims to include in the token
     * @return the signed JWT as a string in the format "header.payload.signature"
     * @throws IllegalArgumentException if the payload cannot be serialized to JSON
     * @throws RuntimeException         if an unexpected error occurs during processing
     */
    @Override
    public String sign(TokenPayload payload) {
        var header = new HashMap<String, String>();

        header.put(HeaderClaims.ALGORITHM, algorithm.name());
        if (!header.containsKey(HeaderClaims.TYPE)) {
            header.put(HeaderClaims.TYPE, "JWT");
        }

        if (!payload.hasIssuer()) {
            payload.withIssuer(issuer);
        }

        try {
            var encodedHeader = Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(objectMapper.writeValueAsBytes(header));
            var encodedPayload = Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(objectMapper.writeValueAsBytes(payload.getPayloadAsMap()));

            byte[] headerBytes = encodedHeader.getBytes(StandardCharsets.UTF_8);
            byte[] payloadBytes = encodedPayload.getBytes(StandardCharsets.UTF_8);

            byte[] signatureBytes = generateSignature(headerBytes, payloadBytes);
            var signature = Base64.getUrlEncoder()
                    .withoutPadding()
                    .encodeToString(signatureBytes);

            return "%s.%s.%s".formatted(encodedHeader, encodedPayload, signature);
        } catch (JsonProcessingException e) {
            throw new IllegalArgumentException("Failed to serialize token header or payload to JSON.", e);
        }
    }

    /**
     * Generates a signature for the given header and payload using the algorithm-specific approach.
     *
     * @param encodedHeader  the Base64URL-encoded header bytes
     * @param encodedPayload the Base64URL-encoded payload bytes
     * @return the signature bytes
     * @throws RuntimeException if signature generation fails
     */
    protected abstract byte[] generateSignature(byte[] encodedHeader, byte[] encodedPayload);
}
