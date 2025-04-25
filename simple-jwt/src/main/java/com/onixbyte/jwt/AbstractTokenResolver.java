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
import com.onixbyte.jwt.constant.HeaderClaims;
import com.onixbyte.jwt.constant.RegisteredClaims;
import com.onixbyte.jwt.data.DecodedToken;
import com.onixbyte.jwt.data.RawToken;
import com.onixbyte.jwt.exception.AlgorithmMismatchException;
import com.onixbyte.jwt.exception.InvalidTokenException;
import com.onixbyte.jwt.exception.TokenDecodingException;
import com.onixbyte.jwt.holder.ObjectMapperHolder;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Base64;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

public abstract class AbstractTokenResolver implements TokenResolver {

    protected final Algorithm algorithm;
    protected final ObjectMapper objectMapper;

    public AbstractTokenResolver(Algorithm algorithm) {
        this.algorithm = algorithm;
        this.objectMapper = ObjectMapperHolder.getInstance().getObjectMapper();
    }

    @Override
    public DecodedToken verify(String token) {
        RawToken rawToken = splitToken(token);

        try {
            // decode header and payload
            Map<String, String> decodedHeader = decodeHeader(rawToken.header());
            Map<String, Object> decodedPayload = decodePayload(rawToken.payload());

            // compose decoded token
            var decodedToken = DecodedToken.builder()
                    .header(decodedHeader)
                    .payload(decodedPayload)
                    .build();

            // verify signature based on algorithm
            verifyAlgorithm(decodedToken, algorithm);
            verifySignature(rawToken);
            verifyClaims(decodedToken);

            return decodedToken;
        } catch (JsonProcessingException e) {
            throw new TokenDecodingException("Failed to decode JWT components", e);
        }
    }

    protected Map<String, String> decodeHeader(String encodedHeader) throws JsonProcessingException {
        byte[] headerBytes = Base64.getUrlDecoder().decode(encodedHeader);
        String headerJson = new String(headerBytes, StandardCharsets.UTF_8);
        return objectMapper.readValue(headerJson, new TypeReference<>() {
        });
    }

    protected Map<String, Object> decodePayload(String encodedPayload) throws JsonProcessingException {
        byte[] payloadBytes = Base64.getUrlDecoder().decode(encodedPayload);
        String payloadJson = new String(payloadBytes, StandardCharsets.UTF_8);
        return objectMapper.readValue(payloadJson, new TypeReference<>() {
        });
    }

    protected void verifyAlgorithm(DecodedToken token, Algorithm expectedAlgorithm) {
        var algorithmValue = token.header().get(HeaderClaims.ALGORITHM);
        if (algorithmValue == null) {
            throw new AlgorithmMismatchException("No algorithm found in token header");
        }

        try {
            Algorithm tokenAlgorithm = Algorithm.valueOf(algorithmValue.toUpperCase());
            if (tokenAlgorithm != expectedAlgorithm) {
                throw new AlgorithmMismatchException(
                        "Algorithm mismatch - Expected: " + expectedAlgorithm + ", Found: " + tokenAlgorithm);
            }
        } catch (IllegalArgumentException e) {
            throw new AlgorithmMismatchException("Unknown algorithm in token: " + algorithmValue);
        }
    }

    protected void verifyClaims(DecodedToken token) {
        var claims = token.payload();

        // get current time
        var now = LocalDateTime.now()
                .atZone(ZoneId.systemDefault())
                .toInstant();

        // check not before
        var _notBefore = claims.get(RegisteredClaims.NOT_BEFORE);
        if (Objects.nonNull(_notBefore)) {
            if (_notBefore instanceof Long notBefore) {
                var nbfInstant = Instant.ofEpochSecond(notBefore);
                if (nbfInstant.isBefore(now)) { // token not active
                    throw new InvalidTokenException("The provided token is not valid yet.");
                }
            } else { // illegal format
                throw new InvalidTokenException("The 'not before' claim must be a numeric value representing seconds since the Unix epoch.");
            }
        }

        // check expire after
        var _expireAfter = claims.get(RegisteredClaims.EXPIRES_AT);
        if (Objects.nonNull(_expireAfter)) {
            if (_expireAfter instanceof Long expireAfter) {
                var expInstant = Instant.ofEpochSecond(expireAfter);
                if (expInstant.isAfter(now)) { // token expired
                    throw new InvalidTokenException("The provided token is expired.");
                }
            } else { // illegal format
                throw new IllegalArgumentException("The 'expire after' claim must be a numeric value representing seconds since the Unix epoch.");
            }
        }
    }

    /**
     * Verifies the signature of the token (to be implemented by subclasses).
     */
    protected abstract void verifySignature(RawToken token);
}
