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

package com.onixbyte.jwt.data;

import com.onixbyte.jwt.constant.Algorithm;
import com.onixbyte.jwt.constant.HeaderClaims;
import com.onixbyte.jwt.constant.RegisteredClaims;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

public record DecodedToken(
        Map<String, String> header,
        Map<String, Object> payload
) {

    public static DecodedTokenBuilder builder() {
        return new DecodedTokenBuilder();
    }

    public static class DecodedTokenBuilder {
        private Map<String, String> header;
        private Map<String, Object> payload;

        private DecodedTokenBuilder() {
        }

        public DecodedTokenBuilder header(Map<String, String> header) {
            this.header = header;
            return this;
        }

        public DecodedTokenBuilder payload(Map<String, Object> payload) {
            this.payload = payload;
            return this;
        }

        public DecodedToken build() {
            return new DecodedToken(header, payload);
        }
    }

    public Algorithm getAlgorithm() {
        return Optional.ofNullable(header)
                .map((_header) -> _header.get(HeaderClaims.ALGORITHM))
                .map(Algorithm::valueOf)
                .orElse(null);
    }

    public String getSubject() {
        return Optional.ofNullable(payload)
                .map((_payload) -> _payload.get(RegisteredClaims.SUBJECT))
                .map(DecodedToken::safeConvertObjectToString)
                .orElse(null);
    }

    public String getIssuer() {
        return Optional.ofNullable(payload)
                .map((_payload) -> _payload.get(RegisteredClaims.ISSUER))
                .map(DecodedToken::safeConvertObjectToString)
                .orElse(null);
    }

    public LocalDateTime getNotBefore() {
        return Optional.ofNullable(payload)
                .map((_payload) -> _payload.get(RegisteredClaims.NOT_BEFORE))
                .map(DecodedToken::safeConvertNumberToLocalDateTime)
                .orElse(null);
    }

    public Map<String, Object> getClaims() {
        var customClaims = new HashMap<>(payload);
        RegisteredClaims.VALUES.forEach(customClaims::remove);
        return customClaims;
    }

    public Object getClaim(String name) {
        return payload.get(name);
    }

    public <T> T getClaim(String name, Class<T> targetType) {
        var claim = payload.get(name);
        if (targetType.isInstance(claim)) {
            return targetType.cast(claim);
        } else {
            return null;
        }
    }

    private static LocalDateTime safeConvertNumberToLocalDateTime(Object object) {
        if (object instanceof Long timestamp) {
            return LocalDateTime.ofInstant(Instant.ofEpochSecond(timestamp), ZoneId.systemDefault());
        } else {
            return null;
        }
    }

    private static String safeConvertObjectToString(Object object) {
        if (object instanceof String str) {
            return str;
        } else {
            return null;
        }
    }
}
