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

import com.onixbyte.jwt.constant.Algorithm;
import com.onixbyte.jwt.util.CryptoUtil;

import java.nio.charset.StandardCharsets;

/**
 * Implementation of token creator that generates HMAC-signed JSON Web Tokens (JWTs).
 * <p>
 * This class uses a specified HMAC algorithm to create signed tokens, validating
 * the secret key length meets minimum requirements for the chosen algorithm.
 *
 * @author zihluwang
 */
public class HmacTokenCreator extends AbstractTokenCreator {

    private final byte[] secret;

    /**
     * Constructs an HMAC token creator with the specified algorithm, issuer, and secret key.
     *
     * @param algorithm the HMAC algorithm to use for signing (e.g., HS256, HS384, HS512)
     * @param issuer    the issuer identifier to include in the token payload if not already present
     * @param secret    the secret key as a string, used to generate the HMAC signature
     * @throws IllegalArgumentException if the secret key is shorter than the minimum required
     *                                  length for the specified algorithm
     */
    public HmacTokenCreator(Algorithm algorithm, String issuer, String secret) {
        super(algorithm, issuer);

        var minSecretLength = algorithm.getShaLength() >> 3;
        var secretBytesLength = secret.getBytes(StandardCharsets.UTF_8).length;
        if (secretBytesLength < minSecretLength) {
            throw new IllegalArgumentException("Secret key too short for HS%d: minimum %d bytes required, got %d."
                    .formatted(algorithm.getShaLength(), minSecretLength, secretBytesLength)
            );
        }

        this.secret = secret.getBytes(StandardCharsets.UTF_8);
    }

    /**
     * Generates an HMAC signature for the given header and payload.
     *
     * @param encodedHeader  the Base64URL-encoded header bytes
     * @param encodedPayload the Base64URL-encoded payload bytes
     * @return the HMAC signature bytes
     */
    @Override
    protected byte[] generateSignature(byte[] encodedHeader, byte[] encodedPayload) {
        return CryptoUtil.createSignatureFor(algorithm, secret, encodedHeader, encodedPayload);
    }
}
