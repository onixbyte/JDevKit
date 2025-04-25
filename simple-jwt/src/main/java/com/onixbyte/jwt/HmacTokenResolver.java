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
import com.onixbyte.jwt.data.RawToken;
import com.onixbyte.jwt.exception.SignatureVerificationException;
import com.onixbyte.jwt.util.CryptoUtil;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

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
public class HmacTokenResolver extends AbstractTokenResolver {

    private final byte[] secret;

    public HmacTokenResolver(Algorithm algorithm, String secret) {
        super(algorithm);

        // validate secret length
        var minSecretLength = algorithm.getShaLength() >> 3;
        var secretBytes = secret.getBytes(StandardCharsets.UTF_8);
        if (secretBytes.length < minSecretLength) {
            throw new IllegalArgumentException(String.format(
                    "Secret key too short for %s: minimum %d bytes required, got %d",
                    algorithm.name(), minSecretLength, secretBytes.length));
        }

        this.secret = secretBytes;
    }

    @Override
    protected void verifySignature(RawToken token) {
        try {
            var signatureBytes = Base64.getUrlDecoder().decode(token.signature());
            var valid = CryptoUtil.verifySignatureFor(algorithm, secret, token.header(), token.payload(), signatureBytes);

            if (!valid) {
                throw new SignatureVerificationException(
                        "Invalid signature for algorithm: " + algorithm);
            }
        } catch (IllegalArgumentException e) {
            throw new SignatureVerificationException(
                    "Failed to decode signature or verify token", e);
        }
    }
}
