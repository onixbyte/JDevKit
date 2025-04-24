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

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.interfaces.ECPrivateKey;

public class EcdsaTokenCreator extends AbstractTokenCreator {

    private final ECPrivateKey privateKey;

    /**
     * Constructs an RSA token creator with the specified algorithm, issuer, and private key.
     *
     * @param algorithm  the RSA algorithm to use for signing (e.g., RS256, RS384, RS512)
     * @param issuer     the issuer identifier to include in the token payload if not already present
     * @param privateKey the private key, used to generate the RSA signature
     * @throws IllegalArgumentException if the key is shorter than the minimum required
     *                                 length for the specified algorithm
     */
    public EcdsaTokenCreator(Algorithm algorithm, String issuer, ECPrivateKey privateKey) {
        super(algorithm, issuer);

        var minKeyBitLength = algorithm.getShaLength();
        var keyBitLength = privateKey.getParams().getCurve().getField().getFieldSize();
        if (keyBitLength < minKeyBitLength) {
            throw new IllegalArgumentException(
                    "EC key too small for ES%d: minimum %d bits required, got %d bits."
                            .formatted(algorithm.getShaLength(), minKeyBitLength, keyBitLength)
            );
        }

        this.privateKey = privateKey;
    }

    /**
     * Generates an RSA signature for the given header and payload.
     *
     * @param encodedHeader  the Base64URL-encoded header bytes
     * @param encodedPayload the Base64URL-encoded payload bytes
     * @return the RSA signature bytes
     * @throws RuntimeException if signature generation fails due to cryptographic errors
     */
    @Override
    protected byte[] generateSignature(byte[] encodedHeader, byte[] encodedPayload) {
        try {
            return CryptoUtil.createSignatureFor(algorithm, privateKey, encodedHeader, encodedPayload);
        } catch (NoSuchAlgorithmException | SignatureException | InvalidKeyException e) {
            throw new RuntimeException("Failed to generate RSA signature", e);
        }
    }
}
