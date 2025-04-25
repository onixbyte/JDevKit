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

    public EcdsaTokenCreator(Algorithm algorithm, String issuer, ECPrivateKey privateKey) {
        super(algorithm, issuer);

        var _minKeyLength = algorithm.getShaLength();
        var keyLength = privateKey.getParams().getCurve().getField().getFieldSize();
        if (keyLength < _minKeyLength) {
            throw new IllegalArgumentException(
                    "EC key too small for ES%d: minimum %d bits required, got %d bits."
                            .formatted(algorithm.getShaLength(), _minKeyLength, keyLength)
            );
        }

        this.privateKey = privateKey;
    }

    @Override
    protected byte[] generateSignature(byte[] encodedHeader, byte[] encodedPayload) {
        try {
            return CryptoUtil.createSignatureFor(algorithm, privateKey, encodedHeader, encodedPayload);
        } catch (NoSuchAlgorithmException | SignatureException | InvalidKeyException e) {
            throw new RuntimeException("Failed to generate RSA signature", e);
        }
    }
}
