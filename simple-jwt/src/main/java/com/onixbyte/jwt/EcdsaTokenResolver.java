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
import com.onixbyte.jwt.util.EcdsaSignatureUtil;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.interfaces.ECPublicKey;
import java.util.Base64;

public class EcdsaTokenResolver extends AbstractTokenResolver {

    private final ECPublicKey publicKey;

    public EcdsaTokenResolver(Algorithm algorithm, ECPublicKey publicKey) {
        super(algorithm);

        // validate key size
        var minKeyLength = algorithm.getShaLength() >> 3;
        var keyLength = publicKey.getParams().getCurve().getField().getFieldSize();
        if (keyLength < minKeyLength) {
            throw new IllegalArgumentException(String.format(
                    "EC key too small for %s: minimum %d bits required, got %d bits",
                    algorithm, minKeyLength, keyLength));
        }

        this.publicKey = publicKey;
    }

    @Override
    protected void verifySignature(RawToken token) {
        try {
            var signatureBytes = Base64.getUrlDecoder().decode(token.signature());

            // Validate signature structure before conversion
            EcdsaSignatureUtil.validateSignatureStructure(signatureBytes, publicKey, algorithm.getShaLength());

            // Convert JOSE to DER format
            var derSignature = EcdsaSignatureUtil.convertJoseToDer(signatureBytes, algorithm.getShaLength());

            // Verify signature
            var valid = CryptoUtil.verifySignatureFor(
                    algorithm, publicKey, token.header(), token.payload(), derSignature);

            if (!valid) {
                throw new SignatureVerificationException(
                        "Invalid signature for algorithm: " + algorithm);
            }
        } catch (NoSuchAlgorithmException | SignatureException | InvalidKeyException | IllegalArgumentException e) {
            throw new SignatureVerificationException(
                    "Failed to verify ECDSA signature with algorithm: " + algorithm, e);
        }
    }
}
