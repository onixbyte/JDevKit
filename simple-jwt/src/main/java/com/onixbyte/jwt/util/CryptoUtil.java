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

package com.onixbyte.jwt.util;

import com.onixbyte.jwt.constant.Algorithm;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;

/**
 * Utility class for cryptographic operations related to JWT processing.
 * <p>
 * Provides methods for creating and verifying signatures using specified algorithms, primarily for
 * JSON Web Token (JWT) authentication purposes.
 *
 * @author zihluwang
 */
public final class CryptoUtil {

    /**
     * Private constructor to prevent instantiation of this utility class.
     */
    private CryptoUtil() {
    }

    private static final byte JWT_PART_SEPARATOR = (byte) 46;

    /**
     * Creates a signature for the given header and payload using the specified algorithm
     * and secret.
     *
     * @param algorithm the cryptographic algorithm to use (e.g., HMAC-SHA256)
     * @param secret    the secret key bytes used for signing
     * @param header    the header bytes to include in the signature
     * @param payload   the payload bytes to include in the signature
     * @return the generated signature bytes
     * @throws IllegalArgumentException if the algorithm is not supported or the key is invalid
     */
    public static byte[] createSignatureFor(
            Algorithm algorithm,
            byte[] secret,
            byte[] header,
            byte[] payload) {
        try {
            final var mac = Mac.getInstance(algorithm.getAlgorithm());
            mac.init(new SecretKeySpec(secret, algorithm.getAlgorithm()));
            mac.update(header);
            mac.update(JWT_PART_SEPARATOR);
            return mac.doFinal(payload);
        } catch (InvalidKeyException e) {
            throw new IllegalArgumentException("The provided secret key is invalid for the algorithm '%s'."
                    .formatted(algorithm.getAlgorithm()), e);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException("The specified algorithm '%s' is not supported."
                    .formatted(algorithm.getAlgorithm()), e);
        }
    }

    /**
     * Create signature for JWT header and payload using a private key.
     *
     * @param algorithm    algorithm name.
     * @param privateKey   the private key to use for signing.
     * @param headerBytes  JWT header.
     * @param payloadBytes JWT payload.
     * @return the signature bytes.
     * @throws NoSuchAlgorithmException if the algorithm is not supported.
     * @throws InvalidKeyException      if the given key is inappropriate for initializing the
     *                                  specified algorithm.
     * @throws SignatureException       if this signature object is not initialized properly or
     *                                  if this signature algorithm is unable to process the input
     *                                  data provided.
     */
    public static byte[] createSignatureFor(
            Algorithm algorithm,
            PrivateKey privateKey,
            byte[] headerBytes,
            byte[] payloadBytes
    ) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        final var s = Signature.getInstance(algorithm.getAlgorithm());
        s.initSign(privateKey);
        s.update(headerBytes);
        s.update(JWT_PART_SEPARATOR);
        s.update(payloadBytes);
        return s.sign();
    }

    /**
     * Verifies the signature for the given header and payload using the specified algorithm
     * and secret.
     * <p>
     * This method converts the header and payload strings to UTF-8 bytes before verification.
     *
     * @param algorithm      the cryptographic algorithm used for signing
     * @param secretBytes    the secret key bytes used for signing
     * @param header         the header string to verify
     * @param payload        the payload string to verify
     * @param signatureBytes the signature bytes to check against
     * @return {@code true} if the signature is valid, {@code false} otherwise
     * @throws IllegalArgumentException if the algorithm is not supported or the key is invalid
     */
    public static boolean verifySignatureFor(
            Algorithm algorithm,
            byte[] secretBytes,
            String header,
            String payload,
            byte[] signatureBytes) {
        return verifySignatureFor(
                algorithm,
                secretBytes,
                header.getBytes(StandardCharsets.UTF_8),
                payload.getBytes(StandardCharsets.UTF_8),
                signatureBytes);
    }

    /**
     * Verifies the signature for the given header and payload bytes using the specified algorithm
     * and secret.
     *
     * @param algorithm      the cryptographic algorithm used for signing
     * @param secretBytes    the secret key bytes used for signing
     * @param headerBytes    the header bytes to verify
     * @param payloadBytes   the payload bytes to verify
     * @param signatureBytes the signature bytes to check against
     * @return {@code true} if the signature matches, {@code false} otherwise
     * @throws IllegalArgumentException if the algorithm is not supported or the key is invalid
     */
    public static boolean verifySignatureFor(
            Algorithm algorithm,
            byte[] secretBytes,
            byte[] headerBytes,
            byte[] payloadBytes,
            byte[] signatureBytes) {
        return MessageDigest.isEqual(
                createSignatureFor(
                        algorithm,
                        secretBytes,
                        headerBytes,
                        payloadBytes),
                signatureBytes);
    }

}
