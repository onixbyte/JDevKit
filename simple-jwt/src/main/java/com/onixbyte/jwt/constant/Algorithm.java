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

package com.onixbyte.jwt.constant;

/**
 * Enumeration of cryptographic algorithms supported for JSON Web Token (JWT) signing
 * and verification.
 * <p>
 * Defines a set of recognised algorithms including HMAC (HS*), RSA (RS*), and ECDSA (ES*) variants,
 * each with a specific SHA length (256, 384, or 512 bits). Provides methods to identify the
 * algorithm type and retrieve its properties.
 *
 * @author zihluwang
 */
public enum Algorithm {
    HS256(1, 256, "HmacSHA256"),
    HS384(1, 384, "HmacSHA384"),
    HS512(1, 512, "HmacSHA512"),
    RS256(2, 256, "SHA256withRSA"),
    RS384(2, 384, "SHA384withRSA"),
    RS512(2, 512, "SHA512withRSA"),
    ES256(3, 256, "SHA256withECDSA"),
    ES384(3, 384, "SHA384withECDSA"),
    ES512(3, 512, "SHA512withECDSA");

    /**
     * Bit flag indicating an HMAC-based algorithm.
     */
    private static final int HS_FLAG = 1; // 001

    /**
     * Bit flag indicating an RSA-based algorithm.
     */
    private static final int RS_FLAG = 2; // 010

    /**
     * Bit flag indicating an ECDSA-based algorithm.
     */
    private static final int ES_FLAG = 3; // 011

    /**
     * The type flag identifying the algorithm family (HMAC, RSA, or ECDSA).
     */
    private final int typeFlag;

    /**
     * The length of the SHA hash in bits (256, 384, or 512).
     */
    private final int shaLength;

    /**
     * The standard name of the algorithm as recognised by the Java Cryptography Architecture (JCA).
     */
    private final String algorithm;

    /**
     * Constructs an algorithm enum constant with the specified type flag, SHA length, and algorithm name.
     *
     * @param typeFlag  the bit flag identifying the algorithm type
     * @param shaLength the length of the SHA hash in bits
     * @param algorithm the JCA-compliant algorithm name
     */
    Algorithm(int typeFlag, int shaLength, String algorithm) {
        this.typeFlag = typeFlag;
        this.shaLength = shaLength;
        this.algorithm = algorithm;
    }

    /**
     * Determines whether this algorithm is HMAC-based.
     *
     * @return {@code true} if the algorithm uses HMAC (e.g., HS256, HS384, HS512), {@code false} otherwise
     */
    public boolean isHmac() {
        return (this.typeFlag & HS_FLAG) != 0;
    }

    /**
     * Determines whether this algorithm is RSA-based.
     *
     * @return {@code true} if the algorithm uses RSA (e.g., RS256, RS384, RS512), {@code false} otherwise
     */
    public boolean isRsa() {
        return (this.typeFlag & RS_FLAG) != 0;
    }

    /**
     * Determines whether this algorithm is ECDSA-based.
     *
     * @return {@code true} if the algorithm uses ECDSA (e.g., ES256, ES384, ES512), {@code false} otherwise
     */
    public boolean isEcdsa() {
        return (this.typeFlag & ES_FLAG) != 0;
    }

    /**
     * Retrieves the SHA length of this algorithm in bits.
     *
     * @return the SHA length (256, 384, or 512)
     */
    public int getShaLength() {
        return shaLength;
    }

    /**
     * Retrieves the type flag of this algorithm.
     *
     * @return the type flag (1 for HMAC, 2 for RSA, 3 for ECDSA)
     */
    public int getTypeFlag() {
        return typeFlag;
    }

    /**
     * Retrieves the JCA-compliant name of this algorithm.
     *
     * @return the algorithm name (e.g., "HmacSHA256", "SHA256withRSA")
     */
    public String getAlgorithm() {
        return algorithm;
    }
}
