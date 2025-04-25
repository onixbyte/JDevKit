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

import java.math.BigInteger;
import java.security.SignatureException;
import java.security.interfaces.ECPublicKey;

/**
 * Utility class for handling ECDSA signature format conversions between JOSE and DER.
 *
 * @author siujamo
 */
public final class EcdsaSignatureUtil {

    /**
     * Private constructor to prevent instantiation of this utility class.
     */
    private EcdsaSignatureUtil() {
    }

    /**
     * Converts a signature from JOSE format to DER format.
     *
     * @param joseSignature the signature in JOSE format
     * @param shaLength     the SHA length (e.g., 256, 384, 512)
     * @return the signature in DER format
     * @throws SignatureException if the JOSE signature is invalid
     */
    public static byte[] convertJoseToDer(byte[] joseSignature, int shaLength) throws SignatureException {
        final int ecNumberSize = shaLength >> 3;

        // Retrieve R and S number's length and padding
        int rPadding = countPadding(joseSignature, 0, ecNumberSize);
        int sPadding = countPadding(joseSignature, ecNumberSize, joseSignature.length);
        int rLength = ecNumberSize - rPadding;
        int sLength = ecNumberSize - sPadding;
        int length = 2 + rLength + 2 + sLength;
        // Create DER signature array with correct size
        final byte[] derSignature;
        int offset;
        if (length > 0x7f) {
            derSignature = new byte[3 + length];
            derSignature[1] = (byte) 0x81;
            offset = 2;
        } else {
            derSignature = new byte[2 + length];
            offset = 1;
        }
        // DER Structure: http://crypto.stackexchange.com/a/1797
        // Header with signature length info
        derSignature[0] = (byte) 0x30;
        derSignature[offset++] = (byte) (length & 0xff);
        // Header with "min R" number length
        derSignature[offset++] = (byte) 0x02;
        derSignature[offset++] = (byte) rLength;
        // R number
        if (rPadding < 0) {
            // Sign
            derSignature[offset++] = (byte) 0x00;
            System.arraycopy(joseSignature, 0, derSignature, offset, ecNumberSize);
            offset += ecNumberSize;
        } else {
            int copyLength = Math.min(ecNumberSize, rLength);
            System.arraycopy(joseSignature, rPadding, derSignature, offset, copyLength);
            offset += copyLength;
        }
        // Header with "min S" number length
        derSignature[offset++] = (byte) 0x02;
        derSignature[offset++] = (byte) sLength;
        // S number
        if (sPadding < 0) {
            // Sign
            derSignature[offset++] = (byte) 0x00;
            System.arraycopy(joseSignature, ecNumberSize, derSignature, offset, ecNumberSize);
        } else {
            System.arraycopy(joseSignature, ecNumberSize + sPadding, derSignature, offset,
                    Math.min(ecNumberSize, sLength));
        }
        return derSignature;
    }

    /**
     * Validates the structure of a JOSE signature.
     *
     * @param joseSignature the signature in JOSE format
     * @param publicKey     the EC public key
     * @param shaLength     the SHA length (e.g., 256, 384, 512)
     * @throws SignatureException if the signature structure is invalid
     */
    public static void validateSignatureStructure(byte[] joseSignature, ECPublicKey publicKey, int shaLength)
            throws SignatureException {
        final var ecNumberSize = shaLength >> 3;

        // check signature length
        if (joseSignature.length != ecNumberSize * 2) {
            throw new SignatureException("Invalid JOSE signature format: incorrect length");
        }
        // check if signature is all zeros
        if (isAllZeros(joseSignature)) {
            throw new SignatureException("Invalid signature format: all zeros");
        }
        // extract R and S components
        var rBytes = new byte[ecNumberSize];
        System.arraycopy(joseSignature, 0, rBytes, 0, ecNumberSize);
        if (isAllZeros(rBytes)) {
            throw new SignatureException("Invalid signature format: R component is all zeros");
        }
        var sBytes = new byte[ecNumberSize];
        System.arraycopy(joseSignature, ecNumberSize, sBytes, 0, ecNumberSize);
        if (isAllZeros(sBytes)) {
            throw new SignatureException("Invalid signature format: S component is all zeros");
        }
        // check resulting DER length
        var rPadding = countPadding(joseSignature, 0, ecNumberSize);
        var sPadding = countPadding(joseSignature, ecNumberSize, joseSignature.length);
        var rLength = ecNumberSize - rPadding;
        var sLength = ecNumberSize - sPadding;
        var length = 2 + rLength + 2 + sLength;
        if (length > 255) {
            throw new SignatureException("Invalid JOSE signature format: resulting DER too large");
        }
        // verify R and S are less than curve order
        var order = publicKey.getParams().getOrder();
        var r = new BigInteger(1, rBytes);
        var s = new BigInteger(1, sBytes);
        if (order.compareTo(r) < 1) {
            throw new SignatureException("Invalid signature format: R >= curve order");
        }
        if (order.compareTo(s) < 1) {
            throw new SignatureException("Invalid signature format: S >= curve order");
        }
    }

    /**
     * Counts padding bytes at the beginning of a section of the byte array.
     */
    private static int countPadding(byte[] bytes, int fromIndex, int toIndex) {
        var padding = 0;
        while (fromIndex + padding < toIndex && bytes[fromIndex + padding] == 0) {
            padding++;
        }
        return (fromIndex + padding < toIndex && (bytes[fromIndex + padding] & 0xff) > 0x7f) ?
                padding - 1 : padding;
    }

    /**
     * Checks if a byte array consists entirely of zeros.
     */
    private static boolean isAllZeros(byte[] bytes) {
        for (var b : bytes) {
            if (b != 0) {
                return false;
            }
        }
        return true;
    }
}
