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

import com.onixbyte.jwt.constant.RegisteredClaims;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.*;

/**
 * A builder-style class for constructing JSON Web Token (JWT) payloads.
 * <p>
 * Provides a fluent interface to set standard registered claims (e.g., subject, issuer, audience)
 * and custom claims for a JWT payload. The class supports chaining method calls to build the
 * payload incrementally, which can then be retrieved as a map for use in JWT creation. Ensures that
 * registered claims are set using dedicated methods to prevent misuse.
 *
 * @author zihluwang
 */
public class TokenPayload {

    /**
     * Creates a new instance of {@link TokenPayload} with an empty payload.
     * <p>
     * Initialises the payload with empty collections for claims and audiences, ready for
     * configuration via the builder methods.
     *
     * @return a new {@link TokenPayload} instance
     */
    public static TokenPayload createPayload() {
        return new TokenPayload();
    }

    /**
     * The map storing custom claims for the JWT payload.
     */
    private final Map<String, Object> payload;

    /**
     * The list of audience identifiers for the JWT.
     */
    private final List<String> audiences;

    /**
     * The subject of the JWT, identifying the principal.
     */
    private String subject;

    /**
     * The issuer of the JWT, identifying the entity that issued the token.
     */
    private String issuer;

    /**
     * The unique identifier for the JWT.
     */
    private String tokenId;

    /**
     * The expiration time of the JWT, as seconds since the Unix epoch.
     */
    private Long expiresAt;

    /**
     * The time before which the JWT must not be accepted, as seconds since the Unix epoch.
     */
    private Long notBefore;

    /**
     * The issuance time of the JWT, as seconds since the Unix epoch.
     */
    private Long issuedAt;

    /**
     * Private constructor to enforce use of the factory method.
     * <p>
     * Initialises the internal collections for storing claims and audiences, preventing direct
     * instantiation outside the class.
     */
    private TokenPayload() {
        payload = new HashMap<>();
        audiences = new ArrayList<>();
    }

    /**
     * Adds a single audience to the JWT payload.
     * <p>
     * Appends the specified audience identifier to the list of audiences, allowing the token to be
     * validated for multiple recipients.
     *
     * @param audience the audience identifier to add
     * @return this {@link TokenPayload} instance for method chaining
     */
    public TokenPayload withAudience(String audience) {
        audiences.add(audience);
        return this;
    }

    /**
     * Adds multiple audiences to the JWT payload.
     * <p>
     * Appends all provided audience identifiers to the list of audiences, enabling the token to be
     * validated for multiple recipients.
     *
     * @param audiences the audience identifiers to add
     * @return this {@link TokenPayload} instance for method chaining
     */
    public TokenPayload withAudiences(String... audiences) {
        this.audiences.addAll(Arrays.asList(audiences));
        return this;
    }

    /**
     * Sets the subject of the JWT payload.
     * <p>
     * Specifies the principal that is the subject of the token, typically identifying the user or
     * entity the token represents.
     *
     * @param subject the subject identifier
     * @return this {@link TokenPayload} instance for method chaining
     */
    public TokenPayload withSubject(String subject) {
        this.subject = subject;
        return this;
    }

    /**
     * Sets the issuer of the JWT payload.
     * <p>
     * Specifies the entity that issued the token, allowing recipients to verify the token's origin.
     *
     * @param issuer the issuer identifier
     * @return this {@link TokenPayload} instance for method chaining
     */
    public TokenPayload withIssuer(String issuer) {
        this.issuer = issuer;
        return this;
    }

    /**
     * Sets the unique identifier for the JWT payload.
     * <p>
     * Assigns a unique token ID to the JWT, which can be used to prevent token reuse or for
     * tracking purposes.
     *
     * @param tokenId the unique token identifier
     * @return this {@link TokenPayload} instance for method chaining
     */
    public TokenPayload withTokenId(String tokenId) {
        this.tokenId = tokenId;
        return this;
    }

    /**
     * Sets the expiration time for the JWT payload.
     * <p>
     * Specifies when the token expires, converted to seconds since the Unix epoch based on the
     * system's default time zone.
     *
     * @param expiresAt the expiration time as a {@link LocalDateTime}
     * @return this {@link TokenPayload} instance for method chaining
     */
    public TokenPayload withExpiresAt(LocalDateTime expiresAt) {
        this.expiresAt = expiresAt.atZone(ZoneId.systemDefault())
                .toInstant()
                .getEpochSecond();
        return this;
    }

    /**
     * Sets the time before which the JWT must not be accepted.
     * <p>
     * Specifies the "not before" time, converted to seconds since the Unix epoch based on the
     * system's default time zone.
     *
     * @param notBefore the time before which the token is invalid, as a {@link LocalDateTime}
     * @return this {@link TokenPayload} instance for method chaining
     */
    public TokenPayload withNotBefore(LocalDateTime notBefore) {
        this.notBefore = notBefore.atZone(ZoneId.systemDefault())
                .toInstant()
                .getEpochSecond();
        return this;
    }

    /**
     * Sets the issuance time for the JWT payload.
     * <p>
     * Specifies when the token was issued, converted to seconds since the Unix epoch based on the
     * system's default time zone.
     *
     * @param issuedAt the issuance time as a {@link LocalDateTime}
     * @return this {@link TokenPayload} instance for method chaining
     */
    public TokenPayload withIssuedAt(LocalDateTime issuedAt) {
        this.issuedAt = issuedAt.atZone(ZoneId.systemDefault())
                .toInstant()
                .getEpochSecond();
        return this;
    }

    /**
     * Adds a custom claim to the JWT payload.
     * <p>
     * Stores a custom key-value pair in the payload, provided the key is not a registered claim.
     * Registered claims must be set using their dedicated methods to ensure proper handling.
     *
     * @param name  the name of the custom claim
     * @param value the value of the custom claim
     * @return this {@link TokenPayload} instance for method chaining
     * @throws IllegalStateException if the claim name is a registered claim
     */
    public TokenPayload withClaim(String name, String value) {
        checkClaimName(name);

        this.payload.put(name, value);
        return this;
    }

    /**
     * Adds a custom claim to the JWT payload.
     * <p>
     * Stores a custom key-value pair in the payload, provided the key is not a registered claim.
     * Registered claims must be set using their dedicated methods to ensure proper handling.
     *
     * @param name  the name of the custom claim
     * @param value the value of the custom claim
     * @return this {@link TokenPayload} instance for method chaining
     * @throws IllegalStateException if the claim name is a registered claim
     */
    public TokenPayload withClaim(String name, Long value) {
        checkClaimName(name);

        this.payload.put(name, value);
        return this;
    }

    /**
     * Adds a custom claim to the JWT payload.
     * <p>
     * Stores a custom key-value pair in the payload, provided the key is not a registered claim.
     * Registered claims must be set using their dedicated methods to ensure proper handling.
     *
     * @param name  the name of the custom claim
     * @param value the value of the custom claim
     * @return this {@link TokenPayload} instance for method chaining
     * @throws IllegalStateException if the claim name is a registered claim
     */
    public TokenPayload withClaim(String name, Double value) {
        checkClaimName(name);

        this.payload.put(name, value);
        return this;
    }

    /**
     * Adds a custom claim to the JWT payload.
     * <p>
     * Stores a custom key-value pair in the payload, provided the key is not a registered claim.
     * Registered claims must be set using their dedicated methods to ensure proper handling.
     *
     * @param name  the name of the custom claim
     * @param value the value of the custom claim
     * @return this {@link TokenPayload} instance for method chaining
     * @throws IllegalStateException if the claim name is a registered claim
     */
    public TokenPayload withClaim(String name, Boolean value) {
        checkClaimName(name);

        this.payload.put(name, value);
        return this;
    }

    /**
     * Adds a custom claim to the JWT payload.
     * <p>
     * Stores a custom key-value pair in the payload, provided the key is not a registered claim.
     * Registered claims must be set using their dedicated methods to ensure proper handling.
     *
     * @param name  the name of the custom claim
     * @param value the value of the custom claim
     * @return this {@link TokenPayload} instance for method chaining
     * @throws IllegalStateException if the claim name is a registered claim
     */
    public TokenPayload withClaim(String name, LocalDateTime value) {
        checkClaimName(name);

        this.payload.put(name, value);
        return this;
    }

    /**
     * Adds a custom claim with null value to the JWT payload.
     * <p>
     * Stores a custom key-value pair in the payload, provided the key is not a registered claim.
     * Registered claims must be set using their dedicated methods to ensure proper handling.
     *
     * @param name the name of the custom claim
     * @return this {@link TokenPayload} instance for method chaining
     * @throws IllegalStateException if the claim name is a registered claim
     */
    public TokenPayload withNullClaim(String name) {
        checkClaimName(name);

        this.payload.put(name, null);
        return this;
    }

    /**
     * Checks if the JWT payload has a valid issuer.
     * <p>
     * Returns {@code true} if the issuer is non-null and not blank, indicating that an issuer has
     * been set.
     *
     * @return {@code true} if an issuer is set, {@code false} otherwise
     */
    public boolean hasIssuer() {
        return Objects.nonNull(issuer) && !issuer.isBlank();
    }

    /**
     * Retrieves the complete JWT payload as a map.
     * <p>
     * Constructs a map containing all custom claims, registered claims (if set), and audiences.
     * Only non-empty or non-blank values are included to ensure a clean payload.
     *
     * @return a map containing the JWT payload
     */
    public Map<String, Object> getPayloadAsMap() {
        var _payload = new HashMap<>(payload);

        Optional.of(audiences)
                .filter((aud) -> !aud.isEmpty())
                .ifPresent((aud) -> _payload.put(RegisteredClaims.AUDIENCE, aud));
        Optional.ofNullable(subject)
                .filter((sub) -> !sub.isBlank())
                .ifPresent((sub) -> _payload.put(RegisteredClaims.SUBJECT, subject));
        Optional.ofNullable(expiresAt)
                .ifPresent((exp) -> _payload.put(RegisteredClaims.EXPIRES_AT, exp));
        Optional.ofNullable(tokenId)
                .filter((jti) -> !jti.isBlank())
                .ifPresent((jti) -> _payload.put(RegisteredClaims.TOKEN_ID, jti));
        Optional.ofNullable(issuer)
                .filter((iss) -> !iss.isBlank())
                .ifPresent((iss) -> _payload.put(RegisteredClaims.ISSUER, iss));
        Optional.ofNullable(issuedAt)
                .ifPresent((iat) -> _payload.put(RegisteredClaims.ISSUED_AT, iat));
        Optional.ofNullable(notBefore)
                .ifPresent((nbf) -> _payload.put(RegisteredClaims.NOT_BEFORE, nbf));

        return _payload;
    }

    /**
     * Check the given claim name, make sure the name will not be one of the registered claim name.
     *
     * @param name a claim name
     */
    private void checkClaimName(String name) {
        if (RegisteredClaims.VALUES.contains(name)) {
            throw new IllegalStateException("Please set registered claims with pre-defined methods");
        }
    }
}
