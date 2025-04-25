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

import com.onixbyte.jwt.data.DecodedToken;
import com.onixbyte.jwt.data.RawToken;

import java.util.Map;

public class EcdsaTokenManager<T> implements TokenManager<T> {



    @Override
    public T extract(String token) {
        return null;
    }

    @Override
    public String sign(TokenPayload payload) {
        return "";
    }

    @Override
    public DecodedToken verify(String token) {
        return null;
    }

    @Override
    public Map<String, String> getHeader(RawToken token) {
        return Map.of();
    }

    @Override
    public Map<String, String> getHeader(String token) {
        return Map.of();
    }

    @Override
    public Map<String, Object> getPayload(RawToken token) {
        return Map.of();
    }

    @Override
    public Map<String, Object> getPayload(String token) {
        return Map.of();
    }
}
