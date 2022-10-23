/*
 * Copyright 2021 the original author or authors.
 * <p>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 * https://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.openrewrite.java.security.search.secret;

import org.openrewrite.internal.lang.Nullable;

import java.util.Objects;

@FunctionalInterface
public interface SecretPredicate<K, V, ExecutionContext> {

    boolean isSecret(@Nullable K key,@Nullable V value, ExecutionContext ctx);

    default SecretPredicate<K, V, ExecutionContext> and(SecretPredicate<K, V, ExecutionContext> other) {
        Objects.requireNonNull(other);
        return (K k, V v, ExecutionContext ctx) -> isSecret(k, v, ctx) && other.isSecret(k, v, ctx);
    }

    default SecretPredicate<K, V, ExecutionContext> or(SecretPredicate<K, V, ExecutionContext> other) {
        Objects.requireNonNull(other);
        return (K k, V v, ExecutionContext ctx) -> isSecret(k, v, ctx) || other.isSecret(k, v, ctx);
    }

    default SecretPredicate<K, V, ExecutionContext> negate(SecretPredicate<K, V, ExecutionContext> other) {
        Objects.requireNonNull(other);
        return (K k, V v, ExecutionContext ctx) -> !isSecret(k, v, ctx);
    }
}
