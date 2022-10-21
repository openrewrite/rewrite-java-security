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
