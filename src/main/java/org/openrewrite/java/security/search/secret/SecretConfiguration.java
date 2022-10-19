package org.openrewrite.java.security.search.secret;

import org.openrewrite.ExecutionContext;
import org.openrewrite.internal.lang.Nullable;

import java.util.List;

public interface SecretConfiguration {
    SecretFinder[] secretFinders();

    @Nullable
    default String findSecret(@Nullable String key, @Nullable String value, ExecutionContext ctx, @Nullable List<String> secretTypeFilter) {
        for (SecretFinder secretFinder : secretFinders()) {
            if (secretTypeFilter == null || secretTypeFilter.contains(secretFinder.getName())) {
                String secretName = secretFinder.findSecret(key, value, ctx);
                if (secretName != null) {
                    return secretName;
                }
            }
        }
        return null;
    }
}
