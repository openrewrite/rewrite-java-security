package org.openrewrite.java.security.secret;

import org.openrewrite.ExecutionContext;
import org.openrewrite.internal.lang.Nullable;

public interface SecretConfiguration {
    SecretFinder[] secretFinders();

    @Nullable
    default String findSecret(@Nullable String key, @Nullable String value, ExecutionContext ctx) {
        for (SecretFinder secretFinder : secretFinders()) {
            String secretName = secretFinder.findSecret(key, value, ctx);
            if (secretName != null) {
                return secretName;
            }
        }
        return null;
    }
}
