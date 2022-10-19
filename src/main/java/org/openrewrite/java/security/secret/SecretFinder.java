package org.openrewrite.java.security.secret;

import org.openrewrite.ExecutionContext;
import org.openrewrite.internal.StringUtils;
import org.openrewrite.internal.lang.Nullable;

import java.util.function.BiPredicate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SecretFinder {
    private final String name;
    @Nullable
    private final Pattern keyPattern;
    @Nullable
    private final Pattern valuePattern;
    private final BiPredicate<String, ExecutionContext> keyPredicate;
    private final BiPredicate<String, ExecutionContext> valuePredicate;

    private SecretFinder(String name, @Nullable Pattern keyPattern, @Nullable Pattern valuePattern, BiPredicate<String, ExecutionContext> keyPredicate, BiPredicate<String, ExecutionContext> valuePredicate) {
        this.name = name;
        this.keyPattern = keyPattern;
        this.valuePattern = valuePattern;
        this.keyPredicate = keyPredicate;
        this.valuePredicate = valuePredicate;
    }
    
    @Nullable
    public String findSecret(@Nullable String key, @Nullable String value, ExecutionContext ctx) {
        String foundKey = null;
        String foundValue = null;
        if (keyPattern != null && !StringUtils.isNullOrEmpty(key)) {
            Matcher keyMatcher = keyPattern.matcher(key);
            if (keyMatcher.find()) {
                foundKey = keyMatcher.group();
                if (!keyPredicate.test(foundKey, ctx)) {
                    foundKey = null;
                }
            }
        }
        if (valuePattern != null && !StringUtils.isNullOrEmpty(value)) {
            Matcher valueMatcher = valuePattern.matcher(value);
            if (valueMatcher.find()) {
                foundValue = valueMatcher.group();
                if (!valuePredicate.test(foundValue, ctx)) {
                    foundValue = null;
                }
            }
        }
        if (keyPattern != null && valuePattern != null) {
            if (foundKey != null && foundValue != null) {
                return name;
            }
        } else if (keyPattern != null && foundKey != null) {
            return name;
        } else if (valuePattern != null && foundValue != null) {
            return name;
        }
        return null;
    }

    public static Builder builder(String name) {
        return new Builder(name);
    }

    public static class Builder {
        private final String name;
        private Pattern keyPattern = null;
        private Pattern valuePattern = null;
        private BiPredicate<String, ExecutionContext> keyVerifier = (s, ctx) -> true;
        private BiPredicate<String, ExecutionContext> valueVerifier = (s, ctx) -> true;

        Builder(String name) {
            this.name = name;
        }

        SecretFinder build() {
            return new SecretFinder(name, keyPattern, valuePattern, keyVerifier, valueVerifier);
        }

        Builder keyPattern(String keyPattern) {
            if (!StringUtils.isNullOrEmpty(keyPattern)) {
                this.keyPattern = Pattern.compile(keyPattern);
            }
            return this;
        }

        Builder valuePattern(String valuePattern) {
            if (!StringUtils.isNullOrEmpty(valuePattern)) {
                this.valuePattern = Pattern.compile(valuePattern);
            }
            return this;
        }

        Builder keyVerifier(BiPredicate<String, ExecutionContext> keyVerifier) {
            this.keyVerifier = keyVerifier;
            return this;
        }

        Builder valueVerifier(BiPredicate<String, ExecutionContext> valueVerifier) {
            this.valueVerifier = valueVerifier;
            return this;
        }
    }
}
