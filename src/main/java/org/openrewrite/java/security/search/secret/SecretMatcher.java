package org.openrewrite.java.security.search.secret;

import org.openrewrite.ExecutionContext;
import org.openrewrite.internal.StringUtils;
import org.openrewrite.internal.lang.Nullable;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SecretMatcher {
    private final String name;
    @Nullable
    private final Pattern keyPattern;
    @Nullable
    private final Pattern valuePattern;
    private final SecretValidator secretValidator;

    private SecretMatcher(String name, @Nullable Pattern keyPattern, @Nullable Pattern valuePattern, SecretValidator secretValidator) {
        this.name = name;
        this.keyPattern = keyPattern;
        this.valuePattern = valuePattern;
        this.secretValidator = secretValidator;
    }

    public String getName() {
        return name;
    }

    @FunctionalInterface
    interface SecretValidator {
        boolean isValid(@Nullable String key, @Nullable String value, ExecutionContext ctx);
    }
    
    @Nullable
    public String matches(@Nullable String key, @Nullable String value, ExecutionContext ctx) {
        String foundKey = null;
        String foundValue = null;
        if (keyPattern != null && !StringUtils.isNullOrEmpty(key)) {
            Matcher keyMatcher = keyPattern.matcher(key);
            if (keyMatcher.find()) {
                foundKey = keyMatcher.group();
            }
        }
        if (valuePattern != null && !StringUtils.isNullOrEmpty(value)) {
            Matcher valueMatcher = valuePattern.matcher(value);
            if (valueMatcher.find()) {
                foundValue = valueMatcher.group();
            }
        }
        if (keyPattern != null && valuePattern != null) {
            if (foundKey != null && foundValue != null && secretValidator.isValid(foundKey, foundValue, ctx)) {
                return name;
            }
        } else if (keyPattern != null && foundKey != null && secretValidator.isValid(foundKey, null, ctx)) {
            return name;
        } else if (valuePattern != null && foundValue != null && secretValidator.isValid(null, foundValue, ctx)) {
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
        private SecretValidator secretValidator = (key, value, ctx) -> true;

        Builder(String name) {
            this.name = name;
        }

        SecretMatcher build() {
            return new SecretMatcher(name, keyPattern, valuePattern, secretValidator);
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

        Builder valueVerifier(SecretValidator secretValidator) {
            this.secretValidator = secretValidator;
            return this;
        }
    }
}
