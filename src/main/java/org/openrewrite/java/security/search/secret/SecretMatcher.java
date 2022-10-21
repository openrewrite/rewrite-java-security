package org.openrewrite.java.security.search.secret;

import org.openrewrite.ExecutionContext;
import org.openrewrite.internal.StringUtils;
import org.openrewrite.internal.lang.Nullable;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SecretMatcher {
    private final String secretName;
    @Nullable
    private final Pattern keyPattern;
    @Nullable
    private final Pattern valuePattern;
    private final SecretValidator secretValidator;

    private SecretMatcher(String secretName, @Nullable Pattern keyPattern, @Nullable Pattern valuePattern, SecretValidator secretValidator) {
        this.secretName = secretName;
        this.keyPattern = keyPattern;
        this.valuePattern = valuePattern;
        this.secretValidator = secretValidator;
    }

    public String getSecretName() {
        return secretName;
    }

    @FunctionalInterface
    interface SecretValidator {
        boolean isSecret(@Nullable String key, @Nullable String value, ExecutionContext ctx);
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
            if (foundKey != null && foundValue != null && secretValidator.isSecret(foundKey, foundValue, ctx)) {
                return secretName;
            }
        } else if (keyPattern != null && foundKey != null && secretValidator.isSecret(foundKey, null, ctx)) {
            return secretName;
        } else if (valuePattern != null && foundValue != null && secretValidator.isSecret(null, foundValue, ctx)) {
            return secretName;
        }
        return null;
    }

    public static Builder builder(String secretName) {
        return new Builder(secretName);
    }

    public static class Builder {
        private final String secretName;
        private Pattern keyPattern = null;
        private Pattern valuePattern = null;
        private SecretValidator secretValidator = (key, value, ctx) -> true;

        Builder(String secretName) {
            this.secretName = secretName;
        }

        SecretMatcher build() {
            return new SecretMatcher(secretName, keyPattern, valuePattern, secretValidator);
        }

        Builder keyRegex(String keyRegex) {
            if (!StringUtils.isNullOrEmpty(keyRegex)) {
                this.keyPattern = Pattern.compile(keyRegex);
            }
            return this;
        }

        Builder valueRegex(String valueRegex) {
            if (!StringUtils.isNullOrEmpty(valueRegex)) {
                this.valuePattern = Pattern.compile(valueRegex);
            }
            return this;
        }

        Builder secretValidator(SecretValidator secretValidator) {
            this.secretValidator = secretValidator;
            return this;
        }
    }
}
