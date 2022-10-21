package org.openrewrite.java.security.search.secret;

import org.openrewrite.ExecutionContext;
import org.openrewrite.internal.lang.Nullable;

import java.util.regex.Pattern;


public class SecretRegexPredicate implements SecretPredicate<String, String, ExecutionContext> {
    private final Pattern keyPattern;
    private final Pattern valuePattern;
    public SecretRegexPredicate(@Nullable String keyRegex,@Nullable String valueRegex) {
        this.keyPattern = keyRegex != null ? Pattern.compile(keyRegex) : null;
        this.valuePattern = valueRegex != null ? Pattern.compile(valueRegex) : null;

    }

    @Override
    public boolean isSecret(@Nullable String key, @Nullable String value, ExecutionContext ctx) {
        boolean match = false;
        if (keyPattern != null && valuePattern != null) {
            match = key != null && keyPattern.matcher(key).find()
                && value != null && valuePattern.matcher(value).find();
        }
        else if (keyPattern != null) {
            match = key != null && keyPattern.matcher(key).find();
        }
        else if (valuePattern != null) {
            match = value != null && valuePattern.matcher(value).find();
        }
        return match;
    }
}
