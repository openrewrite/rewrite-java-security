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
