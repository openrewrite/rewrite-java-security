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

import com.nimbusds.jwt.JWTParser;
import org.openrewrite.ExecutionContext;
import org.openrewrite.internal.lang.Nullable;

import java.text.ParseException;
import java.util.Collections;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Uses <a href="https://github.com/felx/nimbus-jose-jwt">...</a> JWTParser for validating potential JWT Tokens
 * Less restrictive than <a href="https://github.com/Yelp/detect-secrets/blob/master/detect_secrets/plugins/jwt.py">...</a>
 */
public class JwtSecretPredicateGroup implements SecretPredicateGroup {
    @Override
    public String getName() {
        return "JSON Web Token";
    }

    @Override
    public List<SecretPredicate<String, String, ExecutionContext>> secretPredicates() {
        return Collections.singletonList(new SecretPredicate<String, String, ExecutionContext>() {
            private final Pattern valuePattern = Pattern.compile("eyJ[A-Za-z0-9-_=]+\\.[A-Za-z0-9-_=]+\\.?[A-Za-z0-9-_.+/=]*?");

            @Override
            public boolean isSecret(@Nullable String key, @Nullable String value, ExecutionContext ctx) {
                if (value != null && valuePattern.matcher(value).find()) {
                    try {
                        JWTParser.parse(value);
                    } catch (ParseException e) {
                        return false;
                    }
                    return true;
                }
                return false;
            }
        });
    }
}
