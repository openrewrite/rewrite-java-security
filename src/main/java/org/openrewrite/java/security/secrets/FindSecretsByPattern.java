/*
 * Copyright 2022 the original author or authors.
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
package org.openrewrite.java.security.secrets;

import lombok.EqualsAndHashCode;
import lombok.Value;
import org.jspecify.annotations.Nullable;
import org.openrewrite.*;

import java.util.regex.Pattern;

@Value
@EqualsAndHashCode(callSuper = false)
public class FindSecretsByPattern extends Recipe {
    @Option(
            displayName = "Name",
            description = "The type of secret that this recipe is looking for.",
            example = "AWS Access Key"
    )
    String secretName;

    @Option(displayName = "Key pattern",
            description = "A regular expression to match a 'key' against. For example, a key ",
            example = "[a-zA-Z0-9+\\/=]{88}",
            required = false
    )
    @Nullable
    String keyPattern;

    @Option(displayName = "Value pattern",
            description = "A regular expression to search for.",
            example = "[a-zA-Z0-9+\\/=]{88}"
    )
    String valuePattern;

    public FindSecretsByPattern(String secretName, @Nullable String keyPattern, String valuePattern) {
        this.secretName = secretName;
        this.keyPattern = keyPattern;
        this.valuePattern = valuePattern;
    }

    @Override
    public Validated validate() {
        return super.validate()
                .and(Validated.test("keyPattern", "Must be a valid regular expression", keyPattern, p -> {
                    try {
                        if (keyPattern == null) {
                            return true;
                        }
                        Pattern.compile(keyPattern);
                        return true;
                    } catch (Exception e) {
                        return false;
                    }
                }))
                .and(Validated.test("valuePattern", "Must be a valid regular expression", valuePattern, p -> {
                    try {
                        Pattern.compile(valuePattern);
                        return true;
                    } catch (Exception e) {
                        return false;
                    }
                }));
    }

    @Override
    public String getDisplayName() {
        return "Find secrets with regular expressions";
    }

    @Override
    public String getDescription() {
        return "A secret is a literal that matches any one of the provided patterns.";
    }

    @Override
    public TreeVisitor<?, ExecutionContext> getVisitor() {
        Pattern keyPatternCompiled = keyPattern == null ? null : Pattern.compile(keyPattern);
        Pattern valuePatternCompiled = Pattern.compile(valuePattern);

        return new FindSecretsVisitor(secretName) {
            @Override
            protected boolean isSecret(@Nullable String key, @Nullable String value, ExecutionContext ctx) {
                return (keyPatternCompiled == null || (key != null && keyPatternCompiled.matcher(key).find())) &&
                       value != null && valuePatternCompiled.matcher(value).find();
            }
        };
    }
}
