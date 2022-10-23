package org.openrewrite.java.security.secrets;

import lombok.EqualsAndHashCode;
import lombok.Value;
import org.openrewrite.*;
import org.openrewrite.internal.lang.Nullable;

import java.util.regex.Pattern;

@Value
@EqualsAndHashCode(callSuper = false)
public class FindSecretsByPattern extends Recipe {
    @Option(
            displayName = "Name",
            description = "The type of secret that this recipe is looking for.",
            example = "AWS Access Key"
    )
    String name;

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

    public FindSecretsByPattern(String name, @Nullable String keyPattern, String valuePattern) {
        this.name = name;
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
    protected TreeVisitor<?, ExecutionContext> getVisitor() {
        Pattern keyPatternCompiled = keyPattern == null ? null : Pattern.compile(keyPattern);
        Pattern valuePatternCompiled = Pattern.compile(valuePattern);

        return new FindSecretsVisitor(name) {
            @Override
            protected boolean isSecret(@Nullable String key, @Nullable String value, ExecutionContext ctx) {
                return (keyPatternCompiled == null || (key != null && keyPatternCompiled.matcher(key).find())) &&
                       value != null && valuePatternCompiled.matcher(value).find();
            }
        };
    }
}
