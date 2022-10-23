package org.openrewrite.java.security.secrets;

import com.nimbusds.jwt.JWTParser;
import org.openrewrite.ExecutionContext;
import org.openrewrite.Recipe;
import org.openrewrite.TreeVisitor;
import org.openrewrite.internal.lang.Nullable;

import java.text.ParseException;
import java.util.regex.Pattern;

public class FindJwtSecrets extends Recipe {

    @Override
    public String getDisplayName() {
        return "Find JWT secrets";
    }

    @Override
    public String getDescription() {
        return "Locates JWTs stored in plain text in code.";
    }

    @Override
    protected TreeVisitor<?, ExecutionContext> getVisitor() {
        return new FindSecretsVisitor("JWT") {
            private final Pattern valuePattern = Pattern.compile("eyJ[A-Za-z0-9-_=]+\\.[A-Za-z0-9-_=]+\\.?[A-Za-z0-9-_.+/=]*?");

            @Override
            protected boolean isSecret(@Nullable String key, @Nullable String value, ExecutionContext ctx) {
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
        };
    }
}
