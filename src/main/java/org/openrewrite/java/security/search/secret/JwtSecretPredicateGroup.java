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
