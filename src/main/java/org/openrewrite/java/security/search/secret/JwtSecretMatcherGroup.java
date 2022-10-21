package org.openrewrite.java.security.search.secret;

import java.text.ParseException;

import com.nimbusds.jwt.JWTParser;

/**
 * Uses <a href="https://github.com/felx/nimbus-jose-jwt">...</a> JWTParser for validating potential JWT Tokens
 * Less restrictive than <a href="https://github.com/Yelp/detect-secrets/blob/master/detect_secrets/plugins/jwt.py">...</a>
 */
public class JwtSecretMatcherGroup implements SecretMatcherGroup {

    @Override
    public SecretMatcher[] secretMatchers() {
        return new SecretMatcher[]{
                SecretMatcher.builder("JSON Web Token")
                        .valueRegex("eyJ[A-Za-z0-9-_=]+\\.[A-Za-z0-9-_=]+\\.?[A-Za-z0-9-_.+/=]*?")
                        .secretValidator((k, v, ctx) -> {
                            if (v != null) {
                                try {
                                    JWTParser.parse(v);
                                } catch (ParseException e) {
                                    return false;
                                }
                            }
                            return true;
                        })
                        .build()
        };
    }
}
