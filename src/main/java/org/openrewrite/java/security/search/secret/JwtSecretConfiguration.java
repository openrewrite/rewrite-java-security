package org.openrewrite.java.security.search.secret;

import java.text.ParseException;

import com.nimbusds.jwt.JWTParser;

/**
 * Uses <a href="https://github.com/felx/nimbus-jose-jwt">...</a> JWTParser for validating potential JWT Tokens
 * Less restrictive than <a href="https://github.com/Yelp/detect-secrets/blob/master/detect_secrets/plugins/jwt.py">...</a>
 */
public class JwtSecretConfiguration implements SecretConfiguration {

    @Override
    public SecretFinder[] secretFinders() {
        return new SecretFinder[]{
                SecretFinder.builder("JSON Web Token")
                        .valuePattern("eyJ[A-Za-z0-9-_=]+\\.[A-Za-z0-9-_=]+\\.?[A-Za-z0-9-_.+/=]*?")
                        .valueVerifier((k, v, ctx) -> {
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
