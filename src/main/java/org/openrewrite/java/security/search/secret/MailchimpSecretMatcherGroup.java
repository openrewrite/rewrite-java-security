package org.openrewrite.java.security.search.secret;

public class MailchimpSecretMatcherGroup implements SecretMatcherGroup {
    @Override
    public SecretMatcher[] secretMatchers() {
        return new SecretMatcher[0];
    }
}
