package org.openrewrite.java.security.search.secret;

class NpmSecretMatcherGroup implements SecretMatcherGroup {
    @Override
    public SecretMatcher[] secretMatchers() {
        return new SecretMatcher[]{
                SecretMatcher.builder("NPM Token")
                        .valuePattern("\\/\\/.+\\/:_authToken=\\s*((npm_.+)|([A-Fa-f0-9-]{36})).*")
                        .build()
        };
    }
}
