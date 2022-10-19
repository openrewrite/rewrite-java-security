package org.openrewrite.java.security.search.secret;

class NpmSecretConfiguration implements SecretConfiguration {
    @Override
    public SecretFinder[] secretFinders() {
        return new SecretFinder[]{
                SecretFinder.builder("NPM Token")
                        .valuePattern("\\/\\/.+\\/:_authToken=\\s*((npm_.+)|([A-Fa-f0-9-]{36})).*")
                        .build()
        };
    }
}
