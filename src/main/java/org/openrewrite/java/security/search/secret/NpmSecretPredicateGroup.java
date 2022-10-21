package org.openrewrite.java.security.search.secret;

import org.openrewrite.ExecutionContext;

class NpmSecretPredicateGroup implements SecretPredicateGroup {
    @Override
    public String getName() {
        return "NPM Token";
    }

    @Override
    public SecretPredicate<String, String, ExecutionContext> secretPredicate() {
        return new SecretRegexPredicate(null, "\\/\\/.+\\/:_authToken=\\s*((npm_.+)|([A-Fa-f0-9-]{36})).*");
    }
}
