package org.openrewrite.java.security.search.secret;

import org.openrewrite.ExecutionContext;

import java.util.Collections;
import java.util.List;

class NpmSecretPredicateGroup implements SecretPredicateGroup {
    @Override
    public String getName() {
        return "NPM Token";
    }

    @Override
    public List<SecretPredicate<String, String, ExecutionContext>> secretPredicates() {
        return Collections.singletonList(new SecretRegexPredicate(null, "\\/\\/.+\\/:_authToken=\\s*((npm_.+)|([A-Fa-f0-9-]{36})).*"));
    }
}
