package org.openrewrite.java.security.search.secret;

import org.openrewrite.ExecutionContext;

class ArtifactorySecretPredicateGroup implements SecretPredicateGroup {
    @Override
    public String getName() {
        return "Artifactory";
    }

    @Override
    public SecretPredicate<String, String, ExecutionContext> secretPredicate() {
        return new SecretRegexPredicate(null, "(?:\\s|=|:|\"|^)AP[\\dABCDEF][a-zA-Z0-9]{8,}(?:\\s|\"|$)")
                .or(new SecretRegexPredicate(null, "(?:\\s|=|:|\"|^)AKC[a-zA-Z0-9]{10,}(?:\\s|\"|$)"));
    }
}
