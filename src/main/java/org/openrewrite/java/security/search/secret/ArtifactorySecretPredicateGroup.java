package org.openrewrite.java.security.search.secret;

import org.openrewrite.ExecutionContext;

import java.util.Arrays;
import java.util.List;

class ArtifactorySecretPredicateGroup implements SecretPredicateGroup {
    @Override
    public String getName() {
        return "Artifactory";
    }

    @Override
    public List<SecretPredicate<String, String, ExecutionContext>> secretPredicates() {
        return Arrays.asList(new SecretRegexPredicate(null, "(?:\\s|=|:|\"|^)AP[\\dABCDEF][a-zA-Z0-9]{8,}(?:\\s|\"|$)"),
                new SecretRegexPredicate(null, "(?:\\s|=|:|\"|^)AKC[a-zA-Z0-9]{10,}(?:\\s|\"|$)")
        );
    }
}
