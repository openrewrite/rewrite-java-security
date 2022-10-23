package org.openrewrite.java.security.search.secret;

import org.openrewrite.ExecutionContext;

import java.util.Collections;
import java.util.List;

class AzureSecretPredicateGroup implements SecretPredicateGroup {

    @Override
    public String getName() {
        return "Azure Storage Account access key";
    }

    @Override
    public List<SecretPredicate<String, String, ExecutionContext>> secretPredicates() {
        return Collections.singletonList(new SecretRegexPredicate("AccountKey", "[a-zA-Z0-9+\\/=]{88}"));
    }
}
