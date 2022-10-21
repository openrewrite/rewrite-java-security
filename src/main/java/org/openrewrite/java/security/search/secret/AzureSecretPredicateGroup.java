package org.openrewrite.java.security.search.secret;

import org.openrewrite.ExecutionContext;

class AzureSecretPredicateGroup implements SecretPredicateGroup {

    @Override
    public String getName() {
        return "Azure Storage Account access key";
    }

    @Override
    public SecretPredicate<String, String, ExecutionContext> secretPredicate() {
        return new SecretRegexPredicate("AccountKey", "[a-zA-Z0-9+\\/=]{88}");
    }
}
