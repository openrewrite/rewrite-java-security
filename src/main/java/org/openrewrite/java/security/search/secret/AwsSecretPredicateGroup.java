package org.openrewrite.java.security.search.secret;

import org.openrewrite.ExecutionContext;

class AwsSecretPredicateGroup implements SecretPredicateGroup {
    @Override
    public String getName() {
        return "AWS Access Key";
    }

    @Override
    public SecretPredicate<String, String, ExecutionContext> secretPredicate() {
        return new SecretRegexPredicate(null, "AKIA[0-9A-Z]{16}")
                .or(new SecretRegexPredicate("aws.{0,20}?(key|pwd|pw|password|pass|token)", "^([0-9a-zA-Z/+]{40})$"));
    }
}
