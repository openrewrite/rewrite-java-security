package org.openrewrite.java.security.search.secret;

import org.openrewrite.ExecutionContext;

import java.util.Arrays;
import java.util.List;

class AwsSecretPredicateGroup implements SecretPredicateGroup {
    @Override
    public String getName() {
        return "AWS Access Key";
    }

    @Override
    public List<SecretPredicate<String, String, ExecutionContext>> secretPredicates() {
        return Arrays.asList(new SecretRegexPredicate(null, "AKIA[0-9A-Z]{16}"),
                new SecretRegexPredicate("aws.{0,20}?(key|pwd|pw|password|pass|token)", "^([0-9a-zA-Z/+]{40})$"));
    }
}
