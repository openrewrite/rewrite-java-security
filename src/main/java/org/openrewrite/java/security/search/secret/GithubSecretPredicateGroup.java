package org.openrewrite.java.security.search.secret;

import org.openrewrite.ExecutionContext;

import java.util.Arrays;
import java.util.List;

class GithubSecretPredicateGroup implements SecretPredicateGroup {
    @Override
    public String getName() {
        return "GitHub";
    }

    @Override
    public List<SecretPredicate<String, String, ExecutionContext>> secretPredicates() {
        return Arrays.asList(new SecretRegexPredicate(null, "[gG][iI][tT][hH][uU][bB].*['|\"][0-9a-zA-Z]{35,40}['|\"]"),
                new SecretRegexPredicate(null, "(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36}"));
    }

}
