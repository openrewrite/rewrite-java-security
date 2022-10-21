package org.openrewrite.java.security.search.secret;

import org.openrewrite.ExecutionContext;

class GithubSecretPredicateGroup implements SecretPredicateGroup {
    @Override
    public String getName() {
        return "GitHub";
    }

    @Override
    public SecretPredicate<String, String, ExecutionContext> secretPredicate() {
        return new SecretRegexPredicate(null, "[gG][iI][tT][hH][uU][bB].*['|\"][0-9a-zA-Z]{35,40}['|\"]")
                .or(new SecretRegexPredicate(null, "(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36}"));
    }

}
