package org.openrewrite.java.security.search.secret;

import org.openrewrite.ExecutionContext;

class DiscordSecretPredicateGroup implements SecretPredicateGroup {
    @Override
    public String getName() {
        return "Discord";
    }

    @Override
    public SecretPredicate<String, String, ExecutionContext> secretPredicate() {
        return new SecretRegexPredicate(null, "[MN][a-zA-Z\\d_-]{23}\\.[a-zA-Z\\d_-]{6}\\.[a-zA-Z\\d_-]{27}");
    }

}

