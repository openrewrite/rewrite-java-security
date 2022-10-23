package org.openrewrite.java.security.search.secret;

import org.openrewrite.ExecutionContext;

import java.util.Collections;
import java.util.List;

class DiscordSecretPredicateGroup implements SecretPredicateGroup {
    @Override
    public String getName() {
        return "Discord";
    }

    @Override
    public List<SecretPredicate<String, String, ExecutionContext>> secretPredicates() {
        return Collections.singletonList(new SecretRegexPredicate(null, "[MN][a-zA-Z\\d_-]{23}\\.[a-zA-Z\\d_-]{6}\\.[a-zA-Z\\d_-]{27}")) ;
    }

}

