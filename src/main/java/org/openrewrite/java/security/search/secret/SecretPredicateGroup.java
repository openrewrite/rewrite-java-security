package org.openrewrite.java.security.search.secret;

import org.openrewrite.ExecutionContext;

public interface SecretPredicateGroup {
    default String getName(){
        return "IDK";
    }

    SecretPredicate<String, String, ExecutionContext> secretPredicate();
}
