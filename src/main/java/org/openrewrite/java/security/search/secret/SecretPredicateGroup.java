package org.openrewrite.java.security.search.secret;

import org.openrewrite.ExecutionContext;

import java.util.List;

public interface SecretPredicateGroup {
    default String getName(){
        return "IDK";
    }

    List<SecretPredicate<String, String, ExecutionContext>> secretPredicates();
}
