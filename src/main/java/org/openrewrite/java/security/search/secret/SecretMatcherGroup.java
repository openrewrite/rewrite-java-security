package org.openrewrite.java.security.search.secret;

public interface SecretMatcherGroup {
    SecretMatcher[] secretMatchers();
}
