package org.openrewrite.java.security.search.secret;

class GithubSecretMatcherGroup implements SecretMatcherGroup {
    @Override
    public SecretMatcher[] secretMatchers() {
        return new SecretMatcher[]{
                SecretMatcher.builder("GitHub")
                        .valuePattern("[gG][iI][tT][hH][uU][bB].*['|\"][0-9a-zA-Z]{35,40}['|\"]")
                        .build(),
                SecretMatcher.builder("GitHub Token")
                        .valuePattern("(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36}")
                        .build()
        };
    }
}
