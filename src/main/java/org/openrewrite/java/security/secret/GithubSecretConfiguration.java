package org.openrewrite.java.security.secret;

class GithubSecretConfiguration implements SecretConfiguration {
    @Override
    public SecretFinder[] secretFinders() {
        return new SecretFinder[]{
                SecretFinder.builder("GitHub")
                        .valuePattern("[gG][iI][tT][hH][uU][bB].*['|\"][0-9a-zA-Z]{35,40}['|\"]")
                        .build(),
                SecretFinder.builder("GitHub Token")
                        .valuePattern("(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36}")
                        .build()
        };
    }
}
