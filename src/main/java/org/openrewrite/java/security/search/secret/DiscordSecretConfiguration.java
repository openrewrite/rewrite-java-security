package org.openrewrite.java.security.search.secret;

class DiscordSecretConfiguration implements SecretConfiguration {
    @Override
    public SecretFinder[] secretFinders() {
        return new SecretFinder[]{
                SecretFinder.builder("Discord Bot Token")
                        .valuePattern("[MN][a-zA-Z\\d_-]{23}\\.[a-zA-Z\\d_-]{6}\\.[a-zA-Z\\d_-]{27}")
                        .build()
        };
    }
}

