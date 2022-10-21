package org.openrewrite.java.security.search.secret;

class DiscordSecretMatcherGroup implements SecretMatcherGroup {
    @Override
    public SecretMatcher[] secretMatchers() {
        return new SecretMatcher[]{
                SecretMatcher.builder("Discord Bot Token")
                        .valueRegex("[MN][a-zA-Z\\d_-]{23}\\.[a-zA-Z\\d_-]{6}\\.[a-zA-Z\\d_-]{27}")
                        .build()
        };
    }
}

