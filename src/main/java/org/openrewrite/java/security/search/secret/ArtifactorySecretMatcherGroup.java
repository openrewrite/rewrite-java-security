package org.openrewrite.java.security.search.secret;

class ArtifactorySecretMatcherGroup implements SecretMatcherGroup {
    @Override
    public SecretMatcher[] secretMatchers() {
        return new SecretMatcher[]{
                SecretMatcher.builder("Artifactory API Token")
                        .valuePattern("(?:\\s|=|:|\"|^)AKC[a-zA-Z0-9]{10,}(?:\\s|\"|$)")
                        .build(),
                SecretMatcher.builder("Artifactory Password")
                        .valuePattern("(?:\\s|=|:|\"|^)AP[\\dABCDEF][a-zA-Z0-9]{8,}(?:\\s|\"|$)")
                        .build()
        };
    }
}
