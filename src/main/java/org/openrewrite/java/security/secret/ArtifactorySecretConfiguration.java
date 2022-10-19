package org.openrewrite.java.security.secret;

class ArtifactorySecretConfiguration implements SecretConfiguration {
    @Override
    public SecretFinder[] secretFinders() {
        return new SecretFinder[]{
                SecretFinder.builder("Artifactory API Token")
                        .valuePattern("(?:\\s|=|:|\"|^)AKC[a-zA-Z0-9]{10,}(?:\\s|\"|$)")
                        .build(),
                SecretFinder.builder("Artifactory Password")
                        .valuePattern("(?:\\s|=|:|\"|^)AP[\\dABCDEF][a-zA-Z0-9]{8,}(?:\\s|\"|$)")
                        .build()
        };
    }
}
