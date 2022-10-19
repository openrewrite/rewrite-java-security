package org.openrewrite.java.security.search.secret;

class AzureSecretConfiguration implements SecretConfiguration {

    @Override
    public SecretFinder[] secretFinders() {
        return new SecretFinder[]{
                new SecretFinder.Builder("Azure Storage Account access key")
                        .keyPattern("AccountKey")
                        .valuePattern("[a-zA-Z0-9+\\/=]{88}")
                        .build()
        };
    }
}
