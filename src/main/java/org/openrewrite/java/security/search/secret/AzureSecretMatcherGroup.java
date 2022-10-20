package org.openrewrite.java.security.search.secret;

class AzureSecretMatcherGroup implements SecretMatcherGroup {

    @Override
    public SecretMatcher[] secretMatchers() {
        return new SecretMatcher[]{
                new SecretMatcher.Builder("Azure Storage Account access key")
                        .keyPattern("AccountKey")
                        .valuePattern("[a-zA-Z0-9+\\/=]{88}")
                        .build()
        };
    }
}
