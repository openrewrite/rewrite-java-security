package org.openrewrite.java.security.search.secret;

class AwsSecretMatcherGroup implements SecretMatcherGroup {
    @Override
    public SecretMatcher[] secretMatchers() {
        return new SecretMatcher[]{
                SecretMatcher.builder("AWS API Key")
                        .valuePattern("((?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16})")
                        .build(),
                SecretMatcher.builder("AWS Token")
                        .keyPattern("aws.{0,20}?(key|pwd|pw|password|pass|token)")
                        .valuePattern("^([0-9a-zA-Z/+]{40})$")
                        .build(),
                SecretMatcher.builder("AWS Token In Java")
                        .valuePattern("aws.{0,20}?(key|pwd|pw|password|pass|token).{0,20}?['|\"]([0-9a-zA-Z/+]{40})['|\"]")
                        .build(),
                SecretMatcher.builder("AWS AppSync GraphQL Key")
                        .valuePattern("da2-[a-z0-9]{26}")
                        .build(),
                SecretMatcher.builder("Amazon MWS Auth Token")
                        .valuePattern("amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
                        .build(),
                SecretMatcher.builder("Azure Storage Account access key")
                        .keyPattern("AccountKey")
                        .valuePattern("[a-zA-Z0-9+\\/=]{88}")
                        .build()
        };
    }

}
