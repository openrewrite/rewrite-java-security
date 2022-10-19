package org.openrewrite.java.security.secret;

class AwsSecretConfiguration implements SecretConfiguration {
    @Override
    public SecretFinder[] secretFinders() {
        return new SecretFinder[]{
                SecretFinder.builder("AWS API Key")
                        .valuePattern("((?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16})")
                        .build(),
                SecretFinder.builder("AWS Token")
                        .keyPattern("aws.{0,20}?(key|pwd|pw|password|pass|token)")
                        .valuePattern("^([0-9a-zA-Z/+]{40})$")
                        .build(),
                SecretFinder.builder("AWS Token In Java")
                        .valuePattern("aws.{0,20}?(key|pwd|pw|password|pass|token).{0,20}?['|\"]([0-9a-zA-Z/+]{40})['|\"]")
                        .build(),
                SecretFinder.builder("AWS AppSync GraphQL Key")
                        .valuePattern("da2-[a-z0-9]{26}")
                        .build(),
                SecretFinder.builder("Amazon MWS Auth Token")
                        .valuePattern("amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
                        .build(),
                SecretFinder.builder("Azure Storage Account access key")
                        .keyPattern("AccountKey")
                        .valuePattern("[a-zA-Z0-9+\\/=]{88}")
                        .build()
        };
    }

}
