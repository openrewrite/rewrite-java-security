package org.openrewrite.java.security.secret;

import org.junit.jupiter.api.Test;

import static org.openrewrite.java.Assertions.java;

public class GithubSecretConfigurationTest implements SecretConfigurationTest {
    @Override
    public SecretConfiguration secretConfiguration() {
        return new GithubSecretConfiguration();
    }

    @Test
    void githubSecrets() {
        rewriteRun(
                //language=java
                java("""
                    class Test {
                        void githubTest() {
                            String secret = "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";
                            String notSecret = "foo_wWPw5k4aXcaT4fNP0UcnZwJUVFk6LO0pINUx";
                        }
                    }
                """,
        """
                    class Test {
                        void githubTest() {
                            String secret = /*~~(GitHub Token)~~>*/"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";
                            String notSecret = "foo_wWPw5k4aXcaT4fNP0UcnZwJUVFk6LO0pINUx";
                        }
                    }
                """)
        );
    }
}
