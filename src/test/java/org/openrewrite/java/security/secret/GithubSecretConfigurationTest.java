package org.openrewrite.java.security.secret;

import org.junit.jupiter.api.Test;
import org.openrewrite.test.RecipeSpec;
import org.openrewrite.test.RewriteTest;

import static org.openrewrite.java.Assertions.java;

public class GithubSecretConfigurationTest implements RewriteTest {
    @Override
    public void defaults(RecipeSpec spec) {
        spec.recipe(new DetectSecrets());
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
