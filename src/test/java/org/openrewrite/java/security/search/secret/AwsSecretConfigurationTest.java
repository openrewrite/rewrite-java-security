package org.openrewrite.java.security.search.secret;

import org.junit.jupiter.api.Test;
import org.openrewrite.test.RecipeSpec;
import org.openrewrite.test.RewriteTest;

import java.util.List;

import static org.openrewrite.java.Assertions.java;
import static org.openrewrite.yaml.Assertions.yaml;

public class AwsSecretConfigurationTest implements RewriteTest {
    @Override
    public void defaults(RecipeSpec spec) {
        spec.recipe(new DetectSecrets(List.of("AWS Token", "AWS API Key")));
    }

    @Test
    void awsSecrets() {
        rewriteRun(
                //language=yaml
                yaml("""
                    env1:
                      aws_access_key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
                    env2:
                      aws_access_key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEYa
                    evn3:
                      aws_access_key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKE
                    """,
                        """
                        env1:
                          ~~(AWS Token)~~>aws_access_key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
                        env2:
                          aws_access_key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEYa
                        evn3:
                          aws_access_key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKE
                        """),
                //language=java
                java("""
                            class T {
                                String[] awsSecrets = {
                                    "AKIAZZZZZZZZZZZZZZZZ",
                                    "akiazzzzzzzzzzzzzzzz",
                                    "AKIAZZZ",
                                };
                            }
                        """,
                        """
                                class T {
                                    String[] awsSecrets = {
                                        /*~~(AWS API Key)~~>*/"AKIAZZZZZZZZZZZZZZZZ",
                                        "akiazzzzzzzzzzzzzzzz",
                                        "AKIAZZZ",
                                    };
                                }
                            """)
        );
    }

}
