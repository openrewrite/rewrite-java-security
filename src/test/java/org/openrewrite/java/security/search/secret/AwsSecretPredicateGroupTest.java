/*
 * Copyright 2021 the original author or authors.
 * <p>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 * https://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.openrewrite.java.security.search.secret;

import org.junit.jupiter.api.Test;
import org.openrewrite.test.RecipeSpec;
import org.openrewrite.test.RewriteTest;

import java.util.List;

import static org.openrewrite.java.Assertions.java;
import static org.openrewrite.yaml.Assertions.yaml;

public class AwsSecretPredicateGroupTest implements RewriteTest {
    @Override
    public void defaults(RecipeSpec spec) {
        spec.recipe(new FindSecrets(List.of("AWS Token", "AWS API Key")));
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
                      ~~(AWS Access Key)~~>aws_access_key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
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
                                    /*~~(AWS Access Key)~~>*/"AKIAZZZZZZZZZZZZZZZZ",
                                    "akiazzzzzzzzzzzzzzzz",
                                    "AKIAZZZ",
                                };
                            }
                        """)
        );
    }

}
