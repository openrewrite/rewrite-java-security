/*
 * Copyright 2022 the original author or authors.
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
package org.openrewrite.java.security.secrets;

import org.junit.jupiter.api.Test;
import org.openrewrite.config.Environment;
import org.openrewrite.test.RecipeSpec;
import org.openrewrite.test.RewriteTest;

import static org.openrewrite.java.Assertions.java;

public class FindGitHubSecretsTest implements RewriteTest {

    @Override
    public void defaults(RecipeSpec spec) {
        spec.recipe(Environment.builder()
          .scanRuntimeClasspath("org.openrewrite.java.security.secrets")
          .build()
          .activateRecipes("org.openrewrite.java.security.secrets.FindGitHubSecrets"));
    }

    @Test
    void githubSecrets() {
        rewriteRun(
          //language=java
          java(
            """
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
                      String secret = /*~~(GitHub)~~>*/"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";
                      String notSecret = "foo_wWPw5k4aXcaT4fNP0UcnZwJUVFk6LO0pINUx";
                  }
              }
              """
          )
        );
    }
}
