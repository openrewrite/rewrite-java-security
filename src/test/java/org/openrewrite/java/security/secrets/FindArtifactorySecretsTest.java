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

public class FindArtifactorySecretsTest implements RewriteTest {

    @Override
    public void defaults(RecipeSpec spec) {
        spec.recipe(Environment.builder()
          .scanRuntimeClasspath("org.openrewrite.java.security.secrets")
          .build()
          .activateRecipes("org.openrewrite.java.security.secrets.FindArtifactorySecrets"));
    }

    @Test
    void artifactorySecrets() {
        rewriteRun(
          //language=java
          java(
            """
              class Test {
                  String[] artifactoryStrings = {
                      "AP6xxxxxxxxxx",
                      "AP2xxxxxxxxxx",
                      "AP3xxxxxxxxxx",
                      "AP5xxxxxxxxxx",
                      "APAxxxxxxxxxx",
                      "APBxxxxxxxxxx",
                      "AKCxxxxxxxxxx",
                      " AP6xxxxxxxxxx",
                      " AKCxxxxxxxxxx",
                      "=AP6xxxxxxxxxx",
                      "=AKCxxxxxxxxxx",
                      "\\"AP6xxxxxxxxxx\\"",
                      "\\"AKCxxxxxxxxxx\\"",
                      "artif-key:AP6xxxxxxxxxx",
                      "artif-key:AKCxxxxxxxxxx",
                      "X-JFrog-Art-Api: AKCxxxxxxxxxx",
                      "X-JFrog-Art-Api: AP6xxxxxxxxxx",
                      "artifactoryx:_password=AKCxxxxxxxxxx",
                      "artifactoryx:_password=AP6xxxxxxxxxx",
                      "testAKCwithinsomeirrelevantstring",
                      "testAP6withinsomeirrelevantstring",
                      "X-JFrog-Art-Api: $API_KEY",
                      "X-JFrog-Art-Api: $PASSWORD",
                      "artifactory:_password=AP6xxxxxx",
                      "artifactory:_password=AKCxxxxxxxx"};
              }
              """,
            """
              class Test {
                  String[] artifactoryStrings = {
                      /*~~(Artifactory)~~>*/"AP6xxxxxxxxxx",
                      /*~~(Artifactory)~~>*/"AP2xxxxxxxxxx",
                      /*~~(Artifactory)~~>*/"AP3xxxxxxxxxx",
                      /*~~(Artifactory)~~>*/"AP5xxxxxxxxxx",
                      /*~~(Artifactory)~~>*/"APAxxxxxxxxxx",
                      /*~~(Artifactory)~~>*/"APBxxxxxxxxxx",
                      /*~~(Artifactory)~~>*/"AKCxxxxxxxxxx",
                      /*~~(Artifactory)~~>*/" AP6xxxxxxxxxx",
                      /*~~(Artifactory)~~>*/" AKCxxxxxxxxxx",
                      /*~~(Artifactory)~~>*/"=AP6xxxxxxxxxx",
                      /*~~(Artifactory)~~>*/"=AKCxxxxxxxxxx",
                      /*~~(Artifactory)~~>*/"\\"AP6xxxxxxxxxx\\"",
                      /*~~(Artifactory)~~>*/"\\"AKCxxxxxxxxxx\\"",
                      /*~~(Artifactory)~~>*/"artif-key:AP6xxxxxxxxxx",
                      /*~~(Artifactory)~~>*/"artif-key:AKCxxxxxxxxxx",
                      /*~~(Artifactory)~~>*/"X-JFrog-Art-Api: AKCxxxxxxxxxx",
                      /*~~(Artifactory)~~>*/"X-JFrog-Art-Api: AP6xxxxxxxxxx",
                      /*~~(Artifactory)~~>*/"artifactoryx:_password=AKCxxxxxxxxxx",
                      /*~~(Artifactory)~~>*/"artifactoryx:_password=AP6xxxxxxxxxx",
                      "testAKCwithinsomeirrelevantstring",
                      "testAP6withinsomeirrelevantstring",
                      "X-JFrog-Art-Api: $API_KEY",
                      "X-JFrog-Art-Api: $PASSWORD",
                      "artifactory:_password=AP6xxxxxx",
                      "artifactory:_password=AKCxxxxxxxx"};
              }
              """
          )
        );
    }
}
