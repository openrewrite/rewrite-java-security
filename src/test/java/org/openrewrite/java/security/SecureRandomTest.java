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
package org.openrewrite.java.security;

import org.junit.jupiter.api.Test;
import org.openrewrite.DocumentExample;
import org.openrewrite.Issue;
import org.openrewrite.test.RecipeSpec;
import org.openrewrite.test.RewriteTest;

import static org.openrewrite.java.Assertions.java;

class SecureRandomTest implements RewriteTest {

    @Override
    public void defaults(RecipeSpec spec) {
        spec.recipe(new SecureRandom());
    }

    @DocumentExample
    @Issue("https://github.com/openrewrite/rewrite-java-security/issues/131")
    @Test
    void secureContext() {
        rewriteRun(
          //language=java
          java(
            """
              import java.util.Random;

              public class A {
                  String generateSecretToken() {
                      Random r = new Random();
                      return Long.toHexString(r.nextLong());
                  }
              }
              """,
            """
              import java.security.SecureRandom;
              import java.util.Random;

              public class A {
                  String generateSecretToken() {
                      Random r = new SecureRandom();
                      return Long.toHexString(r.nextLong());
                  }
              }
              """
          )
        );
    }

    @Test
    void removeImport() {
        rewriteRun(
          //language=java
          java(
            """
              import java.util.Random;

              public class A {
                  void generateSecretToken() {
                      int num = new Random().nextInt();
                  }
              }
              """,
            """
              import java.security.SecureRandom;

              public class A {
                  void generateSecretToken() {
                      int num = new SecureRandom().nextInt();
                  }
              }
              """
          )
        );
    }
}
