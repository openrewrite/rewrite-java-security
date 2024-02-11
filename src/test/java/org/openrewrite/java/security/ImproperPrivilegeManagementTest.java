/*
 * Copyright 2023 the original author or authors.
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
import org.openrewrite.test.RecipeSpec;
import org.openrewrite.test.RewriteTest;

import static org.openrewrite.java.Assertions.java;

class ImproperPrivilegeManagementTest implements RewriteTest {

    @Override
    public void defaults(RecipeSpec spec) {
        spec.recipe(new ImproperPrivilegeManagement());
    }

    @DocumentExample
    @SuppressWarnings("removal")
    @Test
    void improper() {
        //language=java
        rewriteRun(
          java(
            """
              import java.security.*;
              public class Test {
                  class MyAction implements PrivilegedAction<Integer> {
                      public Integer run() {
                          System.loadLibrary("awt");
                          return 0;
                      }
                  }
                  void test() {
                      AccessController.doPrivileged((PrivilegedAction<Void>)
                          () -> {
                              // Privileged code goes here, for example:
                              System.loadLibrary("awt");
                              return null; // nothing to return
                          }
                      );
                  }
              }
              """,
            """
              import java.security.*;
              public class Test {
                  /*~~>*/class MyAction implements PrivilegedAction<Integer> {
                      public Integer run() {
                          System.loadLibrary("awt");
                          return 0;
                      }
                  }
                  void test() {
                      /*~~>*/AccessController.doPrivileged((PrivilegedAction<Void>)
                          () -> {
                              // Privileged code goes here, for example:
                              System.loadLibrary("awt");
                              return null; // nothing to return
                          }
                      );
                  }
              }
              """
          )
        );
    }
}
