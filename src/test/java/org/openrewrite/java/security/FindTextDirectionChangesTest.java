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
import org.openrewrite.test.RecipeSpec;
import org.openrewrite.test.RewriteTest;

import static org.openrewrite.java.Assertions.java;

class FindTextDirectionChangesTest implements RewriteTest {

    @Override
    public void defaults(RecipeSpec spec) {
        spec.recipe(new FindTextDirectionChanges());
    }

    @DocumentExample
    @Test
    void conditionalActuallyInComment() {
        //language=java
        rewriteRun(
          java(
            """
              class A {
                  void foo() {
                      boolean isAdmin = false;
                      /*\u202E } \u2066 if(isAdmin) \u2069 \u2066 begin admins only */
                          System.out.println("You are an admin.");
                      /* end admins only \u202E { \u2066 */
                  }
              }
              """,
            """
              class A {
                  void foo() {
                      boolean isAdmin = false;
                      /*\u202E } \u2066 if(isAdmin) \u2069 \u2066 begin admins only */
                          System.out./*~~(Found text-direction altering unicode control characters: LRI,RLO,PDI)~~>*/println("You are an admin.");
                      /* end admins only \u202E { \u2066 */
                  }
              }
              """
          )
        );
    }

    @Test
    void stringLiteral() {
        rewriteRun(
          //language=java
          java(
            """
              class A {
                  String s = "\u202E";
              }
              """,
            """
              class A {
                  String s = /*~~(Found text-direction altering unicode control characters: RLO)~~>*/"\u202E";
              }
              """
          )
        );
    }
}
