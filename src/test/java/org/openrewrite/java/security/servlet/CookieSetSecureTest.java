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
package org.openrewrite.java.security.servlet;

import org.junit.jupiter.api.Test;
import org.openrewrite.DocumentExample;
import org.openrewrite.java.JavaParser;
import org.openrewrite.test.RecipeSpec;
import org.openrewrite.test.RewriteTest;

import static org.openrewrite.java.Assertions.java;

public class CookieSetSecureTest implements RewriteTest {

    @Override
    public void defaults(RecipeSpec spec) {
        spec.recipe(new CookieSetSecure())
          .parser(JavaParser.fromJavaVersion().classpath("javaee-api"));
    }

    @DocumentExample
    @Test
    void setSecureFalse() {
        //language=java
        rewriteRun(
          java(
            """
              import javax.servlet.http.Cookie;
              
              class Test {
                  void test() {
                      Cookie cookie = new Cookie("foo", "bar");
                      System.out.println("hi");
                      cookie.setSecure(false);
                  }
              }
              """,
            """
              import javax.servlet.http.Cookie;
              
              class Test {
                  void test() {
                      Cookie cookie = new Cookie("foo", "bar");
                      System.out.println("hi");
                      cookie.setSecure(true);
                  }
              }
              """
          )
        );
    }

    @Test
    void setSecureTrue() {
        //language=java
        rewriteRun(
          java(
            """
              import javax.servlet.http.Cookie;
              
              class Test {
                  void test() {
                      Cookie cookie = new Cookie("foo", "bar");
                      System.out.println("hi");
                      cookie.setSecure(true);
                  }
              }
              """
          )
        );
    }

    @Test
    void defaultInsecure() {
        //language=java
        rewriteRun(
          java(
            """
              import javax.servlet.http.Cookie;
              
              class Test {
                  void test() {
                      Cookie cookie = new Cookie("foo", "bar");
                      System.out.println("hi");
                  }
              }
              """,
            """
              import javax.servlet.http.Cookie;
              
              class Test {
                  void test() {
                      Cookie cookie = new Cookie("foo", "bar");
                      cookie.setSecure(true);
                      System.out.println("hi");
                  }
              }
              """
          )
        );
    }
}
