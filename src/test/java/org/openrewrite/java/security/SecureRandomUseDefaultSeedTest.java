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
import org.openrewrite.test.RecipeSpec;
import org.openrewrite.test.RewriteTest;

import static org.openrewrite.java.Assertions.java;

class SecureRandomUseDefaultSeedTest implements RewriteTest {

    @Override
    public void defaults(RecipeSpec spec) {
        spec.recipe(new SecureRandomPrefersDefaultSeed());
    }

    @Test
    void possibleStrongSeed() {
        rewriteRun(
          //language=java
          java(
            """
              import java.security.SecureRandom;
                            
              public class A {
                  void test(byte[] bytes) {
                      SecureRandom r = new SecureRandom();
                      r.setSeed(bytes);
                  }
              }
              """
          )
        );
    }

    @Test
    void possibleStrongStringSeed() {
        //language=java
        rewriteRun(
          java(
            """
              import java.security.SecureRandom;
                            
              public class A {
                  void test(String seedVal) {
                      SecureRandom r = new SecureRandom();
                      r.setSeed(seedVal.getBytes());
                  }
              }
              """
          )
        );
    }

    @Test
    void systemTimeSeed() {
        //language=java
        rewriteRun(
          java(
            """
                  import java.security.SecureRandom;
                  
                  public class A {
                      void test(byte[] bytes) {
                          SecureRandom r = new SecureRandom();
                          r.setSeed(System.currentTimeMillis());
                          r.setSeed(System.nanoTime());
                      }
                  }
              """,
            """
                  import java.security.SecureRandom;
                  
                  public class A {
                      void test(byte[] bytes) {
                          SecureRandom r = new SecureRandom();
                      }
                  }
              """
          )
        );
    }

    @Test
    void systemDateSeed() {
        //language=java
        rewriteRun(
          java(
            """
                  import java.security.SecureRandom;
                  import java.util.Date;
                  
                  public class A {
                      void test(byte[] bytes) {
                          SecureRandom r = new SecureRandom();
                          r.setSeed(new Date().getTime());
                      }
                  }
              """,
            """
                  import java.security.SecureRandom;
                  
                  public class A {
                      void test(byte[] bytes) {
                          SecureRandom r = new SecureRandom();
                      }
                  }
              """
          )
        );
    }

    @Test
    void seedIsLiteral() {
        //language=java
        rewriteRun(
          java(
            """
                  import java.security.SecureRandom;
                  
                  public class A {
                      void test() {
                          SecureRandom r = new SecureRandom();
                          r.setSeed("abcdef".getBytes());
                          r.setSeed(1234L);
                      }
                  }
              """,
            """
                  import java.security.SecureRandom;
                  
                  public class A {
                      void test() {
                          SecureRandom r = new SecureRandom();
                      }
                  }
              """
          )
        );
    }
}
