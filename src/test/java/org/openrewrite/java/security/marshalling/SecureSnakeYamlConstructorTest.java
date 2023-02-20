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
package org.openrewrite.java.security.marshalling;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.openrewrite.java.JavaParser;
import org.openrewrite.test.RecipeSpec;
import org.openrewrite.test.RewriteTest;

import static org.openrewrite.java.Assertions.java;

class SecureSnakeYamlConstructorTest implements RewriteTest {

    @Override
    public void defaults(RecipeSpec spec) {
        spec.recipe(new SecureSnakeYamlConstructor())
          .parser(JavaParser.fromJavaVersion().classpath("snakeyaml"));
    }

    @Test
    void snakeYamlConstructor() {
        rewriteRun(
          //language=java
          java(
            """
              import org.yaml.snakeyaml.Yaml;
              
              class Test {
                  Object o = new Yaml();
              }
              """,
            """
              import org.yaml.snakeyaml.Yaml;
              import org.yaml.snakeyaml.constructor.SafeConstructor;
              
              class Test {
                  Object o = new Yaml(new SafeConstructor());
              }
              """
          )
        );
    }

    @Test
    void snakeYamlWithDumperArgument() {
        rewriteRun(
          //language=java
          java(
            """
              import org.yaml.snakeyaml.Yaml;
              import org.yaml.snakeyaml.DumperOptions;
              
              class Test {
                  Object o = new Yaml(new DumperOptions());
              }
              """,
            """
              import org.yaml.snakeyaml.Yaml;
              import org.yaml.snakeyaml.constructor.SafeConstructor;
              import org.yaml.snakeyaml.representer.Representer;
              import org.yaml.snakeyaml.DumperOptions;
              
              class Test {
                  Object o = new Yaml(new SafeConstructor(), new Representer(), new DumperOptions());
              }
              """
          )
        );
    }

    @Test
    void snakeYamlWithRepresenterArgument() {
        rewriteRun(
          //language=java
          java(
            """
              import org.yaml.snakeyaml.Yaml;
              import org.yaml.snakeyaml.representer.Representer;
              
              class Test {
                  Object o = new Yaml(new Representer());
              }
              """,
            """
              import org.yaml.snakeyaml.DumperOptions;
              import org.yaml.snakeyaml.Yaml;
              import org.yaml.snakeyaml.constructor.SafeConstructor;
              import org.yaml.snakeyaml.representer.Representer;
              
              class Test {
                  Object o = new Yaml(new SafeConstructor(), new Representer(), new DumperOptions());
              }
              """
          )
        );
    }

    @Test
    void doNotFixYamlIfDumpIsOnlyMethodCalled() {
        rewriteRun(
          //language=java
          java(
            """
              import org.yaml.snakeyaml.Yaml;
              
              class Test {
                  String test(Object o) {
                     Yaml y = new Yaml();
                     return y.dump(o);
                  }
              }
              """
          )
        );
    }

    @Test
    void doFixYamlIfLoadIsOnlyMethodCalled() {
        rewriteRun(
          //language=java
          java(
            """
              import org.yaml.snakeyaml.Yaml;
                            
              class Test {
                  Object test(String o) {
                      Yaml y = new Yaml();
                      return y.load(o);
                  }
              }
              """,
            """
              import org.yaml.snakeyaml.Yaml;
              import org.yaml.snakeyaml.constructor.SafeConstructor;
                            
              class Test {
                  Object test(String o) {
                      Yaml y = new Yaml(new SafeConstructor());
                      return y.load(o);
                  }
              }
              """
          )
        );
    }

    @Test
    void doFixYamlIfYamlPassedAsArgument() {
        rewriteRun(
          //language=java
          java(
            """
              import org.yaml.snakeyaml.Yaml;
                            
              class Test {
                  void test(String o) {
                      Yaml y = new Yaml();
                      doSomething(y);
                  }
                  
                  void doSomething(Yaml y) {
                      // no-op
                  }
              }
              """,
            """
              import org.yaml.snakeyaml.Yaml;
              import org.yaml.snakeyaml.constructor.SafeConstructor;
                            
              class Test {
                  void test(String o) {
                      Yaml y = new Yaml(new SafeConstructor());
                      doSomething(y);
                  }
                  
                  void doSomething(Yaml y) {
                      // no-op
                  }
              }
              """
          )
        );
    }

    @Test
    void doFixYamlIfYamlAssignedToClassVariable() {
        rewriteRun(
          //language=java
          java(
            """
              import org.yaml.snakeyaml.Yaml;
                            
              class Test {
                  final Yaml y;
                  Test(Object o) {
                      y = new Yaml();
                  }
              }
              """,
            """
              import org.yaml.snakeyaml.Yaml;
              import org.yaml.snakeyaml.constructor.SafeConstructor;
                            
              class Test {
                  final Yaml y;
                  Test(Object o) {
                      y = new Yaml(new SafeConstructor());
                  }
              }
              """
          )
        );
    }

    @Test
    @SuppressWarnings({"UnusedAssignment", "ParameterCanBeLocal"})
    void doNotFixYamlIfYamlAssignedToConstructorVariable() {
        rewriteRun(
          //language=java
          java(
            """
              import org.yaml.snakeyaml.Yaml;
                            
              class Test {
                  final Object y;
                  Test(Object y) {
                      y = new Yaml();
                  }
              }
              """
          )
        );
    }

    @Test
    @SuppressWarnings({"UnusedAssignment"})
    void doNotFixYamlIfYamlAssignedToMethodScopeVariable() {
        rewriteRun(
          //language=java
          java(
            """
              import org.yaml.snakeyaml.Yaml;
                            
              class Test {
                  final Object y;
                  Test() {
                      Object y;
                      {
                        y = new Yaml();
                      }
                  }
              }
              """
          )
        );
    }

    @Test
    void doFixYamlIfYamlAssignedToClassVariableViaThis() {
        rewriteRun(
          //language=java
          java(
            """
              import org.yaml.snakeyaml.Yaml;
                            
              class Test {
                  final Yaml y;
                  Test(Object o) {
                      this.y = new Yaml();
                  }
              }
              """,
            """
              import org.yaml.snakeyaml.Yaml;
              import org.yaml.snakeyaml.constructor.SafeConstructor;
                            
              class Test {
                  final Yaml y;
                  Test(Object o) {
                      this.y = new Yaml(new SafeConstructor());
                  }
              }
              """
          )
        );
    }

    @Test
    void doFixYamlIfSnakeYamlIsReturned() {
        rewriteRun(
          //language=java
          java(
            """
              import org.yaml.snakeyaml.Yaml;
                            
              class Test {
                  Yaml test() {
                      return new Yaml();
                  }
              }
              """,
            """
              import org.yaml.snakeyaml.Yaml;
              import org.yaml.snakeyaml.constructor.SafeConstructor;
                            
              class Test {
                  Yaml test() {
                      return new Yaml(new SafeConstructor());
                  }
              }
              """
          )
        );
    }

    @Test
    @Disabled("See: https://github.com/openrewrite/rewrite/issues/2540")
    void doFixYamlIfPassedInLambda() {
        rewriteRun(
          //language=java
          java(
            """
              import org.yaml.snakeyaml.Yaml;
              import java.util.function.Supplier;
                            
              class Test {
                  void test() {
                      supply(Yaml::new);
                  }
                  
                  void supply(Supplier<Yaml> supplier) {
                      // no-op
                  }
              }
              """,
            """
              import org.yaml.snakeyaml.Yaml;
              import org.yaml.snakeyaml.constructor.SafeConstructor;
                            
              class Test {
                  void test() {
                      supply(() -> new Yaml(new SafeConstructor()));
                  }
                  
                  void supply(Supplier<Yaml> supplier) {
                      // no-op
                  }
              }
              """
          )
        );
    }
}
