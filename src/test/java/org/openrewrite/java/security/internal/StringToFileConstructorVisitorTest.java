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
package org.openrewrite.java.security.internal;

import org.junit.jupiter.api.Test;
import org.openrewrite.DocumentExample;
import org.openrewrite.test.RecipeSpec;
import org.openrewrite.test.RewriteTest;

import static org.openrewrite.java.Assertions.java;

class StringToFileConstructorVisitorTest implements RewriteTest {
    @Override
    public void defaults(RecipeSpec spec) {
        spec.recipe(RewriteTest.toRecipe(() -> new StringToFileConstructorVisitor<>()));
    }

    @DocumentExample
    @SuppressWarnings("RedundantFileCreation")
    @Test
    void stringLiteralFileOutputStreamToNewFile() {
        //language=java
        rewriteRun(
          java(
            """
              import java.io.FileOutputStream;
              import java.io.File;
              public class Test {
                  @SuppressWarnings({"EmptyTryBlock", "RedundantSuppression"})
                  public void test() {
                      try (FileOutputStream fio = new FileOutputStream("test.txt")) {
                         // do something
                      }
                  }
              }
              """,
            """
              import java.io.FileOutputStream;
              import java.io.File;
              public class Test {
                  @SuppressWarnings({"EmptyTryBlock", "RedundantSuppression"})
                  public void test() {
                      try (FileOutputStream fio = new FileOutputStream(new File("test.txt"))) {
                         // do something
                      }
                  }
              }
              """
          )
        );
    }

    @Test
    void stringAppendedFileOutputStreamToFileSeparator() {
        //language=java
        rewriteRun(
          java(
            """
              import java.io.FileOutputStream;
              import java.io.File;
              public class Test {
                  @SuppressWarnings({"EmptyTryBlock", "RedundantSuppression"})
                  public void test() {
                      try (FileOutputStream fio = new FileOutputStream("base" + File.separator + "test.txt")) {
                         // do something
                      }
                  }
              }
              """,
            """
              import java.io.FileOutputStream;
              import java.io.File;
              public class Test {
                  @SuppressWarnings({"EmptyTryBlock", "RedundantSuppression"})
                  public void test() {
                      try (FileOutputStream fio = new FileOutputStream(new File("base", "test.txt"))) {
                         // do something
                      }
                  }
              }
              """
          )
        );
    }

    @Test
    void stringAppendedFileOutputStreamToFileSeparatorChar() {
        //language=java
        rewriteRun(
          java(
            """
              import java.io.FileOutputStream;
              import java.io.File;
              public class Test {
                  @SuppressWarnings({"EmptyTryBlock", "RedundantSuppression"})
                  public void test() {
                      try (FileOutputStream fio = new FileOutputStream("base" + File.separatorChar + "test.txt")) {
                         // do something
                      }
                  }
              }
              """,
            """
              import java.io.FileOutputStream;
              import java.io.File;
              public class Test {
                  @SuppressWarnings({"EmptyTryBlock", "RedundantSuppression"})
                  public void test() {
                      try (FileOutputStream fio = new FileOutputStream(new File("base", "test.txt"))) {
                         // do something
                      }
                  }
              }
              """
          )
        );
    }

    @Test
    void stringWithSlashAppendedFileOutputStream() {
        //language=java
        rewriteRun(
          java(
            """
              import java.io.FileOutputStream;
              import java.io.File;
              public class Test {
                  @SuppressWarnings({"EmptyTryBlock", "RedundantSuppression"})
                  public void test() {
                      try (FileOutputStream fio = new FileOutputStream("base/" + "test.txt")) {
                         // do something
                      }
                  }
              }
              """,
            """
              import java.io.FileOutputStream;
              import java.io.File;
              public class Test {
                  @SuppressWarnings({"EmptyTryBlock", "RedundantSuppression"})
                  public void test() {
                      try (FileOutputStream fio = new FileOutputStream(new File("base/", "test.txt"))) {
                         // do something
                      }
                  }
              }
              """
          )
        );
    }

    @Test
    void slashNotAppendedFileOutputStream() {
        //language=java
        rewriteRun(
          java(
            """
              import java.io.FileOutputStream;
              import java.io.File;
              public class Test {
                  @SuppressWarnings({"EmptyTryBlock", "RedundantSuppression"})
                  public void test() {
                      try (FileOutputStream fio = new FileOutputStream("base-" + "test.txt")) {
                         // do something
                      }
                  }
              }
              """,
            """
              import java.io.FileOutputStream;
              import java.io.File;
              public class Test {
                  @SuppressWarnings({"EmptyTryBlock", "RedundantSuppression"})
                  public void test() {
                      try (FileOutputStream fio = new FileOutputStream(new File("base-" + "test.txt"))) {
                         // do something
                      }
                  }
              }
              """
          )
        );
    }

    @Test
    void stringAppendedFileOutputStream2() {
        // language=java
        rewriteRun(
          java(
            """
              import java.io.FileOutputStream;
              import java.io.File;
              public class Test {
                  @SuppressWarnings({"EmptyTryBlock", "RedundantSuppression"})
                  public void test() {
                      String fileName = "test";
                      try (FileOutputStream fio = new FileOutputStream("base" + File.separator + fileName + ".txt")) {
                         // do something
                      }
                  }
              }
              """,
            """
              import java.io.FileOutputStream;
              import java.io.File;
              public class Test {
                  @SuppressWarnings({"EmptyTryBlock", "RedundantSuppression"})
                  public void test() {
                      String fileName = "test";
                      try (FileOutputStream fio = new FileOutputStream(new File("base", fileName + ".txt"))) {
                         // do something
                      }
                  }
              }
              """
          )
        );
    }
}
