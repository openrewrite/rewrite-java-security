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

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.openrewrite.Issue;
import org.openrewrite.test.RecipeSpec;
import org.openrewrite.test.RewriteTest;

import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.openrewrite.java.Assertions.java;

class SecureTempFileCreationTest implements RewriteTest {

    @Override
    public void defaults(RecipeSpec spec) {
        spec.recipe(new SecureTempFileCreation(SecureTempFileCreation.Target.ALL_SOURCE));
    }

    @Test
    void twoArgCreateTempFile() {
        //language=java
        rewriteRun(
          java(
            """
                  import java.io.File;
                  import java.io.IOException;

                  class Test {
                      static void method() throws IOException {
                          File tempDir = File.createTempFile("hello", "world");
                      }
                  }
              """,
            """
                  import java.io.File;
                  import java.io.IOException;
                  import java.nio.file.Files;

                  class Test {
                      static void method() throws IOException {
                          File tempDir = Files.createTempFile("hello", "world").toFile();
                      }
                  }
              """
          )
        );
    }

    @Test
    void threeArgCreateTempFile() {
        //language=java
        rewriteRun(
          java(
            """
                  import java.io.File;
                  import java.io.IOException;

                  class Test {
                      static void method() throws IOException {
                          File tempDir = File.createTempFile("hello", "world", new File("."));
                      }
                  }
              """,
            """
                  import java.io.File;
                  import java.io.IOException;
                  import java.nio.file.Files;

                  class Test {
                      static void method() throws IOException {
                          File tempDir = Files.createTempFile(new File(".").toPath(), "hello", "world").toFile();
                      }
                  }
              """
          )
        );
    }

    @Test
    void threeArgWithNullPath() {
        //language=java
        rewriteRun(
          java(
            """
              import java.io.File;

              class T {
                  File temp = File.createTempFile("random", "file", null);
              }
              """,
            """
              import java.io.File;
              import java.nio.file.Files;

              class T {
                  File temp = Files.createTempFile("random", "file").toFile();
              }
              """
          )
        );
    }

    /**
     * If the issue could be fixed by the [UseFilesCreateTempDirectory] recipe, then this recipe should not be run.
     */
    @Test
    @Issue("https://github.com/openrewrite/rewrite-java-security/issues/9")
    void doNotFixTemporaryDirectoryHijacking() {
        //language=java
        rewriteRun(
          java(
            """
                  import java.io.File;
                  
                  class A {
                      void b() {
                          File tempDir = File.createTempFile("abc", "def");
                          tempDir.delete();
                          tempDir.mkdir();
                          System.out.println(tempDir.getAbsolutePath());
                      }
                  }
              """
          )
        );
    }


    @Nested
    class TestSourceMatcherTest {

        @ParameterizedTest
        @ValueSource(strings = {
          "commons-vfs2/src/test/java/org/apache/commons/vfs2/provider/zip/ParseXmlInZipTest.java",
          "commons-vfs2/src/test/java/org/apache/commons/vfs2/provider/zip/FileLockTest.java",
          "commons-vfs2/src/test/java/org/apache/commons/vfs2/provider/sftp/AbstractSftpProviderTestCase.java",
          "commons-vfs2/src/test/java/org/apache/commons/vfs2/provider/zip/ZipFileObjectTest.java",
          "commons-vfs2/src/test/java/org/apache/commons/vfs2/provider/local/TempFileTests.java",
          "commons-vfs2/src/test/java/org/apache/commons/vfs2/provider/DefaultFileContentTest.java",
          "src/test/java/org/apache/commons/codec/digest/DigestUtilsTest.java"
        })
        void ensureIsTestSource(String path) {
            assertTrue(SecureTempFileCreation.isTestSource(Path.of(path)));
        }
    }
}
