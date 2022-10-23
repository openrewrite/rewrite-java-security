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
import org.openrewrite.java.JavaParser;
import org.openrewrite.test.RecipeSpec;
import org.openrewrite.test.RewriteTest;

import static org.openrewrite.java.Assertions.java;

@SuppressWarnings({"RedundantThrows", "ResultOfMethodCallIgnored"})
class UseFilesCreateTempDirectoryTest implements RewriteTest {

    @Override
    public void defaults(RecipeSpec spec) {
        spec.recipe(new UseFilesCreateTempDirectory());
    }

    @Test
    void useFilesCreateTempDirectory() {
        //language=java
        rewriteRun(
          java(
            """
              import java.io.File;
              import java.io.IOException;

              class A {
                  void b() throws IOException {
                      File tempDir;
                      tempDir = File.createTempFile("OverridesTest", "dir");
                      tempDir.delete();
                      tempDir.mkdir();
                      System.out.println(tempDir.getAbsolutePath());
                  }
              }
              """,
            """
              import java.io.File;
              import java.io.IOException;
              import java.nio.file.Files;

              class A {
                  void b() throws IOException {
                      File tempDir;
                      tempDir = Files.createTempDirectory("OverridesTest" + "dir").toFile();
                      System.out.println(tempDir.getAbsolutePath());
                  }
              }
              """
          )
        );
    }

    @Test
    void useFilesCreateTempDirectoryWithAsserts() {
        rewriteRun(
          spec -> spec.parser(JavaParser.fromJavaVersion().classpath("junit-jupiter")),
          //language=java
          java(
            """
              import java.io.File;
              import java.io.IOException;
              import static org.junit.jupiter.api.Assertions.assertTrue;

              class A {
                  void b() throws IOException {
                      File tempDir;
                      tempDir = File.createTempFile("OverridesTest", "dir");
                      assertTrue(tempDir.delete());
                      assertTrue(tempDir.mkdir());
                      System.out.println(tempDir.getAbsolutePath());
                  }
              }
              """,
            """
              import java.io.File;
              import java.io.IOException;
              import java.nio.file.Files;

              class A {
                  void b() throws IOException {
                      File tempDir;
                      tempDir = Files.createTempDirectory("OverridesTest" + "dir").toFile();
                      System.out.println(tempDir.getAbsolutePath());
                  }
              }
              """
          )
        );
    }

    @Test
    void useFilesCreateTempDirectoryWithAssertsFullyQualified() {
        rewriteRun(
          spec -> spec.parser(JavaParser.fromJavaVersion().classpath("junit-jupiter")),
          //language=java
          java(
            """
              import java.io.File;
              import java.io.IOException;
              import org.junit.jupiter.api.Assertions;

              class A {
                  void b() throws IOException {
                      File tempDir;
                      tempDir = File.createTempFile("OverridesTest", "dir");
                      Assertions.assertTrue(tempDir.delete());
                      Assertions.assertTrue(tempDir.mkdir());
                      System.out.println(tempDir.getAbsolutePath());
                  }
              }
              """,
            """
              import java.io.File;
              import java.io.IOException;
              import java.nio.file.Files;

              class A {
                  void b() throws IOException {
                      File tempDir;
                      tempDir = Files.createTempDirectory("OverridesTest" + "dir").toFile();
                      System.out.println(tempDir.getAbsolutePath());
                  }
              }
              """
          )
        );
    }

    @Test
    void useFilesCreateTempDirectoryWithJunit4Asserts() {
        rewriteRun(
          spec -> spec.parser(JavaParser.fromJavaVersion().classpath("junit")),
          //language=java
          java(
            """
              import java.io.File;
              import java.io.IOException;
              import static org.junit.Assert.assertTrue;

              class A {
                  void b() throws IOException {
                      File tempDir;
                      tempDir = File.createTempFile("OverridesTest", "dir");
                      assertTrue(tempDir.delete());
                      assertTrue(tempDir.mkdir());
                      System.out.println(tempDir.getAbsolutePath());
                  }
              }
              """,
            """
              import java.io.File;
              import java.io.IOException;
              import java.nio.file.Files;

              class A {
                  void b() throws IOException {
                      File tempDir;
                      tempDir = Files.createTempDirectory("OverridesTest" + "dir").toFile();
                      System.out.println(tempDir.getAbsolutePath());
                  }
              }
              """
          )
        );
    }

    @Test
    void useFilesCreateTempDirectoryWithJunit4AssertsWithMessages() {
        rewriteRun(
          spec -> spec.parser(JavaParser.fromJavaVersion().classpath("junit")),
          //language=java
          java(
            """
              import java.io.File;
              import java.io.IOException;
              import static org.junit.Assert.assertTrue;

              class A {
                  void b() throws IOException {
                      File tempDir;
                      tempDir = File.createTempFile("OverridesTest", "dir");
                      assertTrue("delete", tempDir.delete());
                      assertTrue("mkdir", tempDir.mkdir());
                      System.out.println(tempDir.getAbsolutePath());
                  }
              }
              """,
            """
              import java.io.File;
              import java.io.IOException;
              import java.nio.file.Files;

              class A {
                  void b() throws IOException {
                      File tempDir;
                      tempDir = Files.createTempDirectory("OverridesTest" + "dir").toFile();
                      System.out.println(tempDir.getAbsolutePath());
                  }
              }
              """
          )
        );
    }

    @Test
    void useFilesCreateTempDirectoryWithParentDir() {
        //language=java
        rewriteRun(
          java(
            """
              import java.io.File;
              import java.io.IOException;
              import java.nio.file.Files;

              class A {
                  File testData = Files.createTempDirectory("").toFile();
                  void b() throws IOException {
                      File tmpDir = File.createTempFile("test", "dir", testData);
                      tmpDir.delete();
                      tmpDir.mkdir();
                  }
              }
              """,
            """
              import java.io.File;
              import java.io.IOException;
              import java.nio.file.Files;

              class A {
                  File testData = Files.createTempDirectory("").toFile();
                  void b() throws IOException {
                      File tmpDir = Files.createTempDirectory(testData.toPath(), "test" + "dir").toFile();
                  }
              }
              """
          )
        );
    }

    @Test
    void useFilesCreateTempDirectory2() {
        //language=java
        rewriteRun(
          java(
            """
              import java.io.File;
              import java.io.IOException;

              class A {
                  void b() throws IOException {
                      File tempDir = File.createTempFile("abc", "def");
                      tempDir.delete();
                      tempDir.mkdir();
                      System.out.println(tempDir.getAbsolutePath());
                      tempDir = File.createTempFile("efg", "hij");
                      tempDir.delete();
                      tempDir.mkdir();
                      System.out.println(tempDir.getAbsolutePath());
                  }
              }
              """,
            """
              import java.io.File;
              import java.io.IOException;
              import java.nio.file.Files;

              class A {
                  void b() throws IOException {
                      File tempDir = Files.createTempDirectory("abc" + "def").toFile();
                      System.out.println(tempDir.getAbsolutePath());
                      tempDir = Files.createTempDirectory("efg" + "hij").toFile();
                      System.out.println(tempDir.getAbsolutePath());
                  }
              }
              """
          )
        );
    }

    @Test
    void onlySupportAssignmentToJIdentifier() {
        //language=java
        rewriteRun(
          java(
            """
              package abc;
              import java.io.File;
              public class C {
                  public static File FILE;
              }
              """
          ),
          java(
            """
              package abc;
              import java.io.File;
              import java.io.IOException;

              class A {
                  void b() throws IOException {
                      C.FILE = File.createTempFile("cfile", "txt");
                      File tempDir = File.createTempFile("abc", "png");
                      tempDir.delete();
                      tempDir.mkdir();
                  }
              }
              """,
            """
              package abc;
              import java.io.File;
              import java.io.IOException;
              import java.nio.file.Files;

              class A {
                  void b() throws IOException {
                      C.FILE = File.createTempFile("cfile", "txt");
                      File tempDir = Files.createTempDirectory("abc" + "png").toFile();
                  }
              }
              """
          )
        );
    }

    @SuppressWarnings("RedundantThrows")
    @Test
    void vulnerableFileMkdirWithTmpdirPathParam() {
        //language=java
        rewriteRun(
          java(
            """
              import java.io.File;
              import java.io.IOException;

              class T {
                  void vulnerableFileCreateTempFileMkdirTainted() throws IOException {
                      File tempDirChild = new File(System.getProperty("java.io.tmpdir"), "/child");
                      tempDirChild.mkdir();
                  }
              }
              """
          )
        );
    }

    @Test
    void vulnerableFileMkdirWithTmpdirPathParamDoesNotThrowException() {
        //language=java
        rewriteRun(
          java(
            """
              import java.io.File;
              import java.io.IOException;

              class T {
                  void vulnerableFileCreateTempFileMkdirTainted() {
                      File tempDirChild = new File(System.getProperty("java.io.tmpdir"), "/child");
                      tempDirChild.mkdir();
                  }
              }
              """
          )
        );
    }

    @Test
    void usesMkdirsRecipeASsumesThatTheDirectoryExistsOtherwiseTheExistingCodeWouldAlsoFail() {
        //language=java
        rewriteRun(
          java(
            """
              import java.io.File;
              import java.io.IOException;

              class T {
                  public void doSomething() throws IOException {
                      File tmpDir = new File("/some/dumb/thing");
                      tmpDir.mkdirs();
                      if (!tmpDir.isDirectory()) {
                          System.out.println("Mkdirs failed to create " + tmpDir);
                      }
                      final File workDir = File.createTempFile("unjar", "", tmpDir);
                      workDir.delete();
                      workDir.mkdirs();
                      if (!workDir.isDirectory()) {
                          System.out.println("Mkdirs failed to create " + workDir);
                      }
                  }
              }
              """,
            """
              import java.io.File;
              import java.io.IOException;
              import java.nio.file.Files;

              class T {
                  public void doSomething() throws IOException {
                      File tmpDir = new File("/some/dumb/thing");
                      tmpDir.mkdirs();
                      if (!tmpDir.isDirectory()) {
                          System.out.println("Mkdirs failed to create " + tmpDir);
                      }
                      final File workDir = Files.createTempDirectory(tmpDir.toPath(), "unjar").toFile();
                      if (!workDir.isDirectory()) {
                          System.out.println("Mkdirs failed to create " + workDir);
                      }
                  }
              }
              """
          )
        );
    }

    @Test
    void deleteWrappedInAnIfBlock() {
        //language=java
        rewriteRun(
          java(
            """
              import java.io.File;
              import java.io.IOException;
              import java.nio.file.Files;

              class A {
                  File testData = Files.createTempDirectory("").toFile();
                  void b() throws IOException {
                      File tmpDir = File.createTempFile("test", "dir", testData);
                      if (!tmpDir.delete()) {
                          System.out.println("Failed to delete directory!");
                      }
                      tmpDir.mkdir();
                  }
              }
              """,
            """
              import java.io.File;
              import java.io.IOException;
              import java.nio.file.Files;

              class A {
                  File testData = Files.createTempDirectory("").toFile();
                  void b() throws IOException {
                      File tmpDir = Files.createTempDirectory(testData.toPath(), "test" + "dir").toFile();
                  }
              }
              """
          )
        );
    }

    @Test
    void deleteAndMkdirsWrappedInAnIfBlock() {
        //language=java
        rewriteRun(
          java(
            """
              import java.io.File;
              import java.io.IOException;
              import java.nio.file.Files;

              class A {
                  File testData = Files.createTempDirectory("").toFile();
                  void b() throws IOException {
                      File tmpDir = File.createTempFile("test", "dir", testData);
                      if (!tmpDir.delete() || !tmpDir.mkdir()) {
                          throw new IOException("Failed to or create directory!");
                      }
                  }
              }
              """,
            """
              import java.io.File;
              import java.io.IOException;
              import java.nio.file.Files;

              class A {
                  File testData = Files.createTempDirectory("").toFile();
                  void b() throws IOException {
                      File tmpDir = Files.createTempDirectory(testData.toPath(), "test" + "dir").toFile();
                  }
              }
              """
          )
        );
    }

    @SuppressWarnings("ConstantConditions")
    @Test
    void booleanOperatorOnRaceCalls() {
        //language=java
        rewriteRun(
          java(
            """
              import java.io.File;
              import java.io.IOException;

              class A {
                  File b() throws IOException {
                      boolean success = true;
                      File temp = File.createTempFile("test", "directory");
                      success &= temp.delete();
                      success &= temp.mkdir();
                      if (success) {
                          return temp;
                      } else {
                          throw new RuntimeException("Failed to create directory");
                      }
                  }
              }
              """,
            """
              import java.io.File;
              import java.io.IOException;
              import java.nio.file.Files;

              class A {
                  File b() throws IOException {
                      boolean success = true;
                      File temp = Files.createTempDirectory("test" + "directory").toFile();
                      if (success) {
                          return temp;
                      } else {
                          throw new RuntimeException("Failed to create directory");
                      }
                  }
              }
              """
          )
        );
    }

    @Test
    void multipleCallsToDelete() {
        //language=java
        rewriteRun(
          java(
            """
              import java.io.File;
              import java.io.FileWriter;
              import java.io.IOException;

              class A {
                  void b() throws IOException {
                      boolean success = true;
                      File temp = File.createTempFile("test", "directory");
                      temp.delete();
                      temp.mkdir();
                      File textFile = new File(temp, "test.txt");
                      try (FileWriter writer = new FileWriter(textFile)) {
                          writer.write("Hello World!");
                      } finally {
                          textFile.delete();
                          temp.delete();
                      }
                  }
              }
              """,
            """
              import java.io.File;
              import java.io.FileWriter;
              import java.io.IOException;
              import java.nio.file.Files;

              class A {
                  void b() throws IOException {
                      boolean success = true;
                      File temp = Files.createTempDirectory("test" + "directory").toFile();
                      File textFile = new File(temp, "test.txt");
                      try (FileWriter writer = new FileWriter(textFile)) {
                          writer.write("Hello World!");
                      } finally {
                          textFile.delete();
                          temp.delete();
                      }
                  }
              }
              """
          )
        );
    }

    @Test
    void strangeChainThatCallsThroughNewFile() {
        //language=java
        rewriteRun(
          java(
            """
              import java.io.File;
              import java.io.FileWriter;
              import java.io.IOException;

              class A {
                  void createWorkingDir() throws IOException {
                      File temp = File.createTempFile("temp", Long.toString(System.nanoTime()));
                      temp.delete();
                      temp = new File(temp.getAbsolutePath() + ".d");
                      temp.mkdir();
                  }
              }
              """
          )
        );
    }

    @Test
    void preventCreatingNewNpeAndEmptyStringConcatenation() {
        //language=java
        rewriteRun(
          java(
            """
              import java.io.File;
              import java.io.IOException;

              class T {
                  private void initTmpDir() {
                      try {
                          File temporaryDirectory = File.createTempFile("benchmark-reports", "", null);
                          if (!temporaryDirectory.delete() || !temporaryDirectory.mkdir()) {
                              throw new IOException("Unable to create temporary directory.\\n" + temporaryDirectory.getCanonicalPath());
                          }
                      } catch (IOException e) {
                         e.printStackTrace();
                      }
                  }
              }
              """,
            """
              import java.io.File;
              import java.io.IOException;
              import java.nio.file.Files;

              class T {
                  private void initTmpDir() {
                      try {
                          File temporaryDirectory = Files.createTempDirectory("benchmark-reports").toFile();
                      } catch (IOException e) {
                         e.printStackTrace();
                      }
                  }
              }
              """
          )
        );
    }

    @SuppressWarnings("UnnecessaryLocalVariable")
    @Test
    void removeIfBlockWhenBothDeleteAndMkdirIsRemoved() {
        //language=java
        rewriteRun(
          java(
            """
              import java.io.File;
              import java.io.IOException;

              class Test {
                  private File createTmpDir() throws IOException {
                      File dir = File.createTempFile("artifact", "copy");
                      if (!(dir.delete() && dir.mkdirs())) {
                          throw new IOException("Failed to create temporary directory " + dir.getPath());
                      }
                      return dir;
                  }
              }
              """,
            """
              import java.io.File;
              import java.io.IOException;
              import java.nio.file.Files;

              class Test {
                  private File createTmpDir() throws IOException {
                      File dir = Files.createTempDirectory("artifact" + "copy").toFile();
                      return dir;
                  }
              }
              """
          )
        );
    }
}
