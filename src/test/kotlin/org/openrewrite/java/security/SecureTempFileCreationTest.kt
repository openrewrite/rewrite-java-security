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
package org.openrewrite.java.security

import org.junit.jupiter.api.Test
import org.openrewrite.Issue
import org.openrewrite.java.Assertions.java
import org.openrewrite.test.RecipeSpec
import org.openrewrite.test.RewriteTest

class SecureTempFileCreationTest : RewriteTest {

    override fun defaults(spec: RecipeSpec) {
        spec.recipe(SecureTempFileCreation())
    }

    @Test
    fun twoArgCreateTempFile() = rewriteRun(
        java("""
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
        """)
    )

    @Test
    fun threeArgCreateTempFile() = rewriteRun(
        java("""
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
        """)
    )

    @Test
    fun insideTryCatch() =  rewriteRun(
        java("""
            import java.io.File;
            
            class T {
                private static void foo(File location) {
                    try {
                        File temp = File.createTempFile("random", "file", location);
                    } catch (Exception e) {
                        File temp = File.createTempFile("random", "file", null);
                    }
                }
            }
        """,
            """
            import java.io.File;
            import java.nio.file.Files;
            
            class T {
                private static void foo(File location) {
                    try {
                        File temp = Files.createTempFile(location.toPath(), "random", "file").toFile();
                    } catch (Exception e) {
                        File temp = Files.createTempFile("random", "file").toFile();
                    }
                }
            }
        """)
    )

    /**
     * If the issue could be fixed by the [UseFilesCreateTempDirectory] recipe, then this recipe should not be run.
     */
    @Test
    @Issue("https://github.com/openrewrite/rewrite-java-security/issues/9")
    fun `do not fix temporary directory hijacking`() = rewriteRun(
        java("""
            class A {
                void b() {
                    File tempDir = File.createTempFile("abc", "def");
                    tempDir.delete();
                    tempDir.mkdir();
                    System.out.println(tempDir.getAbsolutePath());
                }
            }
        """)
    )
}
