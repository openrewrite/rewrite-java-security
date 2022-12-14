/*
 * Copyright 2022 the original author or authors.
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

import org.intellij.lang.annotations.Language;
import org.junit.jupiter.api.Test;
import org.openrewrite.test.RecipeSpec;
import org.openrewrite.test.RewriteTest;

import static org.openrewrite.java.Assertions.java;
import static org.openrewrite.test.SourceSpecs.dir;

public class SecureTempFileCreationFilteringTest implements RewriteTest {

    @Language("java")
    private static final String PRODUCTION_TEMP_DIR_HIJACKING_VULNERABLE = """
      import java.io.File;
      import java.io.IOException;
                  
      class ProductionTempDirHijacking {
          static void method() throws IOException {
              File tempDir = File.createTempFile("hello", "world");
              tempDir.delete();
              tempDir.mkdir();
          }
      }
      """;

    @Language("java")
    private static final String PRODUCTION_VULNERABLE = """
      import java.io.File;
      import java.io.IOException;
        
      class Production {
        static void productionMethod() throws IOException {
          File tempDir = File.createTempFile("hello", "world");
        }
      }
      """;

    @Language("java")
    private static final String PRODUCTION_SAFE = """
      import java.io.File;
      import java.io.IOException;
      import java.nio.file.Files;
        
      class Production {
        static void productionMethod() throws IOException {
          File tempDir = Files.createTempFile("hello", "world").toFile();
        }
      }
      """;

    @Language("java")
    private static final String TEST_VULNERABLE = """
      import java.io.File;
      import java.io.IOException;
        
      class Test {
        static void testMethod() throws IOException {
          File tempDir = File.createTempFile("hello", "world");
        }
      }
      """;

    @Language("java")
    private static final String TEST_SAFE = """
      import java.io.File;
      import java.io.IOException;
      import java.nio.file.Files;
        
      class Test {
        static void testMethod() throws IOException {
          File tempDir = Files.createTempFile("hello", "world").toFile();
        }
      }
      """;

    @Override
    public void defaults(RecipeSpec spec) {
        spec.recipe(new SecureTempFileCreation(SecureTempFileCreation.Target.ALL_SOURCE_IF_DETECTED_IN_NON_TEST));
    }

    @Test
    void vulnerableTestFile() {
        rewriteRun(
          dir(
            "src/test/java/org/openrewrite/java/security/",
            java(TEST_VULNERABLE)
          )
        );
    }

    @Test
    void vulnerableProductionFile() {
        rewriteRun(
          dir(
            "src/main/java/org/openrewrite/java/security/",
            java(PRODUCTION_VULNERABLE, PRODUCTION_SAFE)
          )
        );
    }

    @Test
    void vulnerableTestAndProductionFile() {
        rewriteRun(
          dir(
            "src/main/java/org/openrewrite/java/security/",
            java(PRODUCTION_VULNERABLE, PRODUCTION_SAFE)
          ),
          dir(
            "src/test/java/org/openrewrite/java/security/",
            java(TEST_VULNERABLE, TEST_SAFE)
          )
        );
    }

    @Test
    void vulnerableTempDirHijackingDoesNotTriggerChangesToTests() {
        rewriteRun(
          dir(
            "src/main/java/org/openrewrite/java/security/",
            java(PRODUCTION_TEMP_DIR_HIJACKING_VULNERABLE)
          ),
          dir(
            "src/test/java/org/openrewrite/java/security/",
            java(TEST_VULNERABLE)
          )
        );
    }
}
