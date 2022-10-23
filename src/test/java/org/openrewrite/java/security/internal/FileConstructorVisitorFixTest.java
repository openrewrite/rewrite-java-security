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
import org.openrewrite.test.RecipeSpec;
import org.openrewrite.test.RewriteTest;

import static org.openrewrite.java.Assertions.java;

class FileConstructorVisitorFixTest implements RewriteTest {

    @Override
    public void defaults(RecipeSpec spec) {
        spec.recipe(RewriteTest.toRecipe(FileConstructorFixVisitor::new));
    }

    @SuppressWarnings("UnnecessaryLocalVariable")
    @Test
    void doesNotChangeConstructorWhenNonSlashAppended() {
        rewriteRun(
          //language=java
          java(
            """
              import java.io.File;
              class Test {
                  public File exportTo(File original, String extension, byte[] bytes) {
                      File file = new File(original.getAbsolutePath() + extension);
                      // Do something with file...
                      return file;
                  }
              }
              """
          )
        );
    }
}
