package org.openrewrite.java.security.internal

import org.junit.jupiter.api.Test
import org.openrewrite.test.RecipeSpec
import org.openrewrite.test.RewriteTest

class FileConstructorVisitorFixTest: RewriteTest {
    override fun defaults(spec: RecipeSpec) {
        spec.recipe(RewriteTest.toRecipe { FileConstructorFixVisitor() })
    }

    @Test
    fun doesNotChangeConstructorWhenNonSlashAppended() = rewriteRun(
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
    )
}
