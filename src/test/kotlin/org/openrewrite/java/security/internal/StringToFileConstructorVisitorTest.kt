package org.openrewrite.java.security.internal

import org.junit.jupiter.api.Test
import org.openrewrite.test.RecipeSpec
import org.openrewrite.test.RewriteTest

class StringToFileConstructorVisitorTest: RewriteTest {
    override fun defaults(spec: RecipeSpec) {
        spec.recipe(RewriteTest.toRecipe { StringToFileConstructorVisitor() })
    }

    @Test
    fun `FileOutputStream string literal to new File`() = rewriteRun(
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
    )
}
