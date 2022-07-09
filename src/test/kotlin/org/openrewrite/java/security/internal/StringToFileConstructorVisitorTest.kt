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

    @Test
    fun `FileOutputStream String appended File#seperator`() = rewriteRun(
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
    )

    @Test
    fun `FileOutputStream String appended File#separatorChar`() = rewriteRun(
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
    )

    @Test
    fun `FileOutputStream String with slash appended`() = rewriteRun(
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
    )

    @Test
    fun `FileOutputStream String appended File#seperator and appended file extension`() = rewriteRun(
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
    )
}
