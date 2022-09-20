package org.openrewrite.java.security

import org.junit.jupiter.api.Test
import org.openrewrite.java.Assertions.java
import org.openrewrite.test.RecipeSpec
import org.openrewrite.test.RewriteTest

class RegularExpressionDenialOfServiceTest: RewriteTest {
    override fun defaults(spec: RecipeSpec) {
        spec.recipe(RegularExpressionDenialOfService())
    }

    @Test
    fun `fix ReDOS for simple string`() = rewriteRun(
        java(
            """
            class Test {
                private static final String testRe = "(.|\\s)*";
            }
            """,
            """
            class Test {
                private static final String testRe = "(.|\n|\r)*";
            }
            """
        )
    )
}
