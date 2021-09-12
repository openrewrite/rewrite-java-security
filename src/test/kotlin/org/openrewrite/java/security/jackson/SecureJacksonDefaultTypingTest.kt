package org.openrewrite.java.security.jackson

import org.junit.jupiter.api.Test
import org.openrewrite.Recipe
import org.openrewrite.java.JavaParser
import org.openrewrite.java.JavaRecipeTest

class SecureJacksonDefaultTypingTest: JavaRecipeTest {
    override val parser: JavaParser
        get() = JavaParser.fromJavaVersion()
            .logCompilationWarningsAndErrors(true)
            .classpath("jackson-databind", "jackson-core")
            .build()

    override val recipe: Recipe
        get() = SecureJacksonDefaultTyping()

    @Test
    fun activateDefaultTyping() = assertChanged(
        before = """
            import com.fasterxml.jackson.databind.ObjectMapper;

            class Test {
                ObjectMapper o = new ObjectMapper().enableDefaultTyping();
            }
        """,
        after = """
            import com.fasterxml.jackson.databind.ObjectMapper;
            import com.fasterxml.jackson.databind.jsontype.BasicPolymorphicTypeValidator;
            
            class Test {
                ObjectMapper o = new ObjectMapper().activateDefaultTyping(BasicPolymorphicTypeValidator.builder().build());
            }
        """
    )
}
