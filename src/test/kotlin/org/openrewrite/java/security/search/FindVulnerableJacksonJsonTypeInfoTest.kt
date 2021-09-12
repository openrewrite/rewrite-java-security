package org.openrewrite.java.security.search

import org.junit.jupiter.api.Test
import org.openrewrite.Recipe
import org.openrewrite.java.JavaParser
import org.openrewrite.java.JavaRecipeTest

class FindVulnerableJacksonJsonTypeInfoTest : JavaRecipeTest {
    override val parser: JavaParser
        get() = JavaParser.fromJavaVersion()
            .classpath("jackson-annotations")
            .build()

    override val recipe: Recipe
        get() = FindVulnerableJacksonJsonTypeInfo()

    @Test
    fun idClass() = assertChanged(
        before = """
            import java.util.List;
            import com.fasterxml.jackson.annotation.JsonTypeInfo;
            import com.fasterxml.jackson.annotation.JsonTypeInfo.Id;
            
            class PenetrationTesting {
                @JsonTypeInfo(use = Id.CLASS)
                Object name;
                
                /*~~>*/@JsonTypeInfo(use = Id.CLASS)
                List<Object> names;
            
                int age;
            }
        """,
        after = """
            import java.util.List;
            import com.fasterxml.jackson.annotation.JsonTypeInfo;
            import com.fasterxml.jackson.annotation.JsonTypeInfo.Id;
            
            class PenetrationTesting {
                /*~~>*/@JsonTypeInfo(use = Id.CLASS)
                Object name;
                
                /*~~>*/@JsonTypeInfo(use = Id.CLASS)
                List<Object> names;
            
                int age;
            }
        """
    )
}
