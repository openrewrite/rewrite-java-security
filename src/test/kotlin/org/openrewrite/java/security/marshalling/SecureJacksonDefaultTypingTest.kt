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
package org.openrewrite.java.security.marshalling

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
                ObjectMapper o2 = new ObjectMapper().enableDefaultTyping(ObjectMapper.DefaultTyping.NON_FINAL);
            }
        """,
        after = """
            import com.fasterxml.jackson.databind.ObjectMapper;
            import com.fasterxml.jackson.databind.jsontype.BasicPolymorphicTypeValidator;
            
            class Test {
                ObjectMapper o = new ObjectMapper().activateDefaultTyping(BasicPolymorphicTypeValidator.builder().build());
                ObjectMapper o2 = new ObjectMapper().activateDefaultTyping(BasicPolymorphicTypeValidator.builder().build(), ObjectMapper.DefaultTyping.NON_FINAL);
            }
        """
    )
}
