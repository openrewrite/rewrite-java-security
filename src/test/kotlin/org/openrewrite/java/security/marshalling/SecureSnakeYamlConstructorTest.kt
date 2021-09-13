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

class SecureSnakeYamlConstructorTest: JavaRecipeTest {
    override val parser: JavaParser
        get() = JavaParser.fromJavaVersion()
            .classpath("snakeyaml")
            .build()

    override val recipe: Recipe
        get() = SecureSnakeYamlConstructor()

    @Test
    fun snakeYamlConstructor() = assertChanged(
        before = """
            import org.yaml.snakeyaml.Yaml;
            
            class Test {
                Object o = new Yaml();
            }
        """,
        after = """
            import org.yaml.snakeyaml.Yaml;
            import org.yaml.snakeyaml.constructor.SafeConstructor;
            
            class Test {
                Object o = new Yaml(new SafeConstructor());
            }
        """
    )
}
