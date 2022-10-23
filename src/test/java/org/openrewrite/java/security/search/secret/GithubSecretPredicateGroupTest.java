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
package org.openrewrite.java.security.search.secret;

import org.junit.jupiter.api.Test;
import org.openrewrite.test.RecipeSpec;
import org.openrewrite.test.RewriteTest;

import java.util.List;

import static org.openrewrite.java.Assertions.java;

public class GithubSecretPredicateGroupTest implements RewriteTest {
    @Override
    public void defaults(RecipeSpec spec) {
        spec.recipe(new FindSecrets(List.of("GitHub Token")));
    }

    @Test
    void githubSecrets() {
        rewriteRun(
                //language=java
                java("""
                    class Test {
                        void githubTest() {
                            String secret = "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";
                            String notSecret = "foo_wWPw5k4aXcaT4fNP0UcnZwJUVFk6LO0pINUx";
                        }
                    }
                """,
        """
                    class Test {
                        void githubTest() {
                            String secret = /*~~(GitHub)~~>*/"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";
                            String notSecret = "foo_wWPw5k4aXcaT4fNP0UcnZwJUVFk6LO0pINUx";
                        }
                    }
                """)
        );
    }
}
