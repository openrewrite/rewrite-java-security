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

public class NpmSecretPredicateGroupTest implements RewriteTest {
    @Override
    public void defaults(RecipeSpec spec) {
        spec.recipe(new FindSecrets(List.of("NPM Token")));
    }
    @Test
    void npmSecrets() {
        rewriteRun(
                //language=java
                java("""
                        class Test {
                            void npmTest() {
                                String[] npmSecrets = {
                                    "//registry.npmjs.org/:_authToken=743b294a-cd03-11ec-9d64-0242ac120002",
                                    "//registry.npmjs.org/:_authToken=346a14f2-a672-4668-a892-956a462ab56e",
                                    "//registry.npmjs.org/:_authToken= 743b294a-cd03-11ec-9d64-0242ac120002",
                                    "//registry.npmjs.org/:_authToken=npm_xxxxxxxxxxx"};
                                String[] notNmpSecrets = {
                                    "//registry.npmjs.org:_authToken=743b294a-cd03-11ec-9d64-0242ac120002",
                                    "registry.npmjs.org/:_authToken=743b294a-cd03-11ec-9d64-0242ac120002",
                                    "///:_authToken=743b294a-cd03-11ec-9d64-0242ac120002",
                                    "_authToken=743b294a-cd03-11ec-9d64-0242ac120002",
                                    "foo",
                                    "//registry.npmjs.org/:_authToken=${NPM_TOKEN}"};
                            }
                        }
                    """,
            """
                        class Test {
                            void npmTest() {
                                String[] npmSecrets = {
                                    /*~~(NPM Token)~~>*/"//registry.npmjs.org/:_authToken=743b294a-cd03-11ec-9d64-0242ac120002",
                                    /*~~(NPM Token)~~>*/"//registry.npmjs.org/:_authToken=346a14f2-a672-4668-a892-956a462ab56e",
                                    /*~~(NPM Token)~~>*/"//registry.npmjs.org/:_authToken= 743b294a-cd03-11ec-9d64-0242ac120002",
                                    /*~~(NPM Token)~~>*/"//registry.npmjs.org/:_authToken=npm_xxxxxxxxxxx"};
                                String[] notNmpSecrets = {
                                    "//registry.npmjs.org:_authToken=743b294a-cd03-11ec-9d64-0242ac120002",
                                    "registry.npmjs.org/:_authToken=743b294a-cd03-11ec-9d64-0242ac120002",
                                    "///:_authToken=743b294a-cd03-11ec-9d64-0242ac120002",
                                    "_authToken=743b294a-cd03-11ec-9d64-0242ac120002",
                                    "foo",
                                    "//registry.npmjs.org/:_authToken=${NPM_TOKEN}"};
                            }
                        }
                    """)
        );
    }

}
