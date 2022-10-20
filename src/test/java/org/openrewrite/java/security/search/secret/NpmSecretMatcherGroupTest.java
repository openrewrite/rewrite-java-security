package org.openrewrite.java.security.search.secret;

import org.junit.jupiter.api.Test;
import org.openrewrite.test.RecipeSpec;
import org.openrewrite.test.RewriteTest;

import java.util.List;

import static org.openrewrite.java.Assertions.java;

public class NpmSecretMatcherGroupTest implements RewriteTest {
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
