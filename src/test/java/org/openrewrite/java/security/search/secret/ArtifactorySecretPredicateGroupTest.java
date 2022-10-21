package org.openrewrite.java.security.search.secret;

import org.junit.jupiter.api.Test;
import org.openrewrite.test.RecipeSpec;
import org.openrewrite.test.RewriteTest;

import java.util.List;

import static org.openrewrite.java.Assertions.java;

public class ArtifactorySecretPredicateGroupTest implements RewriteTest {
    @Override
    public void defaults(RecipeSpec spec) {
        spec.recipe(new FindSecrets(List.of("Artifactory Password", "Artifactory API Token")));
    }

    @Test
    void artifactorySecrets() {
        rewriteRun(
                //language=java
                java("""
                    class Test {
                        String[] artifactoryStrings = {
                            "AP6xxxxxxxxxx",
                            "AP2xxxxxxxxxx",
                            "AP3xxxxxxxxxx",
                            "AP5xxxxxxxxxx",
                            "APAxxxxxxxxxx",
                            "APBxxxxxxxxxx",
                            "AKCxxxxxxxxxx",
                            " AP6xxxxxxxxxx",
                            " AKCxxxxxxxxxx",
                            "=AP6xxxxxxxxxx",
                            "=AKCxxxxxxxxxx",
                            "\\"AP6xxxxxxxxxx\\"",
                            "\\"AKCxxxxxxxxxx\\"",
                            "artif-key:AP6xxxxxxxxxx",
                            "artif-key:AKCxxxxxxxxxx",
                            "X-JFrog-Art-Api: AKCxxxxxxxxxx",
                            "X-JFrog-Art-Api: AP6xxxxxxxxxx",
                            "artifactoryx:_password=AKCxxxxxxxxxx",
                            "artifactoryx:_password=AP6xxxxxxxxxx",
                            "testAKCwithinsomeirrelevantstring",
                            "testAP6withinsomeirrelevantstring",
                            "X-JFrog-Art-Api: $API_KEY",
                            "X-JFrog-Art-Api: $PASSWORD",
                            "artifactory:_password=AP6xxxxxx",
                            "artifactory:_password=AKCxxxxxxxx"};
                    }
                """,
        """
                    class Test {
                        String[] artifactoryStrings = {
                            /*~~(Artifactory)~~>*/"AP6xxxxxxxxxx",
                            /*~~(Artifactory)~~>*/"AP2xxxxxxxxxx",
                            /*~~(Artifactory)~~>*/"AP3xxxxxxxxxx",
                            /*~~(Artifactory)~~>*/"AP5xxxxxxxxxx",
                            /*~~(Artifactory)~~>*/"APAxxxxxxxxxx",
                            /*~~(Artifactory)~~>*/"APBxxxxxxxxxx",
                            /*~~(Artifactory)~~>*/"AKCxxxxxxxxxx",
                            /*~~(Artifactory)~~>*/" AP6xxxxxxxxxx",
                            /*~~(Artifactory)~~>*/" AKCxxxxxxxxxx",
                            /*~~(Artifactory)~~>*/"=AP6xxxxxxxxxx",
                            /*~~(Artifactory)~~>*/"=AKCxxxxxxxxxx",
                            /*~~(Artifactory)~~>*/"\\"AP6xxxxxxxxxx\\"",
                            /*~~(Artifactory)~~>*/"\\"AKCxxxxxxxxxx\\"",
                            /*~~(Artifactory)~~>*/"artif-key:AP6xxxxxxxxxx",
                            /*~~(Artifactory)~~>*/"artif-key:AKCxxxxxxxxxx",
                            /*~~(Artifactory)~~>*/"X-JFrog-Art-Api: AKCxxxxxxxxxx",
                            /*~~(Artifactory)~~>*/"X-JFrog-Art-Api: AP6xxxxxxxxxx",
                            /*~~(Artifactory)~~>*/"artifactoryx:_password=AKCxxxxxxxxxx",
                            /*~~(Artifactory)~~>*/"artifactoryx:_password=AP6xxxxxxxxxx",
                            "testAKCwithinsomeirrelevantstring",
                            "testAP6withinsomeirrelevantstring",
                            "X-JFrog-Art-Api: $API_KEY",
                            "X-JFrog-Art-Api: $PASSWORD",
                            "artifactory:_password=AP6xxxxxx",
                            "artifactory:_password=AKCxxxxxxxx"};
                    }
                """)
        );
    }
}
