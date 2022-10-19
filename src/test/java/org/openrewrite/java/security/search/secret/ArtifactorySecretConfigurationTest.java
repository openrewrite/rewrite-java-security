package org.openrewrite.java.security.search.secret;

import org.junit.jupiter.api.Test;
import org.openrewrite.test.RecipeSpec;
import org.openrewrite.test.RewriteTest;

import static org.openrewrite.java.Assertions.java;

public class ArtifactorySecretConfigurationTest implements RewriteTest {
    @Override
    public void defaults(RecipeSpec spec) {
        spec.recipe(new DetectSecrets());
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
                            /*~~(Artifactory Password)~~>*/"AP6xxxxxxxxxx",
                            /*~~(Artifactory Password)~~>*/"AP2xxxxxxxxxx",
                            /*~~(Artifactory Password)~~>*/"AP3xxxxxxxxxx",
                            /*~~(Artifactory Password)~~>*/"AP5xxxxxxxxxx",
                            /*~~(Artifactory Password)~~>*/"APAxxxxxxxxxx",
                            /*~~(Artifactory Password)~~>*/"APBxxxxxxxxxx",
                            /*~~(Artifactory API Token)~~>*/"AKCxxxxxxxxxx",
                            /*~~(Artifactory Password)~~>*/" AP6xxxxxxxxxx",
                            /*~~(Artifactory API Token)~~>*/" AKCxxxxxxxxxx",
                            /*~~(Artifactory Password)~~>*/"=AP6xxxxxxxxxx",
                            /*~~(Artifactory API Token)~~>*/"=AKCxxxxxxxxxx",
                            /*~~(Artifactory Password)~~>*/"\\"AP6xxxxxxxxxx\\"",
                            /*~~(Artifactory API Token)~~>*/"\\"AKCxxxxxxxxxx\\"",
                            /*~~(Artifactory Password)~~>*/"artif-key:AP6xxxxxxxxxx",
                            /*~~(Artifactory API Token)~~>*/"artif-key:AKCxxxxxxxxxx",
                            /*~~(Artifactory API Token)~~>*/"X-JFrog-Art-Api: AKCxxxxxxxxxx",
                            /*~~(Artifactory Password)~~>*/"X-JFrog-Art-Api: AP6xxxxxxxxxx",
                            /*~~(Artifactory API Token)~~>*/"artifactoryx:_password=AKCxxxxxxxxxx",
                            /*~~(Artifactory Password)~~>*/"artifactoryx:_password=AP6xxxxxxxxxx",
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
