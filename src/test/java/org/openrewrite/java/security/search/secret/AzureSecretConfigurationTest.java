package org.openrewrite.java.security.search.secret;

import org.junit.jupiter.api.Test;
import org.openrewrite.test.RecipeSpec;
import org.openrewrite.test.RewriteTest;

import java.util.List;

import static org.openrewrite.yaml.Assertions.yaml;

class AzureSecretConfigurationTest implements RewriteTest {
    @Override
    public void defaults(RecipeSpec spec) {
        spec.recipe(new DetectSecrets(List.of("Azure Storage Account access key")));
    }
    @Test
    void findYamlSecret() {
        rewriteRun(
            //language=yaml
            yaml(
            """
               root:
                 AccountKey: lJzRc1YdHaAA2KCNJJ1tkYwF/+mKK6Ygw0NGe170Xu592euJv2wYUtBlV8z+qnlcNQSnIYVTkLWntUO1F8j8rQ==
               """,
               """
               root:
                 ~~(Azure Storage Account access key)~~>AccountKey: lJzRc1YdHaAA2KCNJJ1tkYwF/+mKK6Ygw0NGe170Xu592euJv2wYUtBlV8z+qnlcNQSnIYVTkLWntUO1F8j8rQ==
               """)
        );
    }
}
