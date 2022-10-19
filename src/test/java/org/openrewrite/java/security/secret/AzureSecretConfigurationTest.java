package org.openrewrite.java.security.secret;

import org.junit.jupiter.api.Test;

import static org.openrewrite.yaml.Assertions.yaml;

class AzureSecretConfigurationTest implements SecretConfigurationTest {
    @Override
    public SecretConfiguration secretConfiguration() {
        return new AzureSecretConfiguration();
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
