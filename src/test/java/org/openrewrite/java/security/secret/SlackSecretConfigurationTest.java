package org.openrewrite.java.security.secret;

import org.junit.jupiter.api.Test;

import static org.openrewrite.yaml.Assertions.yaml;

public class SlackSecretConfigurationTest implements SecretConfigurationTest {
    @Override
    public SecretConfiguration secretConfiguration() {
        return new SlackSecretConfiguration();
    }

    @Test
    void slackWebHook() {
        rewriteRun(
                yaml("""
                        slack:
                          webHook: "https://hooks.slack.com/services/Txxxxxxxx/Bxxxxxxxx/xxxxxxxxxxxxxxxxxxxxxxxx"
                        """,
                        """
                        slack:
                          ~~(Slack WebHook)~~>webHook: "https://hooks.slack.com/services/Txxxxxxxx/Bxxxxxxxx/xxxxxxxxxxxxxxxxxxxxxxxx"
                        """)
        );
    }

    @Test
    void slackSecretTokens() {
        rewriteRun(
                yaml("""
                        slack:
                          s2: "xoxp-523423-234243-234233-e039d02840a0b9379c"
                          s3: "xoxo-523423-234243-234233-e039d02840a0b9379c"
                          s4: "xoxs-523423-234243-234233-e039d02840a0b9379c"
                          s5: "xoxa-511111111-31111111111-3111111111111-e039d02840a0b9379c"
                          s6: "xoxa-2-511111111-31111111111-3111111111111-e039d02840a0b9379c"
                          s7: "xoxr-523423-234243-234233-e039d02840a0b9379c"
                          s8: "xoxb-34532454-e039d02840a0b9379c"
                        """,
                        """
                        slack:
                          ~~(Slack Token)~~>s2: "xoxp-523423-234243-234233-e039d02840a0b9379c"
                          ~~(Slack Token)~~>s3: "xoxo-523423-234243-234233-e039d02840a0b9379c"
                          ~~(Slack Token)~~>s4: "xoxs-523423-234243-234233-e039d02840a0b9379c"
                          ~~(Slack Token)~~>s5: "xoxa-511111111-31111111111-3111111111111-e039d02840a0b9379c"
                          ~~(Slack Token)~~>s6: "xoxa-2-511111111-31111111111-3111111111111-e039d02840a0b9379c"
                          ~~(Slack Token)~~>s7: "xoxr-523423-234243-234233-e039d02840a0b9379c"
                          ~~(Slack Token)~~>s8: "xoxb-34532454-e039d02840a0b9379c"
                        """)
        );
    }
}
