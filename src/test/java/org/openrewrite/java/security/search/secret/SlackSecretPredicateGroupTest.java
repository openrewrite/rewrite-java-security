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

import static org.openrewrite.yaml.Assertions.yaml;

public class SlackSecretPredicateGroupTest implements RewriteTest {
    @Override
    public void defaults(RecipeSpec spec) {
        spec.recipe(new FindSecrets(List.of("Slack WebHook", "Slack Token")));
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
