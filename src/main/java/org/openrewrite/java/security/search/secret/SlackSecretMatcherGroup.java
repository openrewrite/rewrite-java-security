package org.openrewrite.java.security.search.secret;

import org.openrewrite.HttpSenderExecutionContextView;
import org.openrewrite.ipc.http.HttpSender;

public class SlackSecretMatcherGroup implements SecretMatcherGroup {
    @Override
    public SecretMatcher[] secretMatchers() {
        return new SecretMatcher[]{
                SecretMatcher.builder("Slack Token")
                        .valueRegex("(xox[pboa]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})")
                        .build(),
                SecretMatcher.builder("Slack Token")
                        .valueRegex("xox(?:a|b|p|o|s|r)-(?:\\d+-)+[a-z0-9]+")
                        .build(),
                SecretMatcher.builder("Slack WebHook")
                        .valueRegex("https://hooks\\.slack\\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}")
                        .secretValidator((k, v, ctx) -> {
                            // https://github.com/Yelp/detect-secrets/blob/001e16323a2f0162336345f4ceb6d72c204980b5/detect_secrets/plugins/slack.py#L29-L51
                            HttpSender httpSender = HttpSenderExecutionContextView.view(ctx).getHttpSender();
                            if (v.startsWith("https://hooks.slack.com/services/T")) {
                                //httpSender.post()
                            }
                            return true;
                        })
                        .build()
        };
    }
}
