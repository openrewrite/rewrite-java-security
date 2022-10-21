package org.openrewrite.java.security.search.secret;

import org.openrewrite.ExecutionContext;
import org.openrewrite.HttpSenderExecutionContextView;
import org.openrewrite.internal.lang.Nullable;
import org.openrewrite.ipc.http.HttpSender;

import java.util.regex.Pattern;

public class SlackSecretPredicateGroup implements SecretPredicateGroup {
    @Override
    public String getName() {
        return "Slack Token";
    }

    @Override
    public SecretPredicate<String, String, ExecutionContext> secretPredicate() {
        return new SecretRegexPredicate(null, "(xox[pboa]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})")
                .or(new SecretRegexPredicate(null, "xox(?:a|b|p|o|s|r)-(?:\\d+-)+[a-z0-9]+"))
                .or(new SecretPredicate<String, String, ExecutionContext>() {
                    private final Pattern slackPattern = Pattern.compile("https://hooks\\.slack\\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}");
                    @Override
                    public boolean isSecret(@Nullable String key, @Nullable String value, ExecutionContext ctx) {
                        if (value != null && slackPattern.matcher(value).find()) {
                            HttpSender httpSender = HttpSenderExecutionContextView.view(ctx).getHttpSender();
                            // POST Test to slack
                        }
                        return false;
                    }
                });
    }
}
