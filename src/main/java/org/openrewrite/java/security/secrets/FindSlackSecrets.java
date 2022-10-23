package org.openrewrite.java.security.secrets;

import org.openrewrite.ExecutionContext;
import org.openrewrite.HttpSenderExecutionContextView;
import org.openrewrite.Recipe;
import org.openrewrite.TreeVisitor;
import org.openrewrite.internal.lang.Nullable;
import org.openrewrite.ipc.http.HttpSender;

import java.util.regex.Pattern;

public class FindSlackSecrets extends Recipe {

    @Override
    public String getDisplayName() {
        return "Find Slack secrets";
    }

    @Override
    public String getDescription() {
        return "Locates Slack secrets stored in plain text in code.";
    }

    public FindSlackSecrets() {
        doNext(new FindSecretsByPattern("Slack", null, "(xox[pboa]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})"));
        doNext(new FindSecretsByPattern("Slack", null, "xox(?:a|b|p|o|s|r)-(?:\\d+-)+[a-z0-9]+"));
    }

    @Override
    protected TreeVisitor<?, ExecutionContext> getVisitor() {
        return new FindSecretsVisitor("Slack") {
            private final Pattern valuePattern = Pattern.compile("https://hooks\\.slack\\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}");

            @Override
            protected boolean isSecret(@Nullable String key, @Nullable String value, ExecutionContext ctx) {
                if (value != null && valuePattern.matcher(value).find()) {
                    HttpSender httpSender = HttpSenderExecutionContextView.view(ctx).getHttpSender();
                    try(HttpSender.Response response = httpSender.send(httpSender.post(value).build())) {
                        return response.getCode() != 404;
                    }
                }
                return false;
            }
        };
    }
}
