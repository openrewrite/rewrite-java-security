/*
 * Copyright 2022 the original author or authors.
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
package org.openrewrite.java.security.secrets;

import org.jspecify.annotations.Nullable;
import org.openrewrite.*;

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

    @Override
    public TreeVisitor<?, ExecutionContext> getVisitor() {
        return new FindSecretsVisitor("Slack") {
            private final Pattern valuePattern = Pattern.compile("https://hooks\\.slack\\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}");

            @Override
            public Tree visit(@Nullable Tree tree, ExecutionContext ctx) {
                if (tree instanceof SourceFile) {
                    doAfterVisit(new FindSecretsByPattern("Slack", null, "(xox[pboa]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})").getVisitor());
                    doAfterVisit(new FindSecretsByPattern("Slack", null, "xox(?:a|b|p|o|s|r)-(?:\\d+-)+[a-z0-9]+").getVisitor());
                }
                return super.visit(tree, ctx);
            }

            @Override
            protected boolean isSecret(@Nullable String key, @Nullable String value, ExecutionContext ctx) {
//                    HttpSender httpSender = HttpSenderExecutionContextView.view(ctx).getHttpSender();
//                    try(HttpSender.Response response = httpSender.send(httpSender.post(value).build())) {
//                        return response.getCode() != 404;
//                    }
                // TODO make an HTTP request to check
                return value != null && valuePattern.matcher(value).find();
            }
        };
    }
}
