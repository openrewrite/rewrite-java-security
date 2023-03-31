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
package org.openrewrite.java.security.spring;

import lombok.EqualsAndHashCode;
import lombok.Value;
import org.openrewrite.*;
import org.openrewrite.internal.lang.Nullable;
import org.openrewrite.java.*;
import org.openrewrite.java.search.UsesType;
import org.openrewrite.java.tree.J;
import org.openrewrite.java.tree.JavaSourceFile;
import org.openrewrite.java.tree.JavaType;

import java.time.Duration;
import java.util.List;

@Value
@EqualsAndHashCode(callSuper = true)
public class CsrfProtection extends Recipe {
    @Option(displayName = "Only if security configuration exists",
            description = "Only patch existing implementations of `WebSecurityConfigurerAdapter`.",
            required = false)
    @Nullable
    Boolean onlyIfSecurityConfig;

    @Override
    public String getDisplayName() {
        return "Enable CSRF attack prevention";
    }

    @Override
    public String getDescription() {
        return "Cross-Site Request Forgery (CSRF) is a type of attack that occurs when a malicious web site, email, blog, instant message, or program causes a user's web browser to perform an unwanted action on a trusted site when the user is authenticated. See the full [OWASP cheatsheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html).";
    }

    @Override
    public Duration getEstimatedEffortPerOccurrence() {
        return Duration.ofMinutes(5);
    }

    @Override
    protected TreeVisitor<?, ExecutionContext> getSingleSourceApplicableTest() {
        return new UsesType<>("org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter", false);
    }

    private static final MethodMatcher CSRF = new MethodMatcher("org.springframework.security.config.annotation.web.builders.HttpSecurity csrf()");

    @Override
    protected List<SourceFile> visit(List<SourceFile> before, ExecutionContext ctx) {
        return super.visit(new GenerateWebSecurityConfigurerAdapter(Boolean.TRUE.equals(onlyIfSecurityConfig), new JavaVisitor<ExecutionContext>() {
            @Override
            public J visitBlock(J.Block block, ExecutionContext executionContext) {
                for (JavaType.Method method : getCursor().firstEnclosingOrThrow(JavaSourceFile.class).getTypesInUse().getUsedMethods()) {
                    if (CSRF.matches(method)) {
                        return block;
                    }
                }

                return block.withTemplate(
                        JavaTemplate
                                .builder(this::getCursor, "http" +
                                        ".csrf()" +
                                        ".csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());")
                                .imports("org.springframework.security.web.csrf.CookieCsrfTokenRepository")
                                .javaParser(() -> JavaParser.fromJavaVersion()
                                        .classpath(
                                                "spring-security-config",
                                                "spring-context",
                                                "jakarta.servlet-api",
                                                "spring-security-web"
                                        )
                                        .build())
                                .build(),
                        block.getCoordinates().lastStatement()
                );
            }
        }).maybeAddConfiguration(before, ctx), ctx);
    }

    @Override
    protected JavaVisitor<ExecutionContext> getVisitor() {
        return new AddImport<>("org.springframework.security.web.csrf.CookieCsrfTokenRepository", null, true);
    }
}
