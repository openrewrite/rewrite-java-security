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
import org.openrewrite.java.JavaParser;
import org.openrewrite.java.JavaTemplate;
import org.openrewrite.java.JavaVisitor;
import org.openrewrite.java.MethodMatcher;
import org.openrewrite.java.search.HasTypeOnClasspathSourceSet;
import org.openrewrite.java.tree.J;
import org.openrewrite.java.tree.JavaSourceFile;
import org.openrewrite.java.tree.JavaType;

import java.time.Duration;
import java.util.List;

@Value
@EqualsAndHashCode(callSuper = true)
public class PreventClickjacking extends Recipe {
    @Option(displayName = "Only if security configuration exists",
            description = "Only patch existing implementations of `WebSecurityConfigurerAdapter`.",
            required = false)
    @Nullable
    Boolean onlyIfSecurityConfig;

    @Override
    public String getDisplayName() {
        return "Prevent clickjacking";
    }

    @Override
    public Duration getEstimatedEffortPerOccurrence() {
        return Duration.ofMinutes(5);
    }

    @Override
    public String getDescription() {
        return "The `frame-ancestors` directive can be used in a Content-Security-Policy HTTP response header to indicate whether or not a browser should be allowed to render a page in a `<frame>` or `<iframe>`. Sites can use this to avoid Clickjacking attacks by ensuring that their content is not embedded into other sites.";
    }

    @Override
    protected TreeVisitor<?, ExecutionContext> getApplicableTest() {
        return new HasTypeOnClasspathSourceSet<>("org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter");
    }

    private static final MethodMatcher FRAME_OPTIONS = new MethodMatcher("org.springframework.security.config.annotation.web.configurers.HeadersConfigurer frameOptions()");

    @Override
    protected List<SourceFile> visit(List<SourceFile> before, ExecutionContext ctx) {
        return new GenerateWebSecurityConfigurerAdapter(Boolean.TRUE.equals(onlyIfSecurityConfig), new JavaVisitor<ExecutionContext>() {
            @Override
            public J visitBlock(J.Block block, ExecutionContext executionContext) {
                for (JavaType.Method method : getCursor().firstEnclosingOrThrow(JavaSourceFile.class).getTypesInUse().getUsedMethods()) {
                    if (FRAME_OPTIONS.matches(method)) {
                        return block;
                    }
                }
                return block.withTemplate(
                        JavaTemplate
                                .builder(this::getCursor, "http.headers().frameOptions().deny();")
                                .javaParser(() -> JavaParser.fromJavaVersion()
                                        .classpath("spring-security-config", "spring-context", "jakarta.servlet-api")
                                        .build())
                                .build(),
                        block.getCoordinates().lastStatement()
                );
            }
        }).maybeAddConfiguration(before, ctx);
    }
}
