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

import lombok.RequiredArgsConstructor;
import org.jetbrains.annotations.Nullable;
import org.openrewrite.ExecutionContext;
import org.openrewrite.Parser;
import org.openrewrite.SourceFile;
import org.openrewrite.internal.ListUtils;
import org.openrewrite.java.JavaParser;
import org.openrewrite.java.JavaVisitor;
import org.openrewrite.java.MethodMatcher;
import org.openrewrite.java.format.AutoFormatVisitor;
import org.openrewrite.java.tree.J;
import org.openrewrite.java.tree.JavaSourceFile;
import org.openrewrite.java.tree.JavaType;
import org.openrewrite.java.tree.TypeUtils;

import java.nio.file.Paths;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import static java.util.Collections.singletonList;
import static org.openrewrite.Tree.randomId;

@RequiredArgsConstructor
public class GenerateWebSecurityConfigurerAdapter {
    private static final MethodMatcher CONFIGURE = new MethodMatcher("org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter configure(org.springframework.security.config.annotation.web.builders.HttpSecurity)");

    private final boolean onlyIfExistingConfig;
    private final JavaVisitor<ExecutionContext> onConfigureBlock;

    public List<SourceFile> maybeAddConfiguration(List<SourceFile> sourceFiles,
                                                  ExecutionContext ctx) {
        AtomicBoolean found = new AtomicBoolean(false);
        AtomicReference<J.CompilationUnit> springBootApplication = new AtomicReference<>();

        List<SourceFile> after = ListUtils.map(sourceFiles, sourceFile -> {
            if (sourceFile instanceof J.CompilationUnit) {
                J.CompilationUnit cu = (J.CompilationUnit) sourceFile;
                for (JavaType javaType : cu.getTypesInUse().getTypesInUse()) {
                    if (TypeUtils.isOfClassType(javaType, "org.springframework.boot.autoconfigure.SpringBootApplication")) {
                        springBootApplication.set(cu);
                    }
                }

                for (JavaType.Method declaredMethod : cu.getTypesInUse().getDeclaredMethods()) {
                    if (CONFIGURE.matches(declaredMethod)) {
                        found.set(true);
                        return visitConfigureMethod(cu, ctx, onConfigureBlock);
                    }
                }
            }
            return sourceFile;
        });

        if (found.get()) {
            return after;
        } else if(!onlyIfExistingConfig) {
            J.CompilationUnit springBootApp = springBootApplication.get();
            if (springBootApp != null) {
                J.CompilationUnit generated = JavaParser.fromJavaVersion()
                        .classpath("spring-security-config", "spring-context", "jakarta.servlet-api")
                        .build()
                        .parseInputs(singletonList(new Parser.Input(
                                (springBootApp.getSourcePath().getParent() == null ? Paths.get("") :
                                        springBootApp.getSourcePath().getParent())
                                        .resolve("SecurityConfig.java")
                                        .normalize(),
                                () -> GenerateWebSecurityConfigurerAdapter.class
                                        .getResourceAsStream("/WebSecurityConfigurerAdapterTemplate.java")
                        )), null, ctx)
                        .get(0);

                J.Package pkg = springBootApp.getPackageDeclaration();
                if (pkg != null) {
                    generated = generated.withPackageDeclaration(pkg.withId(randomId()));
                }

                generated = generated.withMarkers(springBootApp.getMarkers());
                generated = (J.CompilationUnit) new AutoFormatVisitor<ExecutionContext>().visit(generated, ctx);
                assert generated != null;

                return ListUtils.concat(after, visitConfigureMethod(generated, ctx, onConfigureBlock));
            }
        }

        return sourceFiles;
    }

    @Nullable
    private static SourceFile visitConfigureMethod(J.CompilationUnit cu, ExecutionContext ctx, JavaVisitor<ExecutionContext> onConfigureBlock) {
        return (SourceFile) new JavaVisitor<ExecutionContext>() {
            @Override
            public J visitMethodDeclaration(J.MethodDeclaration method, ExecutionContext ctx) {
                if (CONFIGURE.matches(method.getMethodType())) {
                    return method.withBody((J.Block) onConfigureBlock.visit(method.getBody(),
                            ctx, getCursor()));
                }
                return method;
            }
        }.visit(cu, ctx);
    }
}
