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

import org.jetbrains.annotations.Nullable;
import org.openrewrite.ExecutionContext;
import org.openrewrite.Parser;
import org.openrewrite.SourceFile;
import org.openrewrite.internal.ListUtils;
import org.openrewrite.java.JavaParser;
import org.openrewrite.java.JavaVisitor;
import org.openrewrite.java.MethodMatcher;
import org.openrewrite.java.tree.J;
import org.openrewrite.java.tree.JavaType;
import org.openrewrite.java.tree.TypeUtils;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import static java.util.Collections.singletonList;
import static org.openrewrite.Tree.randomId;

public class GenerateWebSecurityConfigurerAdapter {
    private static final MethodMatcher CONFIGURE = new MethodMatcher("org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter configure(org.springframework.security.config.annotation.web.builders.HttpSecurity)");

    public static List<SourceFile> andAddConfiguration(List<SourceFile> sourceFiles,
                                                       ExecutionContext ctx,
                                                       JavaVisitor<ExecutionContext> onConfigureBlock) {
        AtomicBoolean found = new AtomicBoolean(false);
        AtomicReference<Path> springBootApplicationPackage = new AtomicReference<>(Paths.get(""));
        AtomicReference<J.Package> springBootApplicationPackageName = new AtomicReference<>();

        List<SourceFile> after = ListUtils.map(sourceFiles, sourceFile -> {
            if (sourceFile instanceof J.CompilationUnit) {
                J.CompilationUnit cu = (J.CompilationUnit) sourceFile;
                for (JavaType javaType : cu.getTypesInUse()) {
                    if (TypeUtils.isOfClassType(javaType, "org.springframework.boot.autoconfigure.SpringBootApplication")) {
                        springBootApplicationPackage.set(cu.getSourcePath().getParent() == null ? Paths.get("") :
                                cu.getSourcePath().getParent());
                        if (cu.getPackageDeclaration() != null) {
                            springBootApplicationPackageName.set(cu.getPackageDeclaration());
                        }
                    }
                }

                for (JavaType.Method declaredMethod : cu.getDeclaredMethods()) {
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
        } else {
            J.CompilationUnit generated = JavaParser.fromJavaVersion()
                    .classpath("spring-security-config", "spring-context", "jakarta.servlet-api")
                    .build()
                    .parseInputs(singletonList(new Parser.Input(
                            springBootApplicationPackage.get()
                                    .resolve("SecurityConfig.java")
                                    .normalize(),
                            () -> GenerateWebSecurityConfigurerAdapter.class
                                    .getResourceAsStream("/WebSecurityConfigurerAdapterTemplate.java")
                    )), null, ctx)
                    .get(0)
                    .withPackageDeclaration(springBootApplicationPackageName.get() == null ? null :
                            springBootApplicationPackageName.get().withId(randomId()));

            return ListUtils.concat(after, visitConfigureMethod(generated, ctx, onConfigureBlock));
        }
    }

    @Nullable
    private static SourceFile visitConfigureMethod(J.CompilationUnit cu, ExecutionContext ctx, JavaVisitor<ExecutionContext> onConfigureBlock) {
        return (SourceFile) new JavaVisitor<ExecutionContext>() {
            @Override
            public J visitMethodDeclaration(J.MethodDeclaration method, ExecutionContext ctx) {
                if (CONFIGURE.matches(method.getType())) {
                    return method.withBody((J.Block) onConfigureBlock.visit(method.getBody(),
                            ctx, getCursor()));
                }
                return method;
            }
        }.visit(cu, ctx);
    }
}
