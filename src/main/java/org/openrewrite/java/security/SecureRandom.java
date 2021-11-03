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
package org.openrewrite.java.security;

import org.openrewrite.ExecutionContext;
import org.openrewrite.Recipe;
import org.openrewrite.TreeVisitor;
import org.openrewrite.java.JavaIsoVisitor;
import org.openrewrite.java.JavaTemplate;
import org.openrewrite.java.JavaVisitor;
import org.openrewrite.java.search.InJavaSourceSet;
import org.openrewrite.java.search.UsesType;
import org.openrewrite.java.tree.J;
import org.openrewrite.java.tree.JavaSourceFile;
import org.openrewrite.java.tree.TypeUtils;

import java.util.Arrays;
import java.util.List;

public class SecureRandom extends Recipe {
    private static final List<String> secureWords = Arrays.asList(
            "password", "secret", "token", "cred", "hash"
    );

    @Override
    public String getDisplayName() {
        return "Secure random";
    }

    @Override
    public String getDescription() {
        return "Use cryptographically secure PRNGs in secure contexts.";
    }

    @Override
    protected TreeVisitor<?, ExecutionContext> getSingleSourceApplicableTest() {
        return new JavaVisitor<ExecutionContext>() {
            @Override
            public J visitJavaSourceFile(JavaSourceFile cu, ExecutionContext context) {
                doAfterVisit(new UsesType<>("java.util.Random"));
                doAfterVisit(new InJavaSourceSet<>("main"));
                return cu;
            }
        };
    }

    @Override
    protected TreeVisitor<?, ExecutionContext> getVisitor() {
        return new JavaIsoVisitor<ExecutionContext>() {
            @Override
            public J.NewClass visitNewClass(J.NewClass newClass, ExecutionContext executionContext) {
                J.NewClass n = super.visitNewClass(newClass, executionContext);
                J.MethodDeclaration methodDecl = getCursor().firstEnclosing(J.MethodDeclaration.class);
                if (TypeUtils.isOfClassType(newClass.getType(), "java.util.Random") &&
                        methodDecl != null && secureWords.stream().anyMatch(word -> methodDecl.getSimpleName().toLowerCase().contains(word))) {
                    maybeAddImport("java.security.SecureRandom");
                    return n.withTemplate(JavaTemplate.builder(this::getCursor, "new SecureRandom()")
                            .imports("java.security.SecureRandom")
                            .build(), newClass.getCoordinates().replace());
                }
                return n;
            }
        };
    }
}
