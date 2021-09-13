package org.openrewrite.java.security;

import org.openrewrite.ExecutionContext;
import org.openrewrite.Recipe;
import org.openrewrite.TreeVisitor;
import org.openrewrite.java.JavaIsoVisitor;
import org.openrewrite.java.JavaTemplate;
import org.openrewrite.java.search.InJavaSourceSet;
import org.openrewrite.java.tree.J;
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
        return new InJavaSourceSet<>("main");
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
