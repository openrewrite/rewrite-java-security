package org.openrewrite.java.security.search;

import org.openrewrite.ExecutionContext;
import org.openrewrite.Recipe;
import org.openrewrite.java.JavaVisitor;
import org.openrewrite.java.marker.JavaSearchResult;
import org.openrewrite.java.search.FindAnnotations;
import org.openrewrite.java.tree.J;
import org.openrewrite.java.tree.JavaType;
import org.openrewrite.java.tree.TypeUtils;

import java.util.Arrays;
import java.util.List;

public class FindVulnerableJacksonJsonTypeInfo extends Recipe {
    private static final List<JavaType.FullyQualified> VULNERABLE_TARGET_TYPES = Arrays.asList(
            JavaType.Class.build("java.lang.Object"),
            JavaType.Class.build("java.io.Serializable"),
            JavaType.Class.build("java.util.Comparable"),
            JavaType.Class.build("java.lang.Iterable")
    );

    @Override
    public String getDisplayName() {
        return "Find vulnerable uses of Jackson `@JsonTypeInfo`";
    }

    @Override
    public String getDescription() {
        return "Identify where attackers can deserialize gadgets into a target field.";
    }

    @Override
    protected JavaVisitor<ExecutionContext> getVisitor() {
        return new JavaVisitor<ExecutionContext>() {
            @Override
            public J visitVariableDeclarations(J.VariableDeclarations multiVariable, ExecutionContext ctx) {
                if (isField() && hasJsonTypeInfo(multiVariable) && isVulnerableTarget(multiVariable)) {
                    return multiVariable.withMarkers(multiVariable.getMarkers().addIfAbsent(new JavaSearchResult(FindVulnerableJacksonJsonTypeInfo.this)));
                }
                return super.visitVariableDeclarations(multiVariable, ctx);
            }

            private boolean isVulnerableTarget(J.VariableDeclarations multiVariable) {
                return VULNERABLE_TARGET_TYPES.stream().anyMatch(t -> TypeUtils.isAssignableTo(t, multiVariable.getTypeAsFullyQualified()));
            }

            private boolean hasJsonTypeInfo(J.VariableDeclarations multiVariable) {
                return !FindAnnotations.find(multiVariable, "@com.fasterxml.jackson.annotation.JsonTypeInfo(use=com.fasterxml.jackson.annotation.JsonTypeInfo.Id.CLASS)").isEmpty() ||
                        !FindAnnotations.find(multiVariable, "@com.fasterxml.jackson.annotation.JsonTypeInfo(use=com.fasterxml.jackson.annotation.JsonTypeInfo.Id.MINIMAL_CLASS)").isEmpty();
            }

            private boolean isField() {
                return getCursor().dropParentUntil(J.class::isInstance).dropParentUntil(J.class::isInstance).getValue() instanceof J.ClassDeclaration;
            }
        };
    }
}
