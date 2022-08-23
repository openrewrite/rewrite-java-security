package org.openrewrite.java.security.internal;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import org.openrewrite.java.JavaIsoVisitor;
import org.openrewrite.java.JavaParser;
import org.openrewrite.java.tree.J;
import org.openrewrite.java.tree.JavaType;

import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class TypeGenerator {

    public static JavaType generate(String fqn) {
        List<J.CompilationUnit> compilationUnits =
                JavaParser.fromJavaVersion().build().parse("class Stub { " + fqn + " name;}");
        if (compilationUnits.size() != 1) {
            throw new IllegalArgumentException("Could not parse type: " + fqn);
        }
        J.CompilationUnit compilationUnit = compilationUnits.get(0);
        AtomicReference<JavaType> type = new AtomicReference<>();
        new JavaIsoVisitor<AtomicReference<JavaType>>() {
            @Override
            public J.VariableDeclarations.NamedVariable visitVariable(
                    J.VariableDeclarations.NamedVariable variable,
                    AtomicReference<JavaType> javaTypeAtomicReference) {
                javaTypeAtomicReference.set(variable.getType());
                return variable;
            }
        }.visit(compilationUnit, type);
        if (type.get() == null) {
            throw new IllegalArgumentException("Could not parse type: " + fqn);
        }
        return type.get();
    }
}
