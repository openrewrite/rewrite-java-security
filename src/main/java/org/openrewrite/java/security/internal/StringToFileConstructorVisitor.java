package org.openrewrite.java.security.internal;

import org.openrewrite.java.JavaTemplate;
import org.openrewrite.java.JavaVisitor;
import org.openrewrite.java.dataflow.ExternalSinkModels;
import org.openrewrite.java.tree.Expression;
import org.openrewrite.java.tree.J;
import org.openrewrite.java.tree.JavaCoordinates;
import org.openrewrite.java.tree.Statement;

/**
 * Replaces constructor calls like
 * {@link java.io.FileOutputStream#FileOutputStream(String)} with
 * {@link java.io.FileOutputStream#FileOutputStream(java.io.File)} by adding the required
 * {@link java.io.File} constructor call.
 */
public class StringToFileConstructorVisitor<P> extends JavaVisitor<P> {
    private final JavaTemplate fileConstructorTemplate =
            JavaTemplate.builder(this::getCursor, "new File(#{any(String)})")
                    .imports("java.io.File").build();

    @Override
    public Expression visitExpression(Expression expression, P p) {
        if (getCursor().firstEnclosing(J.Block.class) == null) {
            // Temporary bug fix: https://github.com/openrewrite/rewrite/pull/2023
            return expression;
        }
        if (ExternalSinkModels.getInstance().isSinkNode(expression, getCursor(), "create-file")) {
            J.NewClass parentConstructor = getCursor().firstEnclosing(J.NewClass.class);
            if (parentConstructor != null &&
                    parentConstructor.getArguments() != null &&
                    parentConstructor.getArguments().get(0) == expression) {
                final JavaCoordinates coordinates;
                if (expression instanceof J.Identifier) {
                    coordinates = ((J.Identifier) expression).getCoordinates().replace();
                } else if (expression instanceof Statement){
                    coordinates = ((Statement) expression).getCoordinates().replace();
                } else if (expression instanceof J.Literal) {
                    coordinates = ((J.Literal) expression).getCoordinates().replace();
                } else {
                    throw new IllegalArgumentException("Unexpected first argument type: " + expression.getClass());
                }
                return expression.withTemplate(fileConstructorTemplate, coordinates, expression);
            }
        }
        return expression;
    }
}
