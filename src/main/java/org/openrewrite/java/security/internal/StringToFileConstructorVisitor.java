package org.openrewrite.java.security.internal;

import org.openrewrite.java.JavaTemplate;
import org.openrewrite.java.JavaVisitor;
import org.openrewrite.java.dataflow.ExternalSinkModels;
import org.openrewrite.java.tree.Expression;
import org.openrewrite.java.tree.J;
import org.openrewrite.java.tree.TypeUtils;

/**
 * Replaces constructor calls like
 * {@link java.io.FileOutputStream#FileOutputStream(String)} with
 * {@link java.io.FileOutputStream#FileOutputStream(java.io.File)} by adding the required
 * {@link java.io.File} constructor call.
 */
public class StringToFileConstructorVisitor<P> extends JavaVisitor<P> {
    private final JavaTemplate fileConstructorTemplate =
            JavaTemplate.builder(this::getCursor, "new File(#{any(java.lang.String)})")
                    .imports("java.io.File").build();

    @Override
    public Expression visitExpression(Expression expression, P p) {
        if (ExternalSinkModels.getInstance().isSinkNode(expression, getCursor(), "create-file")) {
            J.NewClass parentConstructor = getCursor().firstEnclosing(J.NewClass.class);
            if (parentConstructor != null &&
                    parentConstructor.getArguments().get(0) == expression &&
                    TypeUtils.isString(expression.getType())
            ) {
                Expression replacementConstructor = expression.withTemplate(
                        fileConstructorTemplate,
                        expression.getCoordinates().replace(),
                        expression
                );
                return (Expression) new FileConstructorFixVisitor<P>()
                        .visitNonNull(
                                replacementConstructor,
                                p,
                                getCursor()
                        );
            }
        }
        return expression;
    }
}
