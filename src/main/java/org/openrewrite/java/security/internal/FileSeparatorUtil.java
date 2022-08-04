package org.openrewrite.java.security.internal;

import io.micrometer.core.lang.Nullable;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import org.openrewrite.java.tree.Expression;
import org.openrewrite.java.tree.J;
import org.openrewrite.java.tree.JavaType;
import org.openrewrite.java.tree.TypeUtils;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class FileSeparatorUtil {

    public static boolean isFileSeparatorExpression(@Nullable Expression e) {
        Expression expression = Expression.unwrap(e);
        if (expression instanceof J.FieldAccess || expression instanceof J.Identifier) {
            // CASE:
            // - File.separator
            // - File.separatorChar
            // - separator
            // - separatorChar
            J.Identifier nameIdentifier;
            JavaType type;
            if (expression instanceof J.FieldAccess) {
                // CASE:
                // - File.separator
                // - File.separatorChar
                nameIdentifier = ((J.FieldAccess) expression).getName();
                type = ((J.FieldAccess) expression).getTarget().getType();
            } else {
                // CASE:
                // - separator statically imported from java.io.File
                // - separatorChar statically imported from java.io.File
                if (((J.Identifier) expression).getFieldType() == null) {
                    return false;
                }
                nameIdentifier = (J.Identifier) expression;
                type = ((J.Identifier) expression).getFieldType().getOwner();
            }
            final String name = nameIdentifier.getSimpleName();
            return ("separator".equals(name) || "separatorChar".equals(name)) &&
                    TypeUtils.isOfClassType(type, "java.io.File");
        } else if (expression instanceof J.Literal) {
            // CASE:
            // - "/";
            // - '/'
            J.Literal literal = (J.Literal) expression;
            if (literal.getValue() instanceof String) {
                String value = (String) literal.getValue();
                // CASE:
                // - "/"
                // - "\\"
                return value.equals("/") || value.equals("\\");
            } else if (literal.getValue() instanceof Character) {
                Character value = (Character) literal.getValue();
                // CASE:
                // - '/'
                // - '\'
                return value.equals('/') || value.equals('\\');
            }
        }
        return false;
    }
}
