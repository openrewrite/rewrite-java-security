package org.openrewrite.java.security.internal;

import org.openrewrite.java.JavaIsoVisitor;
import org.openrewrite.java.JavaTemplate;
import org.openrewrite.java.MethodMatcher;
import org.openrewrite.java.tree.Expression;
import org.openrewrite.java.tree.J;

import java.util.Objects;

/**
 * Fixes the {@link java.io.File#File(String)} constructor call to use the multi-argument constructor when relevant.
 * <p/>
 * For example:
 * <ul>
 *     <li>{@code new File("base" + File.separator + "test.txt")} becomes {@code new File("base", "test.txt")}</li>
 *     <li>{@code new File("base" + File.separatorChar + "test.txt")} becomes {@code new File("base", "test.txt")}</li>
 *     <li>{@code new File("base/" + "test.txt")} becomes {@code new File("base/", "test.txt")}</li>
 * </ul>
 */
public class FileConstructorFixVisitor<P> extends JavaIsoVisitor<P> {
    private static final MethodMatcher FILE_CONSTRUCTOR =
            new MethodMatcher("java.io.File <constructor>(java.lang.String)");

    private final JavaTemplate fileConstructorTemplate =
            JavaTemplate.builder(this::getCursor, "new File(#{any(java.lang.String)}, #{any(java.lang.String)})")
                    .imports("java.io.File")
                    .build();

    @Override
    public J.NewClass visitNewClass(J.NewClass newClass, P p) {
        J.NewClass n = super.visitNewClass(newClass, p);
        if (FILE_CONSTRUCTOR.matches(n)) {
            Expression argument = Objects.requireNonNull(n.getArguments()).get(0);
            if (argument instanceof J.Binary) {
                J.Binary binary = (J.Binary) argument;
                if (binary.getOperator() == J.Binary.Type.Addition) {
                    return n.withTemplate(
                            fileConstructorTemplate,
                            n.getCoordinates().replace(),
                            binary.getLeft(),
                            binary.getRight()
                    );
                }
            }
        }
        return n;
    }
}
