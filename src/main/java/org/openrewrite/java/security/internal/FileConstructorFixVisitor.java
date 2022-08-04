package org.openrewrite.java.security.internal;

import lombok.Value;
import lombok.With;
import org.openrewrite.java.JavaIsoVisitor;
import org.openrewrite.java.JavaTemplate;
import org.openrewrite.java.MethodMatcher;
import org.openrewrite.java.tree.Expression;
import org.openrewrite.java.tree.J;

import java.util.Optional;
import java.util.function.Predicate;

/**
 * Fixes the {@link java.io.File#File(String)} constructor call to use the multi-argument constructor when relevant.
 * <p>
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
    private final JavaTemplate stringAppendTemplate =
            JavaTemplate.builder(this::getCursor, "#{any()} + #{any(java.lang.String)}")
                    .build();

    private final Predicate<Expression> overrideShouldBreakBefore;

    public FileConstructorFixVisitor(Predicate<Expression> overrideShouldBreakBefore) {
        this.overrideShouldBreakBefore = overrideShouldBreakBefore;
    }

    public FileConstructorFixVisitor() {
        this(e -> false);
    }

    @Override
    public J.NewClass visitNewClass(J.NewClass newClass, P p) {
        J.NewClass n = super.visitNewClass(newClass, p);
        if (FILE_CONSTRUCTOR.matches(n)) {
            Expression argument = n.getArguments().get(0);
            if (argument instanceof J.Binary) {
                J.Binary binary = (J.Binary) argument;
                return computeNewArguments(binary)
                        .map(newArguments -> n.<J.NewClass>withTemplate(
                                fileConstructorTemplate,
                                n.getCoordinates().replace(),
                                newArguments.first,
                                newArguments.second
                        ))
                        .orElse(n);
            }
        }
        return n;
    }

    @Value
    @With
    static class NewArguments {
        Expression first, second;
    }

    private Optional<NewArguments> computeNewArguments(J.Binary binary) {
        Expression newFirstArgument = null;
        if (overrideShouldBreakBefore.test(binary.getRight())) {
            newFirstArgument = binary.getLeft();
        }
        if (binary.getLeft() instanceof J.Binary) {
            J.Binary left = (J.Binary) binary.getLeft();
            if (left.getOperator() == J.Binary.Type.Addition) {
                if (FileSeparatorUtil.isFileSeparatorExpression(left.getRight())) {
                    newFirstArgument = left.getLeft();
                } else if (left.getLeft() instanceof J.Binary) {
                    return computeNewArguments(left)
                            .map(leftLeftNewArguments ->
                                    leftLeftNewArguments.withSecond(
                                            binary.withTemplate(
                                                    stringAppendTemplate,
                                                    binary.getCoordinates().replace(),
                                                    leftLeftNewArguments.second,
                                                    binary.getRight()
                                            )
                                    ));
                }
            }
        } else if (binary.getLeft() instanceof J.Literal) {
            J.Literal left = (J.Literal) binary.getLeft();
            if (left.getValue() instanceof String) {
                String leftValue = (String) left.getValue();
                if (leftValue.endsWith("/") || leftValue.endsWith("\\")) {
                    newFirstArgument = left;
                }
            }
        }
        return Optional.ofNullable(newFirstArgument)
                .map(first -> new NewArguments(first, binary.getRight()));
    }
}
