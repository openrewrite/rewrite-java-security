package org.openrewrite.java.security;

import lombok.AllArgsConstructor;
import org.openrewrite.Cursor;
import org.openrewrite.ExecutionContext;
import org.openrewrite.Recipe;
import org.openrewrite.TreeVisitor;
import org.openrewrite.java.JavaIsoVisitor;
import org.openrewrite.java.JavaTemplate;
import org.openrewrite.java.MethodMatcher;
import org.openrewrite.java.dataflow.LocalFlowSpec;
import org.openrewrite.java.tree.Expression;
import org.openrewrite.java.tree.J;
import org.openrewrite.java.tree.Statement;

import javax.swing.plaf.nimbus.State;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;

import static java.util.Collections.emptyList;

public class ZipSlip extends Recipe {
    @Override
    public String getDisplayName() {
        return "Zip Slip";
    }

    @Override
    protected TreeVisitor<?, ExecutionContext> getVisitor() {
        return new ZipSlipVisitor<>();
    }

    private static class ZipSlipVisitor<P> extends JavaIsoVisitor<P> {
        private static final MethodMatcher ZIP_ENTRY_GET_NAME_METHOD =
                new MethodMatcher("java.util.zip.ZipEntry getName()", true);
        private static final MethodMatcher ZIP_ENTRY_APACHE_GET_NAME_METHOD =
                new MethodMatcher("org.apache.commons.compress.archivers.zip.ZipArchiveEntry getName()", true);
        private static final MethodMatcher FILE_CREATE =
                new MethodMatcher("java.io.File <constructor>(.., java.lang.String)");
        private static final MethodMatcher FILES_NEW_OUTPUT_STREAM =
                new MethodMatcher("java.nio.file.Files newOutputStream(java.nio.file.Path)");

        private static final MethodMatcher PATH_RESOLVE =
                new MethodMatcher("java.nio.file.Path resolve(..)");

        private static boolean isFileOrPathCreationExpression(Expression expression, Cursor cursor) {
            return getFileOrPathCreationExpressionFromArgument(expression, cursor).isPresent();
        }

        private static Optional<Expression> getFileOrPathCreationExpressionFromArgument(Expression argument, Cursor cursor) {
            Expression maybeEnclosingJCallable =
                    Optional.<Expression>ofNullable(cursor.firstEnclosing(J.NewClass.class))
                            .orElseGet(() -> cursor.firstEnclosing(J.MethodInvocation.class));
            if (maybeEnclosingJCallable != null &&
                    (PATH_RESOLVE.matches(maybeEnclosingJCallable) ||
                            (maybeEnclosingJCallable instanceof J.NewClass && FILE_CREATE.matches((J.NewClass) maybeEnclosingJCallable)))
            ) {
                if (getArgumentsForCallable(maybeEnclosingJCallable).contains(argument)) {
                    return Optional.of(maybeEnclosingJCallable);
                }
            }
            return Optional.empty();
        }

        private static List<Expression> getArgumentsForCallable(Expression callable) {
            if (callable instanceof J.NewClass) {
                List<Expression> arguments = ((J.NewClass) callable).getArguments();
                return arguments == null ? emptyList() : arguments;
            } else if (callable instanceof J.MethodInvocation) {
                return ((J.MethodInvocation) callable).getArguments();
            } else {
                throw new IllegalArgumentException("Expected NewClass or MethodInvocation, got " + callable);
            }
        }

        private static class ZipEntryToFileOrPathCreationLocalFlowSpec extends LocalFlowSpec<J.MethodInvocation, Expression> {

            @Override
            public boolean isSource(J.MethodInvocation methodInvocation, Cursor cursor) {
                return ZIP_ENTRY_GET_NAME_METHOD.matches(methodInvocation) ||
                        ZIP_ENTRY_APACHE_GET_NAME_METHOD.matches(methodInvocation);
            }

            @Override
            public boolean isSink(Expression expression, Cursor cursor) {
                return isFileOrPathCreationExpression(expression, cursor);
            }
        }

        @Override
        public J.MethodInvocation visitMethodInvocation(J.MethodInvocation method, P p) {
            dataflow().findSinks(new ZipEntryToFileOrPathCreationLocalFlowSpec()).ifPresent(sinkFlow -> {
                doAfterVisit(new TaintedFileOrPathVisitor<>(sinkFlow.getSinks()));
            });
            return super.visitMethodInvocation(method, p);
        }

        /**
         * Visitor that handles known tainted {@link java.io.File} or {@link java.nio.file.Path}
         * objects that have been tainted by zip entry getName() calls.
         */
        @AllArgsConstructor
        private static class TaintedFileOrPathVisitor<P> extends JavaIsoVisitor<P> {
            private final JavaTemplate noZipSlipTemplate = JavaTemplate.builder(this::getCursor, "" +
                    "if (!#{any(java.io.File)}.toPath().normalize().startsWith(#{any(java.io.File)}.toPath())) {\n" +
                    "    throw new Exception(\"Bad zip entry\");\n" +
                    "}").build();
            private final List<Expression> taintedSinks;

            @AllArgsConstructor
            private static class ZipSlipLocalInfo {
                Statement statement;
                Expression parentDir;
                Expression zipEntry;
            }

//            @Override
//            public Expression visitExpression(Expression expression, P o) {
//                if (taintedSinks.contains(expression)) {
//                    if (dataflow().findSinks(new FileOrPathCreationToVulnerableUsageLocalFlowSpec()).isPresent()) {
//                        ZipSlipLocalInfo localInfo = new ZipSlipLocalInfo(
//                                getCursor().firstEnclosing(Statement.class),
//                                getCursor().firstEnclosing(Expression.class),
//                                expression
//                        );
//                        getCursor()
//                                .dropParentUntil(J.Block.class::isInstance)
//                                .putMessage("ZIP SLIP", getCursor().firstEnclosingOrThrow(Statement.class));
//                    }
//                }
//                return expression;
//            }


            @Override
            public J.NewClass visitNewClass(J.NewClass newClass, P p) {
                if (getArgumentsForCallable(newClass).stream().anyMatch(taintedSinks::contains)
                        && dataflow().findSinks(new FileOrPathCreationToVulnerableUsageLocalFlowSpec()).isPresent()) {
                    J.Block firstEnclosingBlock = getCursor().firstEnclosing(J.Block.class);
                    Statement enclosingStatement = getCursor()
                            .dropParentUntil(value -> firstEnclosingBlock.getStatements().contains(value))
                            .getValue();
                    ZipSlipLocalInfo zipSlipLocalInfo = new ZipSlipLocalInfo(
                            enclosingStatement,
                            newClass.getArguments().get(0),
                            newClass
                    );
                    getCursor()
                            .dropParentUntil(J.Block.class::isInstance)
                            .putMessage("ZIP SLIP", zipSlipLocalInfo);
                }
                return super.visitNewClass(newClass, p);
            }

            @Override
            public J.Block visitBlock(J.Block block, P p) {
                J.Block b = super.visitBlock(block, p);
                ZipSlipLocalInfo zipSlipLocalInfo = getCursor().getMessage("ZIP SLIP");
                if (zipSlipLocalInfo != null) {
                    return b.withTemplate(
                            noZipSlipTemplate,
                            zipSlipLocalInfo.statement.getCoordinates().after(),
                            zipSlipLocalInfo.parentDir,
                            zipSlipLocalInfo.zipEntry
                    );
                }
                return b;
            }
        }

        private static class FileOrPathCreationToVulnerableUsageLocalFlowSpec extends LocalFlowSpec<Expression, Expression> {
            private static final MethodMatcher CREATE_FILE_OUTPUT_STREAM =
                    new MethodMatcher("java.io.FileOutputStream <constructor>(..)");
            private static final MethodMatcher CREATE_RANDOM_ACCESS_FILE =
                    new MethodMatcher("java.io.RandomAccessFile <constructor>(..)");
            private static final MethodMatcher CREATE_FILE_WRITER =
                    new MethodMatcher("java.io.FileWriter <constructor>(..)");

            @Override
            public boolean isSource(Expression expression, Cursor cursor) {
                return true;
            }

            @Override
            public boolean isSink(Expression expression, Cursor cursor) {
                J.NewClass maybeNewClass = cursor.firstEnclosing(J.NewClass.class);
                if (maybeNewClass != null) {
                    J.NewClass newClass = maybeNewClass;
                    return (CREATE_FILE_OUTPUT_STREAM.matches(newClass) ||
                            CREATE_RANDOM_ACCESS_FILE.matches(newClass) ||
                            CREATE_FILE_WRITER.matches(newClass)) &&
                            Objects.requireNonNull(newClass.getArguments(), "constructor arguments")
                                    .contains(expression);
                } else {
                    return false;
                }
            }
        }
    }
}
