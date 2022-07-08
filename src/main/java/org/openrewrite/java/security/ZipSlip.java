package org.openrewrite.java.security;

import lombok.AllArgsConstructor;
import org.openrewrite.Cursor;
import org.openrewrite.ExecutionContext;
import org.openrewrite.Recipe;
import org.openrewrite.TreeVisitor;
import org.openrewrite.java.JavaIsoVisitor;
import org.openrewrite.java.JavaTemplate;
import org.openrewrite.java.MethodMatcher;
import org.openrewrite.java.controlflow.Guard;
import org.openrewrite.java.dataflow.ExternalSinkModels;
import org.openrewrite.java.dataflow.LocalFlowSpec;
import org.openrewrite.java.dataflow.LocalTaintFlowSpec;
import org.openrewrite.java.dataflow.internal.InvocationMatcher;
import org.openrewrite.java.tree.Expression;
import org.openrewrite.java.tree.J;
import org.openrewrite.java.tree.Statement;
import org.openrewrite.java.tree.TypeUtils;

import java.util.List;

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
        private static final InvocationMatcher ZIP_ENTRY_GET_NAME = InvocationMatcher.fromInvocationMatchers(
                new MethodMatcher("java.util.zip.ZipEntry getName()", true),
                new MethodMatcher("org.apache.commons.compress.archivers.zip.ZipArchiveEntry getName()", true)
        );
        private static final InvocationMatcher FILE_CREATE = InvocationMatcher.fromMethodMatcher(
                new MethodMatcher("java.io.File <constructor>(.., java.lang.String)")
        );
        private static final InvocationMatcher PATH_RESOLVE = InvocationMatcher.fromMethodMatcher(
                new MethodMatcher("java.nio.file.Path resolve(..)")
        );

        private static boolean isFileOrPathCreationExpression(Expression expression, Cursor cursor) {
            return FILE_CREATE.advanced().isParameter(cursor, 1) ||
                    PATH_RESOLVE.advanced().isFirstParameter(cursor);
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
                return ZIP_ENTRY_GET_NAME.matches(methodInvocation);
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
            private final JavaTemplate noZipSlipFileTemplate = JavaTemplate.builder(this::getCursor, "" +
                    "if (!#{any(java.io.File)}.toPath().normalize().startsWith(#{any(java.io.File)}.toPath())) {\n" +
                    "    throw new RuntimeException(\"Bad zip entry\");\n" +
                    "}")
                    .build();
            private final JavaTemplate noZipSlipPathStartsWithPathTemplate = JavaTemplate.builder(this::getCursor, "" +
                    "if (!#{any(java.nio.file.Path)}.normalize().startsWith(#{any(java.nio.file.Path)})) {\n" +
                    "    throw new RuntimeException(\"Bad zip entry\");\n" +
                    "}").build();

            private final JavaTemplate noZipSlipPathStartsWithFileTemplate = JavaTemplate.builder(this::getCursor, "" +
                    "if (!#{any(java.nio.file.Path)}.normalize().startsWith(#{any(java.io.File)}.toPath())) {\n" +
                    "    throw new RuntimeException(\"Bad zip entry\");\n" +
                    "}").build();
            private final JavaTemplate noZipSlipPathStartsWithStringTemplate = JavaTemplate.builder(this::getCursor, "" +
                    "if (!#{any(java.nio.file.Path)}.normalize().startsWith(#{any(String)})) {\n" +
                    "    throw new RuntimeException(\"Bad zip entry\");\n" +
                    "}").build();

            private final List<Expression> taintedSinks;

            @AllArgsConstructor
            private static class ZipSlipLocalInfo {
                Statement statement;
                Expression parentDir;
                Expression zipEntry;
            }

            @Override
            public J.MethodInvocation visitMethodInvocation(J.MethodInvocation method, P p) {
                if (getArgumentsForCallable(method).stream().anyMatch(taintedSinks::contains)
                        && dataflow().findSinks(new FileOrPathCreationToVulnerableUsageLocalFlowSpec()).isPresent()) {
                    J.Block firstEnclosingBlock = getCursor().firstEnclosing(J.Block.class);
                    Statement enclosingStatement = getCursor()
                            .dropParentUntil(value -> firstEnclosingBlock.getStatements().contains(value))
                            .getValue();
                    // TODO: Test this
                    J.Identifier newFileVariableName = getCursor().firstEnclosing(J.VariableDeclarations.NamedVariable.class).getName();
                    ZipSlipLocalInfo zipSlipLocalInfo = new ZipSlipLocalInfo(
                            enclosingStatement,
                            method.getSelect(),
                            newFileVariableName
                    );
                    getCursor()
                            .dropParentUntil(J.Block.class::isInstance)
                            .putMessage("ZIP SLIP", zipSlipLocalInfo);
                }
                return super.visitMethodInvocation(method, p);
            }

            @Override
            public J.NewClass visitNewClass(J.NewClass newClass, P p) {
                if (getArgumentsForCallable(newClass).stream().anyMatch(taintedSinks::contains)
                        && dataflow().findSinks(new FileOrPathCreationToVulnerableUsageLocalFlowSpec()).isPresent()) {
                    J.Block firstEnclosingBlock = getCursor().firstEnclosing(J.Block.class);
                    Statement enclosingStatement = getCursor()
                            .dropParentUntil(value -> firstEnclosingBlock.getStatements().contains(value))
                            .getValue();
                    // TODO: Test this
                    J.Identifier newFileVariableName = getCursor().firstEnclosing(J.VariableDeclarations.NamedVariable.class).getName();
                    ZipSlipLocalInfo zipSlipLocalInfo = new ZipSlipLocalInfo(
                            enclosingStatement,
                            newClass.getArguments().get(0),
                            newFileVariableName
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
                    JavaTemplate template;
                    if (TypeUtils.isOfClassType(zipSlipLocalInfo.zipEntry.getType(), "java.io.File")) {
                        template = noZipSlipFileTemplate;
                    } else {
                        template = noZipSlipPathStartsWithPathTemplate;
                    }
                    return maybeAutoFormat(
                            b,
                            b.withTemplate(
                                    template,
                                    zipSlipLocalInfo.statement.getCoordinates().after(),
                                    zipSlipLocalInfo.zipEntry,
                                    zipSlipLocalInfo.parentDir
                            ),
                            p,
                            getCursor().getParentOrThrow()
                    );
                }
                return b;
            }
        }

        private static class FileOrPathCreationToVulnerableUsageLocalFlowSpec extends LocalTaintFlowSpec<Expression, Expression> {
            private static final MethodMatcher PATH_STARTS_WITH_MATCHER =
                    new MethodMatcher("java.nio.file.Path startsWith(..) ");
            private static final MethodMatcher STRING_STARTS_WITH_MATCHER =
                    new MethodMatcher("java.lang.String startsWith(..) ");

            @Override
            public boolean isSource(Expression expression, Cursor cursor) {
                return true;
            }

            @Override
            public boolean isSink(Expression expression, Cursor cursor) {
                return ExternalSinkModels.getInstance().isSinkNode(expression, cursor, "create-file");
            }

            @Override
            public boolean isSanitizerGuard(Guard guard, boolean branch) {
                if (branch) {
                    return PATH_STARTS_WITH_MATCHER.matches(guard.getExpression()) ||
                            (STRING_STARTS_WITH_MATCHER.matches(guard.getExpression()) &&
                                    PartialPathTraversalVulnerability.isSafePartialPathExpression(((J.MethodInvocation) guard.getExpression()).getArguments().get(0)));
                } else {
                    return false;
                }
            }
        }
    }
}
