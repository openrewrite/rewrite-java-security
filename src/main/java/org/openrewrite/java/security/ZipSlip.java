package org.openrewrite.java.security;

import lombok.AllArgsConstructor;
import org.openrewrite.*;
import org.openrewrite.internal.lang.Nullable;
import org.openrewrite.java.*;
import org.openrewrite.java.controlflow.Guard;
import org.openrewrite.java.dataflow.ExternalSinkModels;
import org.openrewrite.java.dataflow.LocalFlowSpec;
import org.openrewrite.java.dataflow.LocalTaintFlowSpec;
import org.openrewrite.java.dataflow.internal.InvocationMatcher;
import org.openrewrite.java.search.UsesMethod;
import org.openrewrite.java.security.internal.FileConstructorFixVisitor;
import org.openrewrite.java.security.internal.StringToFileConstructorVisitor;
import org.openrewrite.java.tree.*;
import org.openrewrite.marker.Markers;

import java.util.List;
import java.util.Optional;
import java.util.function.Function;

public class ZipSlip extends Recipe {
    private static final MethodMatcher ZIP_ENTRY_GET_NAME_METHOD_MATCHER =
            new MethodMatcher("java.util.zip.ZipEntry getName()", true);
    private static final MethodMatcher ZIP_ARCHIVE_ENTRY_GET_NAME_METHOD_MATCHER =
            new MethodMatcher("org.apache.commons.compress.archivers.zip.ZipArchiveEntry getName()", true);

    @Override
    public String getDisplayName() {
        return "Zip Slip";
    }

    @Override
    protected @Nullable TreeVisitor<?, ExecutionContext> getSingleSourceApplicableTest() {
        return new JavaIsoVisitor<ExecutionContext>() {
            @Override
            public JavaSourceFile visitJavaSourceFile(JavaSourceFile cu, ExecutionContext executionContext) {
                doAfterVisit(new UsesMethod<>(ZIP_ENTRY_GET_NAME_METHOD_MATCHER));
                doAfterVisit(new UsesMethod<>(ZIP_ARCHIVE_ENTRY_GET_NAME_METHOD_MATCHER));
                return cu;
            }
        };
    }

    @Override
    protected TreeVisitor<?, ExecutionContext> getVisitor() {
        return new JavaIsoVisitor<ExecutionContext>() {
            @Override
            public J.Block visitBlock(J.Block block, ExecutionContext executionContext) {
                J.Block b = super.visitBlock(block, executionContext);
                b = (J.Block) new FileConstructorFixVisitor<>()
                        .visitNonNull(b, executionContext, getCursor().getParentOrThrow());
                b = (J.Block) new StringToFileConstructorVisitor<>()
                        .visitNonNull(b, executionContext, getCursor().getParentOrThrow());
                b = (J.Block) new ZipSlipVisitor<>()
                        .visitNonNull(b, executionContext, getCursor().getParentOrThrow());
                return b;
            }
        };
    }

    private static class ZipSlipVisitor<P> extends JavaIsoVisitor<P> {
        private static final InvocationMatcher ZIP_ENTRY_GET_NAME = InvocationMatcher.fromInvocationMatchers(
                ZIP_ENTRY_GET_NAME_METHOD_MATCHER,
                ZIP_ARCHIVE_ENTRY_GET_NAME_METHOD_MATCHER
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
        private static class TaintedFileOrPathVisitor<P> extends JavaVisitor<P> {
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
            private static class ZipSlipSimpleInjectGuardInfo {
                static String CURSOR_KEY = "ZipSlipSimpleInjectGuardInfo";
                /**
                 * The statement to create the guard after.
                 */
                Statement statement;
                /**
                 * The parent directory expression to create the guard for.
                 */
                Expression parentDir;
                /**
                 * The child file created with the zip entry to create the guard for.
                 */
                Expression zipEntry;
            }

            @AllArgsConstructor
            public static class ZipSlipCreateNewVariableInfo {
                static String CURSOR_KEY = "ZipSlipCreateNewVariableInfo";
                String newVariableName;
                /**
                 * The statement to extract the new variable to before.
                 */
                Statement statement;
                /**
                 * The expression that needs to be extracted to a new variable.
                 */
                MethodCall extractToVariable;
            }

            @Override
            public J visitMethodInvocation(J.MethodInvocation method, P p) {
                return visitMethodCall(method, J.MethodInvocation::getSelect)
                        .<J>map(Function.identity())
                        .orElseGet(() -> super.visitMethodInvocation(method, p));
            }

            @Override
            public J visitNewClass(J.NewClass newClass, P p) {
                return visitMethodCall(newClass, n -> n.getArguments().get(0))
                        .<J>map(Function.identity())
                        .orElseGet(() -> super.visitNewClass(newClass, p));
            }

            private <M extends MethodCall> Optional<J.Identifier> visitMethodCall(M methodCall, Function<M, Expression> parentDirExtractor) {
                if (methodCall.getArguments().stream().anyMatch(taintedSinks::contains)
                        && dataflow().findSinks(new FileOrPathCreationToVulnerableUsageLocalFlowSpec()).isPresent()) {
                    J.Block firstEnclosingBlock = getCursor().firstEnclosingOrThrow(J.Block.class);
                    @SuppressWarnings("SuspiciousMethodCalls")
                    Statement enclosingStatement = getCursor()
                            .dropParentUntil(value -> firstEnclosingBlock.getStatements().contains(value))
                            .getValue();

                    J.VariableDeclarations.NamedVariable enclosingVariable =
                            getCursor().firstEnclosing(J.VariableDeclarations.NamedVariable.class);

                    if (enclosingVariable != null && unwrapNullable(enclosingVariable.getInitializer()) == methodCall) {
                        final ZipSlipSimpleInjectGuardInfo zipSlipSimpleInjectGuardInfo =
                                new ZipSlipSimpleInjectGuardInfo(
                                        enclosingStatement,
                                        parentDirExtractor.apply(methodCall),
                                        enclosingVariable.getName()
                                );
                        getCursor()
                                .dropParentUntil(J.Block.class::isInstance)
                                .putMessage(
                                        ZipSlipSimpleInjectGuardInfo.CURSOR_KEY,
                                        zipSlipSimpleInjectGuardInfo
                                );
                    } else {
                        String newVariableName = VariableNameUtils.generateVariableName(
                                "zipEntryFile",
                                getCursor(),
                                VariableNameUtils.GenerationStrategy.INCREMENT_NUMBER
                        );
                        final ZipSlipCreateNewVariableInfo zipSlipCreateNewVariableInfo =
                                new ZipSlipCreateNewVariableInfo(
                                        newVariableName,
                                        enclosingStatement,
                                        methodCall
                                );
                        getCursor()
                                .dropParentUntil(J.Block.class::isInstance)
                                .putMessage(
                                        ZipSlipCreateNewVariableInfo.CURSOR_KEY,
                                        zipSlipCreateNewVariableInfo
                                );
                        return Optional.of(new J.Identifier(
                                Tree.randomId(),
                                Space.EMPTY,
                                Markers.EMPTY,
                                newVariableName,
                                methodCall.getType(),
                                null
                        ));
                    }
                }
                return Optional.empty();
            }

            @Nullable
            private static Expression unwrapNullable(@Nullable Expression expression) {
                if (expression == null) {
                    return null;
                }
                if (expression instanceof J.Parentheses) {
                    //noinspection unchecked
                    return unwrapNullable(((J.Parentheses<Expression>) expression).getTree());
                } else {
                    return expression;
                }
            }

            @Override
            public J.Block visitBlock(J.Block block, P p) {
                J.Block b = (J.Block) super.visitBlock(block, p);
                ZipSlipCreateNewVariableInfo zipSlipCreateNewVariableInfo = getCursor().pollMessage(ZipSlipCreateNewVariableInfo.CURSOR_KEY);
                if (zipSlipCreateNewVariableInfo != null) {
                    JavaTemplate newVariableTemplate = JavaTemplate
                            .builder(
                                    this::getCursor,
                                    "final File " + zipSlipCreateNewVariableInfo.newVariableName + " = #{any(java.io.File)};"
                            )
                            .imports("java.io.File")
                            .build();
                    return b.withTemplate(
                            newVariableTemplate,
                            zipSlipCreateNewVariableInfo.statement.getCoordinates().before(),
                            zipSlipCreateNewVariableInfo.extractToVariable
                    );
                }
                ZipSlipSimpleInjectGuardInfo zipSlipSimpleInjectGuardInfo = getCursor().pollMessage(ZipSlipSimpleInjectGuardInfo.CURSOR_KEY);
                if (zipSlipSimpleInjectGuardInfo != null) {
                    JavaTemplate template;
                    if (TypeUtils.isOfClassType(zipSlipSimpleInjectGuardInfo.zipEntry.getType(), "java.io.File")) {
                        template = noZipSlipFileTemplate;
                    } else {
                        template = noZipSlipPathStartsWithPathTemplate;
                    }
                    return b.withTemplate(
                            template,
                            zipSlipSimpleInjectGuardInfo.statement.getCoordinates().after(),
                            zipSlipSimpleInjectGuardInfo.zipEntry,
                            zipSlipSimpleInjectGuardInfo.parentDir
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
