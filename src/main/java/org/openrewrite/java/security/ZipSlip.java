/*
 * Copyright 2021 the original author or authors.
 * <p>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 * https://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.openrewrite.java.security;

import lombok.AllArgsConstructor;
import lombok.EqualsAndHashCode;
import lombok.Value;
import org.openrewrite.*;
import org.openrewrite.analysis.InvocationMatcher;
import org.openrewrite.analysis.controlflow.Guard;
import org.openrewrite.analysis.dataflow.*;
import org.openrewrite.analysis.trait.expr.Call;
import org.openrewrite.internal.lang.NonNull;
import org.openrewrite.internal.lang.Nullable;
import org.openrewrite.java.*;
import org.openrewrite.java.search.UsesMethod;
import org.openrewrite.java.security.internal.CursorUtil;
import org.openrewrite.java.security.internal.FileConstructorFixVisitor;
import org.openrewrite.java.security.internal.StringToFileConstructorVisitor;
import org.openrewrite.java.security.internal.TypeGenerator;
import org.openrewrite.java.tree.*;
import org.openrewrite.marker.Markers;

import java.time.Duration;
import java.util.*;
import java.util.function.Function;
import java.util.function.Supplier;

import static java.util.Collections.emptyList;

@Value
@EqualsAndHashCode(callSuper = true)
public class ZipSlip extends Recipe {
    private static final String ZIP_SLIP_IMPORT_REQUIRED_MESSAGE = "ZIP_SLIP_IMPORT_REQUIRED";
    private static final MethodMatcher ZIP_ENTRY_GET_NAME_METHOD_MATCHER =
            new MethodMatcher("java.util.zip.ZipEntry getName()", true);
    private static final MethodMatcher ZIP_ARCHIVE_ENTRY_GET_NAME_METHOD_MATCHER =
            new MethodMatcher("org.apache.commons.compress.archivers.zip.ZipArchiveEntry getName()", true);

    private static final InvocationMatcher ZIP_ENTRY_GET_NAME = InvocationMatcher.fromMethodMatchers(
            ZIP_ENTRY_GET_NAME_METHOD_MATCHER,
            ZIP_ARCHIVE_ENTRY_GET_NAME_METHOD_MATCHER
    );

    @Option(displayName = "Debug",
            description = "Debug and output intermediate results.",
            example = "true")
    boolean debug;

    @Override
    public String getDisplayName() {
        return "Zip slip";
    }

    @Override
    public String getDescription() {
        return "Zip slip is an arbitrary file overwrite critical vulnerability, which typically results in remote command execution. " +
                "A fuller description of this vulnerability is available in the [Snyk documentation](https://snyk.io/research/zip-slip-vulnerability) on it.";
    }

    @Override
    public Duration getEstimatedEffortPerOccurrence() {
        return Duration.ofMinutes(15);
    }

    @Override
    public TreeVisitor<?, ExecutionContext> getVisitor() {
        return Preconditions.check(Preconditions.or(
                new UsesMethod<>(ZIP_ENTRY_GET_NAME_METHOD_MATCHER),
                new UsesMethod<>(ZIP_ARCHIVE_ENTRY_GET_NAME_METHOD_MATCHER)
        ), Repeat.repeatUntilStable(new ZipSlipComplete<>(true, debug)));
    }

    @AllArgsConstructor
    static class ZipSlipComplete<P> extends JavaIsoVisitor<P> {
        boolean fixPartialPathTraversal;
        boolean debug;

        @Override
        public J.CompilationUnit visitCompilationUnit(J.CompilationUnit cu, P p) {
            J.CompilationUnit compilationUnit = super.visitCompilationUnit(cu, p);
            if (compilationUnit != cu) {
                List<String> requiredImports = getCursor().pollMessage(ZIP_SLIP_IMPORT_REQUIRED_MESSAGE);
                if (requiredImports != null) {
                    requiredImports.forEach(this::maybeAddImport);
                }
            }
            return compilationUnit;
        }

        @Override
        public J.Block visitBlock(J.Block block, P p) {
            if (fixPartialPathTraversal) {
                // Fix partial-path first before attempting to fix Zip Slip
                J.Block bPartialPathFix =
                        (J.Block) new PartialPathTraversalVulnerability.PartialPathTraversalVulnerabilityVisitor<>()
                                .visitNonNull(block, p, getCursor().getParentOrThrow());
                if (block != bPartialPathFix) {
                    return bPartialPathFix;
                }
            }
            // Partial-path fix didn't change the block, so we can continue with fixing Zip Slip
            J.Block b = super.visitBlock(block, p);
            if (b != block) {
                // Sometimes this visitor will need to be run multiple times to complete it's work
                // That's okay, just return the new block, we'll run this visitor again later if needed
                return b;
            }
            J.Block superB = b;
            Set<Expression> zipEntryExpressions = computeZipEntryExpressions();
            Supplier<FileConstructorFixVisitor<P>> fileConstructorFixVisitorSupplier =
                    () -> new FileConstructorFixVisitor<>(zipEntryExpressions::contains);
            b = (J.Block) fileConstructorFixVisitorSupplier.get()
                    .visitNonNull(b, p, getCursor().getParentOrThrow());
            b = (J.Block) new StringToFileConstructorVisitor<>(fileConstructorFixVisitorSupplier)
                    .visitNonNull(b, p, getCursor().getParentOrThrow());
            J.Block before = b;
            b = (J.Block) new ZipSlipVisitor<>()
                    .visitNonNull(b, p, getCursor().getParentOrThrow());
            if (before != b || debug) {
                // Only actually make the change if Zip Slip actually fixes a vulnerability
                return b;
            } else {
                return superB;
            }
        }

        /**
         * Compute the set of Expressions that will have been assigned to by a
         * ZipEntry.getName() call.
         */
        private Set<Expression> computeZipEntryExpressions() {
            return CursorUtil.findOuterExecutableBlock(getCursor()).map(outerExecutable -> outerExecutable.computeMessageIfAbsent("computed-zip-entry-expressions", __ -> {
                Set<Expression> zipEntryExpressions = new HashSet<>();
                new JavaIsoVisitor<Set<Expression>>() {
                    @Override
                    public J.MethodInvocation visitMethodInvocation(J.MethodInvocation method, Set<Expression> zipEntryExpressionsInternal) {
                        Dataflow.startingAt(getCursor()).findSinks(new ZipEntryToAnyLocalFlowSpec()).forEach(sinkFlow ->
                                zipEntryExpressionsInternal.addAll(sinkFlow.getExpressionSinks()));
                        return super.visitMethodInvocation(method, zipEntryExpressionsInternal);
                    }
                }.visit(outerExecutable.getValue(), zipEntryExpressions, outerExecutable.getParentOrThrow());
                return zipEntryExpressions;
            })).orElseGet(HashSet::new);
        }
    }

    private static class ZipEntryToAnyLocalFlowSpec extends DataFlowSpec {
        @Override
        public boolean isSource(DataFlowNode srcNode) {
            return srcNode.asExprParent(Call.class).map(call -> call.matches(ZIP_ENTRY_GET_NAME)).orSome(false);
        }

        @Override
        public boolean isSink(DataFlowNode sinkNode) {
            return true;
        }
    }

    private static class ZipEntryToFileOrPathCreationLocalFlowSpec extends DataFlowSpec {
        private static final InvocationMatcher FILE_CREATE = InvocationMatcher.fromMethodMatcher(
                new MethodMatcher("java.io.File <constructor>(.., java.lang.String)")
        );
        private static final InvocationMatcher PATH_RESOLVE = InvocationMatcher.fromMethodMatcher(
                new MethodMatcher("java.nio.file.Path resolve(..)")
        );

        @Override
        public boolean isSource(DataFlowNode srcNode) {
            return srcNode.asExprParent(Call.class).map(call -> call.matches(ZIP_ENTRY_GET_NAME)).orSome(false);
        }

        @Override
        public boolean isSink(DataFlowNode sinkNode) {
            return FILE_CREATE.advanced().isParameter(sinkNode.getCursor(), 1) ||
                    PATH_RESOLVE.advanced().isFirstParameter(sinkNode.getCursor());
        }
    }

    private static class ZipSlipVisitor<P> extends JavaIsoVisitor<P> {

        @Override
        public J.MethodInvocation visitMethodInvocation(J.MethodInvocation method, P p) {
            Dataflow.startingAt(getCursor()).findSinks(new ZipEntryToFileOrPathCreationLocalFlowSpec()).forEach(sinkFlow ->
                    doAfterVisit(new TaintedFileOrPathVisitor<>(sinkFlow.getExpressionSinks()))
            );
            return super.visitMethodInvocation(method, p);
        }

        /**
         * Visitor that handles known tainted {@link java.io.File} or {@link java.nio.file.Path}
         * objects that have been tainted by zip entry getName() calls.
         */
        @AllArgsConstructor
        @EqualsAndHashCode(callSuper = false, onlyExplicitlyIncluded = true)
        private static class TaintedFileOrPathVisitor<P> extends JavaVisitor<P> {
            private static final String IO_EXCEPTION_FQN = "java.io.IOException";
            private static final String RUNTIME_EXCEPTION_THROW_LINE = "    throw new RuntimeException(\"Bad zip entry\");\n";
            private static final String IO_EXCEPTION_THROW_LINE = "    throw new IOException(\"Bad zip entry\");\n";

            private final JavaType ioException = TypeGenerator.generate(IO_EXCEPTION_FQN);

            private void maybeAddImportIOException() {
                getCursor()
                        .dropParentUntil(J.CompilationUnit.class::isInstance)
                        .computeMessageIfAbsent(ZIP_SLIP_IMPORT_REQUIRED_MESSAGE, __ -> Collections.singletonList(IO_EXCEPTION_FQN));
            }

            private JavaTemplate noZipSlipFileTemplate() {
                boolean canSupportIoException = canSupportIoException();
                String exceptionLine = canSupportIoException ? IO_EXCEPTION_THROW_LINE : RUNTIME_EXCEPTION_THROW_LINE;
                JavaTemplate.Builder noZipSlipFileTemplate = JavaTemplate.builder("" +
                        "if (!#{any(java.io.File)}.toPath().normalize().startsWith(#{any(java.io.File)}.toPath().normalize())) {\n" +
                        exceptionLine +
                        "}").contextSensitive();
                if (canSupportIoException) {
                    noZipSlipFileTemplate.imports(IO_EXCEPTION_FQN);
                    maybeAddImportIOException();
                }
                return noZipSlipFileTemplate.build();
            }

            private JavaTemplate noZipSlipFileWithStringTemplate() {
                boolean canSupportIoException = canSupportIoException();
                String exceptionLine = canSupportIoException ? IO_EXCEPTION_THROW_LINE : RUNTIME_EXCEPTION_THROW_LINE;
                JavaTemplate.Builder noZipSlipFileWithStringTemplate = JavaTemplate.builder("" +
                        "if (!#{any(java.io.File)}.toPath().normalize().startsWith(#{any(String)})) {\n" +
                        exceptionLine +
                        "}").contextSensitive();
                if (canSupportIoException) {
                    noZipSlipFileWithStringTemplate.imports(IO_EXCEPTION_FQN);
                    maybeAddImportIOException();
                }
                return noZipSlipFileWithStringTemplate.build();
            }

            private JavaTemplate noZipSlipPathStartsWithPathTemplate() {
                boolean canSupportIoException = canSupportIoException();
                String exceptionLine = canSupportIoException ? IO_EXCEPTION_THROW_LINE : RUNTIME_EXCEPTION_THROW_LINE;
                JavaTemplate.Builder noZipSlipPathStartsWithPathTemplate = JavaTemplate.builder("" +
                        "if (!#{any(java.nio.file.Path)}.normalize().startsWith(#{any(java.nio.file.Path)}.normalize())) {\n" +
                        exceptionLine +
                        "}").contextSensitive();
                if (canSupportIoException) {
                    noZipSlipPathStartsWithPathTemplate.imports(IO_EXCEPTION_FQN);
                    maybeAddImportIOException();
                }
                return noZipSlipPathStartsWithPathTemplate.build();
            }

            private boolean canSupportIoException() {
                Iterator<Cursor> cursors =
                        getCursor()
                                .getPathAsCursors(
                                        c -> isStaticOrInitBlockSafe(c) ||
                                                c.getValue() instanceof J.MethodDeclaration ||
                                                c.getValue() instanceof J.Try
                                );
                while (cursors.hasNext()) {
                    Cursor cursor = cursors.next();
                    if (isStaticOrInitBlockSafe(cursor)) {
                        return false;
                    } else if (cursor.getValue() instanceof J.Try) {
                        J.Try tryBlock = cursor.getValue();
                        if (tryBlock.getCatches().stream().anyMatch(catchClause ->
                                catchClause.getParameter().getTree().getVariables().stream().anyMatch(v ->
                                        TypeUtils.isAssignableTo(v.getType(), ioException)))) {
                            return true;
                        }
                    } else if (cursor.getValue() instanceof J.MethodDeclaration) {
                        J.MethodDeclaration methodDeclaration = cursor.getValue();
                        if (methodDeclaration.getThrows() != null &&
                                methodDeclaration.getThrows().stream().anyMatch(throwsClause ->
                                        TypeUtils.isAssignableTo(throwsClause.getType(), ioException))) {
                            return true;
                        }
                    }
                }
                return false;
            }

            private static boolean isStaticOrInitBlockSafe(Cursor cursor) {
                return cursor.getValue() instanceof J.Block && J.Block.isStaticOrInitBlock(cursor);
            }

            @EqualsAndHashCode.Include
            private final List<Expression> taintedSinks;

            @Value
            @NonNull
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

            @Value
            @NonNull
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
            public J visitAssignment(J.Assignment assignment, P p) {
                J newAssignment = super.visitAssignment(assignment, p);
                if (assignment != newAssignment) {
                    return maybeAutoFormat(assignment, newAssignment, p, getCursor().getParentOrThrow());
                }
                return newAssignment;
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
                        && Dataflow.startingAt(getCursor()).findSinks(new FileOrPathCreationToVulnerableUsageLocalFlowSpec()).isSome()) {
                    J.Block firstEnclosingBlock = getCursor().firstEnclosingOrThrow(J.Block.class);
                    @SuppressWarnings("SuspiciousMethodCalls")
                    Statement enclosingStatement = getCursor()
                            .dropParentUntil(value -> firstEnclosingBlock.getStatements().contains(value))
                            .getValue();

                    J.VariableDeclarations.NamedVariable enclosingVariable =
                            getCursor().firstEnclosing(J.VariableDeclarations.NamedVariable.class);

                    if (enclosingVariable != null && Expression.unwrap(enclosingVariable.getInitializer()) == methodCall) {
                        J.Identifier enclosingVariableIdentifier = enclosingVariable.getName();

                        ZipSlipSimpleInjectGuardInfo zipSlipSimpleInjectGuardInfo =
                                new ZipSlipSimpleInjectGuardInfo(
                                        enclosingStatement,
                                        parentDirExtractor.apply(methodCall),
                                        enclosingVariableIdentifier
                                );
                        getCursor()
                                .dropParentUntil(J.Block.class::isInstance)
                                .putMessage(
                                        ZipSlipSimpleInjectGuardInfo.CURSOR_KEY,
                                        zipSlipSimpleInjectGuardInfo
                                );
                    } else {
                        String newVariableBaseName;
                        if (isTypePath(methodCall.getType())) {
                            newVariableBaseName = "zipEntryPath";
                        } else {
                            assert isTypeFile(methodCall.getType()) :
                                    "Expected method call to be of type `java.io.File` or `java.nio.file.Path` but was `" + methodCall.getType() + "`";
                            newVariableBaseName = "zipEntryFile";
                        }
                        String newVariableName = VariableNameUtils.generateVariableName(
                                newVariableBaseName,
                                getCursor(),
                                VariableNameUtils.GenerationStrategy.INCREMENT_NUMBER
                        );
                        ZipSlipCreateNewVariableInfo zipSlipCreateNewVariableInfo =
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
                                emptyList(),
                                newVariableName,
                                methodCall.getType(),
                                null
                        ));
                    }
                }
                return Optional.empty();
            }

            @Override
            public J.Block visitBlock(J.Block block, P p) {
                J.Block b = (J.Block) super.visitBlock(block, p);
                ZipSlipCreateNewVariableInfo zipSlipCreateNewVariableInfo = getCursor().pollMessage(ZipSlipCreateNewVariableInfo.CURSOR_KEY);
                if (zipSlipCreateNewVariableInfo != null) {
                    JavaTemplate newVariableTemplate;
                    if (isTypePath(zipSlipCreateNewVariableInfo.extractToVariable.getType())) {
                        newVariableTemplate = JavaTemplate
                                .builder(
                                        "final Path " + zipSlipCreateNewVariableInfo.newVariableName + " = #{any(java.nio.file.Path)};"
                                )
                                .contextSensitive()
                                .imports("java.nio.file.Path")
                                .build();
                        maybeAddImport("java.nio.file.Path");
                    } else {
                        assert isTypeFile(zipSlipCreateNewVariableInfo.extractToVariable.getType());
                        newVariableTemplate = JavaTemplate
                                .builder(
                                        "final File " + zipSlipCreateNewVariableInfo.newVariableName + " = #{any(java.io.File)};"
                                )
                                .contextSensitive()
                                .imports("java.io.File")
                                .build();
                        maybeAddImport("java.io.File");
                    }
                    return newVariableTemplate.apply(
                            new Cursor(getCursor().getParent(), b),
                            zipSlipCreateNewVariableInfo.statement.getCoordinates().before(),
                            zipSlipCreateNewVariableInfo.extractToVariable);
                }
                ZipSlipSimpleInjectGuardInfo zipSlipSimpleInjectGuardInfo = getCursor().pollMessage(ZipSlipSimpleInjectGuardInfo.CURSOR_KEY);
                if (zipSlipSimpleInjectGuardInfo != null) {
                    JavaTemplate template;
                    if (isTypeFile(zipSlipSimpleInjectGuardInfo.zipEntry.getType())) {
                        if (isTypeFile(zipSlipSimpleInjectGuardInfo.parentDir.getType())) {
                            template = noZipSlipFileTemplate();
                        } else {
                            assert TypeUtils.isString(zipSlipSimpleInjectGuardInfo.parentDir.getType());
                            template = noZipSlipFileWithStringTemplate();
                        }
                    } else {
                        assert isTypePath(zipSlipSimpleInjectGuardInfo.zipEntry.getType());
                        template = noZipSlipPathStartsWithPathTemplate();
                    }
                    return template.apply(
                            new Cursor(getCursor().getParent(), b),
                            zipSlipSimpleInjectGuardInfo.statement.getCoordinates().after(),
                            zipSlipSimpleInjectGuardInfo.zipEntry,
                            zipSlipSimpleInjectGuardInfo.parentDir);
                }
                return b;
            }
        }

        private static class FileOrPathCreationToVulnerableUsageLocalFlowSpec extends TaintFlowSpec {
            private static final MethodMatcher PATH_STARTS_WITH_MATCHER =
                    new MethodMatcher("java.nio.file.Path startsWith(..) ");
            private static final MethodMatcher STRING_STARTS_WITH_MATCHER =
                    new MethodMatcher("java.lang.String startsWith(..) ");

            @Override
            public boolean isSource(DataFlowNode srcNode) {
                return true;
            }

            @Override
            public boolean isSink(DataFlowNode sinkNode) {
                return ExternalSinkModels.instance().isSinkNode(sinkNode, "create-file");
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

    private static boolean isTypeFile(@Nullable JavaType type) {
        return TypeUtils.isOfClassType(type, "java.io.File");
    }

    private static boolean isTypePath(@Nullable JavaType type) {
        return TypeUtils.isOfClassType(type, "java.nio.file.Path");
    }
}
