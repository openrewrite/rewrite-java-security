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
import org.openrewrite.ExecutionContext;
import org.openrewrite.Option;
import org.openrewrite.Recipe;
import org.openrewrite.TreeVisitor;
import org.openrewrite.internal.lang.Nullable;
import org.openrewrite.java.JavaIsoVisitor;
import org.openrewrite.java.search.UsesMethod;
import org.openrewrite.java.tree.J;

import java.nio.file.Path;
import java.time.Duration;


@Value
@EqualsAndHashCode(callSuper = true)
public class SecureTempFileCreation extends Recipe {

    @AllArgsConstructor
    enum Target {
        AllSource(Target.ALL_SOURCE),
        AllSourceWhenNonTestDetected(Target.ALL_SOURCE_IF_DETECTED_IN_NON_TEST),
        NonTestSource(Target.NON_TEST_SOURCE);

        static final String ALL_SOURCE = "All Source";
        static final String ALL_SOURCE_IF_DETECTED_IN_NON_TEST = "All Source if detected in Non Test Source";
        static final String NON_TEST_SOURCE = "Non-Test Source";

        private static Target fromString(@Nullable String target) {
            if (target == null) {
                return NonTestSource;
            }
            switch (target) {
                case ALL_SOURCE:
                    return AllSource;
                case ALL_SOURCE_IF_DETECTED_IN_NON_TEST:
                    return AllSourceWhenNonTestDetected;
                default:
                    return NonTestSource;
            }
        }

        private final String description;
    }

    @Option(
            displayName = "Target",
            description = "Specify whether this recipe should apply to all sources or only non-test sources. Defaults to non-test sources.",
            required = false,
            valid = {
                    Target.ALL_SOURCE,
                    Target.ALL_SOURCE_IF_DETECTED_IN_NON_TEST,
                    Target.NON_TEST_SOURCE
            },
            example = Target.ALL_SOURCE
    )
    String target;

    @Override
    public String getDisplayName() {
        return "Use secure temporary file creation";
    }

    @Override
    public String getDescription() {
        return "`java.io.File.createTempFile()` has exploitable default file permissions. This recipe migrates to the more secure `java.nio.file.Files.createTempFile()`.";
    }

    @Override
    public Duration getEstimatedEffortPerOccurrence() {
        return Duration.ofMinutes(5);
    }

    @Override
    protected TreeVisitor<?, ExecutionContext> getApplicableTest() {
        Target target = Target.fromString(getTarget());
        return new JavaIsoVisitor<ExecutionContext>() {
            @Override
            public J.CompilationUnit visitCompilationUnit(J.CompilationUnit cu, ExecutionContext executionContext) {
                // If the target is Non Test Source, and this is a test source file, skip it.
                if ((Target.NonTestSource.equals(target) || Target.AllSourceWhenNonTestDetected.equals(target)) && isTestSource(cu.getSourcePath())) {
                    return cu;
                }
                if (getSingleSourceApplicableTest().visitNonNull(cu, executionContext) != cu) {
                    return (J.CompilationUnit) getVisitor().visitNonNull(cu, executionContext, getCursor().getParentOrThrow());
                }
                return cu;
            }
        };
    }

    @Override
    protected JavaIsoVisitor<ExecutionContext> getSingleSourceApplicableTest() {
        return new UsesMethod<>(SecureTempFileCreationVisitor.MATCHER);
    }

    @Override
    protected JavaIsoVisitor<ExecutionContext> getVisitor() {
        return new SecureTempFileCreationVisitor();
    }

    static boolean isTestSource(Path path) {
        return path.getFileSystem().getPathMatcher("glob:**/test/**").matches(path);
    }
}
