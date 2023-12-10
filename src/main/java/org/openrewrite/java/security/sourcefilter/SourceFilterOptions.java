/*
 * Copyright 2023 the original author or authors.
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
package org.openrewrite.java.security.sourcefilter;

import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.Value;
import org.openrewrite.*;
import org.openrewrite.internal.lang.Nullable;
import org.openrewrite.java.search.IsLikelyNotTest;

import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Supplier;

@Value
public class SourceFilterOptions {
    public enum SourceFilter {
        ALL,
        ALL_WHEN_NON_TEST,
        NON_TEST
    }

    @Option(
            displayName = "Source Filter",
            description = "The source sets to apply this recipe to. \n" +
                          " - `ALL`: Apply to all source sets.\n" +
                          " - `ALL-WHEN-NON-TEST`: Only when the recipe changes non-test code, also apply it to test code. " +
                          "IE. Only apply this recipe to all source files, when a non-test file will be modified.\n" +
                          " - `NON-TEST`: Apply only to non-test code.",
            valid = {"ALL", "ALL-WHEN-NON-TEST", "NON-TEST"},
            example = "ALL",
            required = false
    )
    SourceFilter sourceFilter;

    public SourceFilter getSourceFilter() {
        //noinspection ConstantValue
        if (sourceFilter == null) {
            return SourceFilter.ALL;
        }
        return sourceFilter;
    }

    @RequiredArgsConstructor(access = AccessLevel.PACKAGE, staticName = "create")
    public static class Accumulator {
        private final SourceFilterOptions options;
        private final AtomicBoolean hasNonTestModifications = new AtomicBoolean(false);

        TreeVisitor<?, ExecutionContext> scanner(Supplier<TreeVisitor<?, ExecutionContext>> visitor) {
            switch (options.getSourceFilter()) {
                case ALL:
                case NON_TEST:
                    return TreeVisitor.noop();
                case ALL_WHEN_NON_TEST:
                    return new TreeVisitor<Tree, ExecutionContext>() {
                        @Override
                        public @Nullable Tree visit(@Nullable Tree tree, ExecutionContext ctx) {
                            if (!hasNonTestModifications.get()
                                && new IsLikelyNotTest().getVisitor().visit(tree, ctx) != tree
                                && visitor.get().visit(tree, ctx) != tree) {
                                hasNonTestModifications.set(true);
                            }
                            return tree;
                        }
                    };
                default:
                    throw new IllegalStateException("Unsupported source filter " + options.getSourceFilter());
            }
        }

        TreeVisitor<?, ExecutionContext> getVisitor(Supplier<TreeVisitor<?, ExecutionContext>> visitor) {
            switch (options.getSourceFilter()) {
                case ALL:
                    return visitor.get();
                case ALL_WHEN_NON_TEST:
                    if (hasNonTestModifications.get()) {
                        return visitor.get();
                    } else {
                        return TreeVisitor.noop();
                    }
                case NON_TEST:
                    Preconditions.check(new IsLikelyNotTest(), visitor.get());
                default:
                    throw new IllegalStateException("Unsupported source filter " + options.getSourceFilter());
            }
        }
    }

}
