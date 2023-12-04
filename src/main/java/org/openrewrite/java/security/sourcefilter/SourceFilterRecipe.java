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

import org.openrewrite.ExecutionContext;
import org.openrewrite.ScanningRecipe;
import org.openrewrite.TreeVisitor;

public abstract class SourceFilterRecipe extends ScanningRecipe<SourceFilterOptions.Accumulator> {

    public abstract SourceFilterOptions getSecurityRecipeOptions();

    @Override
    public SourceFilterOptions.Accumulator getInitialValue(ExecutionContext ctx) {
        return SourceFilterOptions.Accumulator.create(getSecurityRecipeOptions());
    }

    @Override
    public TreeVisitor<?, ExecutionContext> getScanner(SourceFilterOptions.Accumulator acc) {
        return acc.scanner(this::getSourceFilteredVisitor);
    }

    @Override
    public final TreeVisitor<?, ExecutionContext> getVisitor(SourceFilterOptions.Accumulator acc) {
        return acc.getVisitor(this::getSourceFilteredVisitor);
    }

    public abstract TreeVisitor<?, ExecutionContext> getSourceFilteredVisitor();

}
