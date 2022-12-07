/*
 * Copyright 2022 the original author or authors.
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

import org.openrewrite.ExecutionContext;
import org.openrewrite.internal.lang.Nullable;
import org.openrewrite.java.JavaIsoVisitor;
import org.openrewrite.java.JavaTemplate;
import org.openrewrite.java.MethodMatcher;
import org.openrewrite.java.tree.J;
import org.openrewrite.java.tree.JavaType;

import java.util.List;

class SecureTempFileCreationVisitor extends JavaIsoVisitor<ExecutionContext> {

    static final MethodMatcher MATCHER = new MethodMatcher("java.io.File createTempFile(..)");
    private final JavaTemplate twoArg = JavaTemplate.builder(this::getCursor, "Files.createTempFile(#{any(String)}, #{any(String)}).toFile()")
            .imports("java.nio.file.Files")
            .build();

    private final JavaTemplate threeArg = JavaTemplate.builder(this::getCursor, "Files.createTempFile(#{any(java.io.File)}.toPath(), #{any(String)}, #{any(String)}).toFile()")
            .imports("java.nio.file.Files")
            .build();

    @Override
    public void visit(@Nullable List<? extends J> nodes, ExecutionContext executionContext) {
        super.visit(nodes, executionContext);
    }

    @Override
    public J.Block visitBlock(J.Block block, ExecutionContext executionContext) {
        J.Block createTempDirectoryFix = (J.Block) new UseFilesCreateTempDirectory()
                .getVisitor()
                .visitNonNull(block, executionContext, getCursor().getParentOrThrow());
        if (createTempDirectoryFix != block) {
            // If the issue could be fixed by the UseFilesCreateTempDirectory's visitor
            // then this visitor should not be applied.
            return block;
        } else {
            return super.visitBlock(block, executionContext);
        }
    }

    @Override
    public J.MethodInvocation visitMethodInvocation(J.MethodInvocation method, ExecutionContext executionContext) {
        J.MethodInvocation m = method;
        if (MATCHER.matches(m)) {
            maybeAddImport("java.nio.file.Files");
            if (m.getArguments().size() == 2 || (m.getArguments().size() == 3 && m.getArguments().get(2).getType() == JavaType.Primitive.Null)) {
                // File.createTempFile(String prefix, String suffix)
                m = m.withTemplate(twoArg,
                        m.getCoordinates().replace(),
                        m.getArguments().get(0),
                        m.getArguments().get(1)
                );
            } else if (m.getArguments().size() == 3) {
                // File.createTempFile(String prefix, String suffix, File dir)
                m = m.withTemplate(threeArg,
                        m.getCoordinates().replace(),
                        m.getArguments().get(2),
                        m.getArguments().get(0),
                        m.getArguments().get(1)
                );
            }
        }
        return m;
    }
}
