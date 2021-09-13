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
package org.openrewrite.java.security.marshalling;

import org.openrewrite.ExecutionContext;
import org.openrewrite.Recipe;
import org.openrewrite.java.JavaParser;
import org.openrewrite.java.JavaTemplate;
import org.openrewrite.java.JavaVisitor;
import org.openrewrite.java.MethodMatcher;
import org.openrewrite.java.tree.J;
import org.openrewrite.java.tree.JavaType;
import org.openrewrite.java.tree.TypeUtils;

public class SecureSnakeYamlConstructor extends Recipe {

    @Override
    public String getDisplayName() {
        return "Secure the use of SnakeYAML's constructor";
    }

    @Override
    public String getDescription() {
        return "See the [paper](https://github.com/mbechler/marshalsec) on this subject.";
    }

    @Override
    protected JavaVisitor<ExecutionContext> getVisitor() {
        MethodMatcher snakeYamlConstructor = new MethodMatcher("org.yaml.snakeyaml.Yaml <constructor>()", true);
        return new JavaVisitor<ExecutionContext>() {
            @Override
            public J visitNewClass(J.NewClass newClass, ExecutionContext ctx) {
                if (snakeYamlConstructor.matches(newClass)) {
                    JavaType.Method ctorType = TypeUtils.asMethod(newClass.getConstructorType());
                    assert ctorType != null;

                    maybeAddImport("org.yaml.snakeyaml.constructor.SafeConstructor");
                    return newClass.withTemplate(
                            JavaTemplate
                                    .builder(this::getCursor, "new Yaml(new SafeConstructor())")
                                    .imports("org.yaml.snakeyaml.Yaml")
                                    .imports("org.yaml.snakeyaml.constructor.SafeConstructor")
                                    .javaParser(() -> JavaParser.fromJavaVersion()
                                            .classpath("snakeyaml")
                                            .build())
                                    .build(),
                            newClass.getCoordinates().replace()
                    );
                }

                return super.visitNewClass(newClass, ctx);
            }
        };
    }
}
