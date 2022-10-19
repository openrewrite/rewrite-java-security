package org.openrewrite.java.security.secret;

import org.openrewrite.ExecutionContext;
import org.openrewrite.SourceFile;
import org.openrewrite.Tree;
import org.openrewrite.TreeVisitor;
import org.openrewrite.internal.lang.Nullable;
import org.openrewrite.test.RecipeSpec;
import org.openrewrite.test.RewriteTest;

public interface SecretConfigurationTest extends RewriteTest {
    SecretConfiguration secretConfiguration();

    @Override
    default void defaults(RecipeSpec spec) {
        spec.recipe(RewriteTest.toRecipe(() -> new TreeVisitor<>(){
            @Override
            public @Nullable Tree visitSourceFile(@Nullable SourceFile sourceFile, ExecutionContext executionContext) {
                if (sourceFile == null) {
                    return null;
                }
                return secretConfiguration().findSecrets(sourceFile, executionContext);
            }
        }));
    }
}
