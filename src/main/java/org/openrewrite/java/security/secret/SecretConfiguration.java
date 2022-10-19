package org.openrewrite.java.security.secret;

import org.openrewrite.ExecutionContext;
import org.openrewrite.SourceFile;

public interface SecretConfiguration {
    SecretFinder[] secretFinders();

    default SourceFile findSecrets(SourceFile sourceFile, ExecutionContext ctx) {
        for (SecretFinder secretFinder : secretFinders()) {
            sourceFile = secretFinder.findSecrets(sourceFile, ctx);
        }
        return sourceFile;
    }
}
