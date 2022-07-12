package org.openrewrite.java.security.internal;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import org.openrewrite.Cursor;
import org.openrewrite.java.tree.J;

import java.util.Iterator;
import java.util.Optional;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class CursorUtil {
    /**
     * Find the outermost executable {@link J.Block} that is an executable set of instructions.
     * This is one of the following:
     * <ul>
     *     <li>A {@link J.Block} that is either static or an init block.</li>
     *     <li>The block held by a {@link J.MethodInvocation}.</li>
     * </ul>
     */
    public static Optional<Cursor> findOuterExecutableBlock(Cursor start) {
        Iterator<Cursor> path = start.getPathAsCursors();
        Cursor parent = path.next();
        while (path.hasNext()) {
            Cursor cursor = path.next();
            if (cursor.getValue() instanceof J.MethodDeclaration) {
                assert parent.getValue() instanceof J.Block : "Parent of method declaration is not a block. Was: " + parent.getValue();
                return Optional.of(parent);
            }
            if (cursor.getValue() instanceof J.Block && J.Block.isStaticOrInitBlock(cursor)) {
                return Optional.of(cursor);
            }
            parent = cursor;
        }
        return Optional.empty();
    }

    public static Cursor findOuterExecutableBlockOrThrow(Cursor start) {
        return findOuterExecutableBlock(start)
                .orElseThrow(() -> new IllegalStateException("Could not find outer executable block"));
    }
}
