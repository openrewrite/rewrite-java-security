package org.openrewrite.java.security;

import org.openrewrite.ExecutionContext;
import org.openrewrite.Recipe;
import org.openrewrite.java.JavaIsoVisitor;
import org.openrewrite.java.MethodMatcher;
import org.openrewrite.java.search.UsesMethod;
import org.openrewrite.java.tree.Expression;
import org.openrewrite.java.tree.J;
import org.openrewrite.java.tree.JavaType;
import org.openrewrite.java.tree.TypeUtils;

import java.time.Duration;
import java.util.Collections;
import java.util.Set;

public class SecureRandomPrefersDefaultSeed extends Recipe {

    @Override
    public String getDisplayName() {
        return "SecureRandom seeds should not be predictable";
    }

    @Override
    public String getDescription() {
        return "Seeding `java.security.SecureRandom` with constant or predictable values is not recommended. This recipe will remove `SecureRandom#setSeed(*) invocations having weak arguments in favor of the implementation's default seed.";
    }

    @Override
    public Set<String> getTags() {
        return Collections.singleton("RSPEC-4347");
    }

    @Override
    public Duration getEstimatedEffortPerOccurrence() {
        return Duration.ofMinutes(2);
    }

    @Override
    protected UsesMethod<ExecutionContext> getSingleSourceApplicableTest() {
        return new UsesMethod<>("java.security.SecureRandom setSeed(..)");
    }

    @Override
    protected SecureRandomUseDefaultSeedVisitor getVisitor() {
        return new SecureRandomUseDefaultSeedVisitor();
    }

    private static class SecureRandomUseDefaultSeedVisitor extends JavaIsoVisitor<ExecutionContext> {
        private static final MethodMatcher SET_SEED_MATCHER = new MethodMatcher("java.security.SecureRandom setSeed(..)");
        private static final MethodMatcher SYSTEM_TIME_MATCHER = new MethodMatcher("System currentTimeMillis()");
        private static final MethodMatcher STRING_BYTES_MATCHER = new MethodMatcher("String getBytes()");
        private final JavaType dateType = JavaType.buildType("java.util.Date");

        @Override
        public J.MethodInvocation visitMethodInvocation(J.MethodInvocation method, ExecutionContext executionContext) {
            J.MethodInvocation mi = super.visitMethodInvocation(method, executionContext);
            if (SET_SEED_MATCHER.matches(mi)) {
                boolean isWeakSeed = false;
                for (Expression arg : mi.getArguments()) {
                    if (arg instanceof J.Literal) {
                        isWeakSeed = true;
                    } else if (arg instanceof J.MethodInvocation) {
                        J.MethodInvocation argMi = (J.MethodInvocation) arg;
                        if (SYSTEM_TIME_MATCHER.matches(arg)
                                || (STRING_BYTES_MATCHER.matches(argMi) && argMi.getSelect() instanceof J.Literal)) {
                            isWeakSeed = true;
                        } else if (argMi.getType() != null && TypeUtils.isAssignableTo(dateType, argMi.getType().getDeclaringType())) {
                            isWeakSeed = true;
                            maybeRemoveImport("java.util.Date");
                        }
                    }
                }
                if (isWeakSeed) {
                    //noinspection ConstantConditions
                    return null;
                }
            }
            return mi;
        }
    }


}
