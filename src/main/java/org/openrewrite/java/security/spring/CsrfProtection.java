package org.openrewrite.java.security.spring;

import lombok.EqualsAndHashCode;
import lombok.Value;
import org.openrewrite.*;
import org.openrewrite.internal.lang.Nullable;
import org.openrewrite.java.*;
import org.openrewrite.java.search.HasTypeOnClasspathSourceSet;
import org.openrewrite.java.search.UsesType;
import org.openrewrite.java.tree.J;
import org.openrewrite.java.tree.JavaType;

import java.util.List;

@Value
@EqualsAndHashCode(callSuper = true)
public class CsrfProtection extends Recipe {
    @Option(displayName = "Only if security configuration exists",
            description = "Only patch existing implementations of `WebSecurityConfigurerAdapter`.",
            required = false)
    @Nullable
    Boolean onlyIfSecurityConfig;

    @Override
    public String getDisplayName() {
        return "Enable CSRF attack prevention";
    }

    @Override
    public String getDescription() {
        return "Cross-Site Request Forgery (CSRF) is a type of attack that occurs when a malicious web site, email, blog, instant message, or program causes a user's web browser to perform an unwanted action on a trusted site when the user is authenticated. See the full [OWASP cheatsheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html).";
    }

    @Override
    protected TreeVisitor<?, ExecutionContext> getApplicableTest() {
        return new HasTypeOnClasspathSourceSet<>("org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter");
    }

    @Override
    protected TreeVisitor<?, ExecutionContext> getSingleSourceApplicableTest() {
        return new UsesType<>("org.springframework.security.web.csrf.CookieCsrfTokenRepository");
    }

    private static final MethodMatcher CSRF = new MethodMatcher("org.springframework.security.config.annotation.web.builders.HttpSecurity csrf()");

    @Override
    protected List<SourceFile> visit(List<SourceFile> before, ExecutionContext ctx) {
        return super.visit(new GenerateWebSecurityConfigurerAdapter(Boolean.TRUE.equals(onlyIfSecurityConfig), new JavaVisitor<ExecutionContext>() {
            @Override
            public J visitBlock(J.Block block, ExecutionContext executionContext) {
                for (JavaType javaType : getCursor().firstEnclosingOrThrow(J.CompilationUnit.class).getTypesInUse()) {
                    if (CSRF.matches(javaType)) {
                        return block;
                    }
                }

                return block.withTemplate(
                        JavaTemplate
                                .builder(this::getCursor, "http" +
                                        ".csrf()" +
                                        ".csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());")
                                .imports("org.springframework.security.web.csrf.CookieCsrfTokenRepository")
                                .javaParser(() -> JavaParser.fromJavaVersion()
                                        .classpath(
                                                "spring-security-config",
                                                "spring-context",
                                                "jakarta.servlet-api",
                                                "spring-security-web"
                                        )
                                        .build())
                                .build(),
                        block.getCoordinates().lastStatement()
                );
            }
        }).maybeAddConfiguration(before, ctx), ctx);
    }

    @Override
    protected JavaVisitor<ExecutionContext> getVisitor() {
        return new AddImport<>("org.springframework.security.web.csrf.CookieCsrfTokenRepository", null, true);
    }
}
