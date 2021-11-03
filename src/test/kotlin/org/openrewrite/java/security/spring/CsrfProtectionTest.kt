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
package org.openrewrite.java.security.spring

import org.junit.jupiter.api.Test
import org.openrewrite.Recipe
import org.openrewrite.java.JavaParser
import org.openrewrite.java.JavaRecipeTest
import org.openrewrite.java.cache.ClasspathJavaTypeCache
import org.openrewrite.java.cache.JavaTypeCache

class CsrfProtectionTest : JavaRecipeTest {
    override val parser: JavaParser
        get() = JavaParser.fromJavaVersion()
            .classpath(JavaParser.runtimeClasspath())
            .build()

    override val typeCache: JavaTypeCache
        get() = ClasspathJavaTypeCache()

    override val recipe: Recipe
        get() = CsrfProtection(null)

    @Test
    fun withSecurityConfig() = assertChanged(
        dependsOn = arrayOf("""
            import org.springframework.boot.autoconfigure.SpringBootApplication;
            
            @SpringBootApplication
            class Application {
            }
        """),
        before = """
            import org.springframework.context.annotation.Configuration;
            import org.springframework.security.config.annotation.web.builders.HttpSecurity;
            import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
            
            @Configuration
            class SecurityConfig extends WebSecurityConfigurerAdapter {
                @Override
                protected void configure(HttpSecurity http) throws Exception {
                }
            }
        """,
        after = """
            import org.springframework.context.annotation.Configuration;
            import org.springframework.security.config.annotation.web.builders.HttpSecurity;
            import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
            import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
            
            @Configuration
            class SecurityConfig extends WebSecurityConfigurerAdapter {
                @Override
                protected void configure(HttpSecurity http) throws Exception {
                    http.csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());
                }
            }
        """,
        cycles = 2,
        expectedCyclesThatMakeChanges = 2
    )
}
