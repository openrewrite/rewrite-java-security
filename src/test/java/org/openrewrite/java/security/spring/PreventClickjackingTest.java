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
package org.openrewrite.java.security.spring;

import org.junit.jupiter.api.Test;
import org.openrewrite.InMemoryExecutionContext;
import org.openrewrite.internal.lang.Nullable;
import org.openrewrite.java.JavaParser;
import org.openrewrite.test.RecipeSpec;
import org.openrewrite.test.RewriteTest;

import static org.openrewrite.java.Assertions.java;

class PreventClickjackingTest implements RewriteTest {
    @Override
    public void defaults(RecipeSpec spec) {
        InMemoryExecutionContext ctx = new InMemoryExecutionContext() {
            @Override
            public void putMessage(String key, @Nullable Object value) {
                if (!key.equals(JavaParser.SKIP_SOURCE_SET_TYPE_GENERATION)) {
                    super.putMessage(key, value);
                }
            }
        };

        spec.recipe(new PreventClickjacking(null))
          .parser(JavaParser.fromJavaVersion()
            .classpath("spring-boot-autoconfigure", "spring-security-config", "spring-context", "jakarta.servlet-api"))
          .executionContext(ctx);
    }

    @SuppressWarnings("RedundantThrows")
    @Test
    void withSecurityConfig() {
        //language=java
        rewriteRun(
          java(
                """
            import org.springframework.boot.autoconfigure.SpringBootApplication;
            
            @SpringBootApplication
            class Application {
            }
            """),
          java(
                """
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
            """
              import org.springframework.context.annotation.Configuration;
              import org.springframework.security.config.annotation.web.builders.HttpSecurity;
              import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
              
              @Configuration
              class SecurityConfig extends WebSecurityConfigurerAdapter {
                  @Override
                  protected void configure(HttpSecurity http) throws Exception {
                      http.headers().frameOptions().deny();
                  }
              }
              """
          )
        );
    }

    @SuppressWarnings("RedundantThrows")
    @Test
    void withoutSecurityConfig() {
        rewriteRun(
          java(
            //language=java
            """
              package org.openrewrite;
              
              import org.springframework.boot.autoconfigure.SpringBootApplication;
              
              @SpringBootApplication
              class Application {
              }
              """,
            spec -> spec.path("src/main/java/org/openrewrite/Application.java")
          ),
          java(
            null,
            //language=java
            """
              package org.openrewrite;
              
              import org.springframework.context.annotation.Configuration;
              import org.springframework.security.config.annotation.web.builders.HttpSecurity;
              import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
              
              @Configuration
              class SecurityConfig extends WebSecurityConfigurerAdapter {
                  @Override
                  protected void configure(HttpSecurity http) throws Exception {
                      http.headers().frameOptions().deny();
                  }
              }
              """,
            spec -> spec.path("src/main/java/org/openrewrite/SecurityConfig.java")
          )
        );
    }
}
