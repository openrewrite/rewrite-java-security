/*
 * Copyright 2024 the original author or authors.
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
import org.openrewrite.java.JavaParser;
import org.openrewrite.test.RecipeSpec;
import org.openrewrite.test.RewriteTest;

import static org.openrewrite.java.Assertions.java;
import static org.openrewrite.xml.Assertions.xml;

/**
 * See the <a href="https://blog.gypsyengineer.com/en/security/detecting-dangerous-spring-exporters-with-codeql.html">
 * blog post</a> on this vulnerability.
 */
@SuppressWarnings("deprecation")
public class InsecureSpringServiceExporterTest implements RewriteTest {

    @Override
    public void defaults(RecipeSpec spec) {
        spec
          .recipe(new InsecureSpringServiceExporter())
          .parser(JavaParser.fromJavaVersion()
            .classpath("spring-beans", "spring-context", "spring-web"));
    }

    @Test
    void javaBean() {
        rewriteRun(
          //language=java
          java(
            """
              import org.springframework.context.annotation.Bean;
              import org.springframework.context.annotation.Configuration;
              import org.springframework.remoting.httpinvoker.HttpInvokerServiceExporter;
              
              @Configuration
              class Server {
                  @Bean(name = "/account")
                  HttpInvokerServiceExporter accountService() {
                      HttpInvokerServiceExporter exporter = new HttpInvokerServiceExporter();
                      exporter.setService(new AccountServiceImpl());
                      exporter.setServiceInterface(AccountService.class);
                      return exporter;
                  }
              
              }
              
              class AccountServiceImpl implements AccountService {
                  @Override
                  public String echo(String data) {
                      return data;
                  }
              }
              
              interface AccountService {
                  String echo(String data);
              }
              """,
            """
              import org.springframework.context.annotation.Bean;
              import org.springframework.context.annotation.Configuration;
              import org.springframework.remoting.httpinvoker.HttpInvokerServiceExporter;
              
              @Configuration
              class Server {
                  @Bean(name = "/account")
                  /*~~>*/HttpInvokerServiceExporter accountService() {
                      HttpInvokerServiceExporter exporter = new HttpInvokerServiceExporter();
                      exporter.setService(new AccountServiceImpl());
                      exporter.setServiceInterface(AccountService.class);
                      return exporter;
                  }
              
              }
              
              class AccountServiceImpl implements AccountService {
                  @Override
                  public String echo(String data) {
                      return data;
                  }
              }
              
              interface AccountService {
                  String echo(String data);
              }
              """
          )
        );
    }

    @Test
    void xmlBean() {
        rewriteRun(
          //language=xml
          xml(
            """
              <beans>
                  <bean id="accountService" class="org.openrewrite.AccountServiceImpl"/>
                  <bean name="/account" class="org.springframework.remoting.httpinvoker.HttpInvokerServiceExporter">
                      <property name="service" ref="accountService"/>
                      <property name="serviceInterface" value="org.openrewrite.AccountService"/>
                  </bean>
              </beans>
              """,
            """
              <beans>
                  <bean id="accountService" class="org.openrewrite.AccountServiceImpl"/>
                  <!--~~>--><bean name="/account" class="org.springframework.remoting.httpinvoker.HttpInvokerServiceExporter">
                      <property name="service" ref="accountService"/>
                      <property name="serviceInterface" value="org.openrewrite.AccountService"/>
                  </bean>
              </beans>
              """
          )
        );
    }
}
