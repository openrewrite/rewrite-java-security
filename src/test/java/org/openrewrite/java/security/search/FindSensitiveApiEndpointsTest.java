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
package org.openrewrite.java.security.search;

import org.junit.jupiter.api.Test;
import org.openrewrite.DocumentExample;
import org.openrewrite.java.JavaParser;
import org.openrewrite.test.RecipeSpec;
import org.openrewrite.test.RewriteTest;
import org.openrewrite.test.TypeValidation;

import java.util.List;

import static org.openrewrite.java.Assertions.java;

public class FindSensitiveApiEndpointsTest implements RewriteTest {

    @Override
    public void defaults(RecipeSpec spec) {
        spec.parser(JavaParser.fromJavaVersion().classpath("faker", "spring-web", "reactor-core", "javaee-api"))
          .recipe(new FindSensitiveApiEndpoints(List.of("birthdate"), true));
    }

    @DocumentExample
    @Test
    void webmvc() {
        rewriteRun(
          //language=java
          java(
            """
              import com.arakelian.faker.model.Person;
              import com.arakelian.faker.service.RandomPerson;
              import org.springframework.web.bind.annotation.GetMapping;
              import org.springframework.web.bind.annotation.RequestMapping;
                            
              @RequestMapping("/person")
              class PersonController {
                  @GetMapping("/random")
                  public Person randomPerson() {
                      return RandomPerson.get().next();
                  }
              }
              """,
            """
              import com.arakelian.faker.model.Person;
              import com.arakelian.faker.service.RandomPerson;
              import org.springframework.web.bind.annotation.GetMapping;
              import org.springframework.web.bind.annotation.RequestMapping;
                            
              @RequestMapping("/person")
              class PersonController {
                  @GetMapping("/random")
                  public /*~~(com.arakelian.faker.model.Person#getBirthdate)~~>*/Person randomPerson() {
                      return RandomPerson.get().next();
                  }
              }
              """
          )
        );
    }

    @Test
    void webflux() {
        rewriteRun(
          spec -> spec.typeValidationOptions(TypeValidation.none()),
          //language=java
          java(
            """
              import com.arakelian.faker.model.Person;
              import com.arakelian.faker.service.RandomPerson;
              import org.springframework.web.bind.annotation.GetMapping;
              import org.springframework.web.bind.annotation.RequestMapping;
              import reactor.core.publisher.Mono;
                            
              @RequestMapping("/person")
              class PersonController {
                  @GetMapping("/random")
                  public Mono<Person> randomPersonMono() {
                      return Mono.just(RandomPerson.get().next());
                  }
              }
              """,
            """
              import com.arakelian.faker.model.Person;
              import com.arakelian.faker.service.RandomPerson;
              import org.springframework.web.bind.annotation.GetMapping;
              import org.springframework.web.bind.annotation.RequestMapping;
              import reactor.core.publisher.Mono;
                            
              @RequestMapping("/person")
              class PersonController {
                  @GetMapping("/random")
                  public /*~~(com.arakelian.faker.model.Person#getBirthdate)~~>*/Mono<Person> randomPersonMono() {
                      return Mono.just(RandomPerson.get().next());
                  }
              }
              """
          )
        );
    }

    @Test
    void jaxrs() {
        rewriteRun(
          //language=java
          java(
            """
              import com.arakelian.faker.model.Person;
              import com.arakelian.faker.service.RandomPerson;
                            
              import javax.ws.rs.GET;
              import javax.ws.rs.Path;
                            
              @Path("/person")
              class PersonController {
                  @GET
                  @Path("/random")
                  public Person randomPerson() {
                      return RandomPerson.get().next();
                  }
              }
              """,
            """
              import com.arakelian.faker.model.Person;
              import com.arakelian.faker.service.RandomPerson;
                            
              import javax.ws.rs.GET;
              import javax.ws.rs.Path;
                            
              @Path("/person")
              class PersonController {
                  @GET
                  @Path("/random")
                  public /*~~(com.arakelian.faker.model.Person#getBirthdate)~~>*/Person randomPerson() {
                      return RandomPerson.get().next();
                  }
              }
              """
          )
        );
    }

    @Test
    void transitive() {
        //language=java
        rewriteRun(
          java(
            """
              import com.arakelian.faker.model.Person;
              public interface Account {
                  Person getOwner();
              }
              """
          ),
          java(
            """
              import com.arakelian.faker.model.Person;
              import com.arakelian.faker.service.RandomPerson;
                            
              import javax.ws.rs.GET;
              import javax.ws.rs.Path;
                            
              @Path("/person")
              class PersonController {
                  @GET
                  @Path("/random")
                  public Account randomPerson() {
                      return null;
                  }
              }
              """,
            """
              import com.arakelian.faker.model.Person;
              import com.arakelian.faker.service.RandomPerson;
                            
              import javax.ws.rs.GET;
              import javax.ws.rs.Path;
                            
              @Path("/person")
              class PersonController {
                  @GET
                  @Path("/random")
                  public /*~~(Account#getOwner->com.arakelian.faker.model.Person#getBirthdate)~~>*/Account randomPerson() {
                      return null;
                  }
              }
              """
          )
        );
    }
}
