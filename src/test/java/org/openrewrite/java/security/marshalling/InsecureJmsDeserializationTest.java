/*
 * Copyright 2023 the original author or authors.
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

import org.junit.jupiter.api.Test;
import org.openrewrite.java.JavaParser;
import org.openrewrite.test.RecipeSpec;
import org.openrewrite.test.RewriteTest;

import static org.openrewrite.java.Assertions.java;

public class InsecureJmsDeserializationTest implements RewriteTest {

    @Override
    public void defaults(RecipeSpec spec) {
        spec.recipe(new InsecureJmsDeserialization())
          .parser(JavaParser.fromJavaVersion().classpath("javaee-api"));
    }

    @Test
    void insecureDeserialization() {
        rewriteRun(
          //language=java
          java(
            """
              import javax.jms.*;
              class Test implements MessageListener {
                  public void onMessage(Message message) {
                      ObjectMessage objectMessage = (ObjectMessage) message;
                      try {
                          Object object = objectMessage.getObject();
                      } catch (JMSException e) {
                          e.printStackTrace();
                      }
                  }
              }
              """,
            """
              import javax.jms.*;
              class Test implements MessageListener {
                  public void onMessage(Message message) {
                      ObjectMessage objectMessage = (ObjectMessage) message;
                      try {
                          Object object = /*~~>*/objectMessage.getObject();
                      } catch (JMSException e) {
                          e.printStackTrace();
                      }
                  }
              }
              """
          )
        );
    }
}