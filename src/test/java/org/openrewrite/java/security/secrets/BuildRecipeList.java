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
package org.openrewrite.java.security.secrets;

import org.openrewrite.Recipe;
import org.openrewrite.config.Environment;

import java.util.Comparator;

public class BuildRecipeList {
    public static void main(String[] args) {
        for (Recipe recipe : Environment.builder()
          .scanRuntimeClasspath("org.openrewrite.java.security.secrets")
          .build()
          .listRecipes()
          .stream()
          .filter(r -> r.getName().startsWith("org.openrewrite.java.security.secrets.") &&
            !r.getName().endsWith(".FindSecrets"))
          .sorted(Comparator.comparing(Recipe::getName))
          .toList()) {
            System.out.println("  - " + recipe.getName());
        }
    }
}
