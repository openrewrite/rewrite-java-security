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
package org.openrewrite.java.security.search.secret;

import org.openrewrite.ExecutionContext;

import java.util.Arrays;
import java.util.List;

class AwsSecretPredicateGroup implements SecretPredicateGroup {
    @Override
    public String getName() {
        return "AWS Access Key";
    }

    @Override
    public List<SecretPredicate<String, String, ExecutionContext>> secretPredicates() {
        return Arrays.asList(new SecretRegexPredicate(null, "AKIA[0-9A-Z]{16}"),
                new SecretRegexPredicate("aws.{0,20}?(key|pwd|pw|password|pass|token)", "^([0-9a-zA-Z/+]{40})$"));
    }
}
