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
package org.openrewrite.java.security;

import org.openrewrite.ExecutionContext;
import org.openrewrite.Recipe;
import org.openrewrite.Tree;
import org.openrewrite.internal.lang.Nullable;
import org.openrewrite.java.JavaIsoVisitor;
import org.openrewrite.java.tree.Comment;
import org.openrewrite.java.tree.J;
import org.openrewrite.java.tree.Space;

import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static java.util.Collections.emptySet;

public class FindTextDirectionChanges extends Recipe {

    private static final Set<?> EMPTY_SET = emptySet();
    public static final char LRE = '\u202A';
    public static final char RLE = '\u202B';
    public static final char LRO = '\u202D';
    public static final char RLO = '\u202E';
    public static final char LRI = '\u2066';
    public static final char RLI = '\u2067';
    public static final char FSI = '\u2068';
    public static final char PDF = '\u202C';
    public static final char PDI = '\u2069';
    public static final Set<Character> sneakyCodes = Stream.of(LRE, RLE, LRO, RLO, LRI, RLI, FSI, PDF, PDI)
            .collect(Collectors.toSet());
    public static final Map<Character, String> charToText = new HashMap<>();
    static {
        charToText.put(LRE, "LRE");
        charToText.put(RLE, "RLE");
        charToText.put(LRO, "LRO");
        charToText.put(RLO, "RLO");
        charToText.put(LRI, "LRI");
        charToText.put(RLI, "RLI");
        charToText.put(FSI, "FSI");
        charToText.put(PDF, "PDF");
        charToText.put(PDI, "PDI");
    }

    @Override
    public String getDisplayName() {
        return "Find text-direction changes";
    }

    @Override
    public String getDescription() {
        return "Finds unicode control characters which can change the direction text is displayed in. " +
                "These control characters can alter how source code is presented to a human reader without affecting its interpretation by tools like compilers. " +
                "So a malicious patch could pass code review while introducing vulnerabilities. " +
                "See: https://trojansource.codes/ \n" +
                "Note that text direction-changing unicode control characters aren't inherently malicious. " +
                "These characters can appear for legitimate reasons in code written in or dealing with right-to-left languages.";
    }

    @Override
    public Set<String> getTags() {
        return Collections.singleton("CVE-2021-42574");
    }

    @Override
    protected JavaIsoVisitor<ExecutionContext> getVisitor() {
        return new JavaIsoVisitor<ExecutionContext>() {

            @Override
            public @Nullable J visit(@Nullable Tree tree, ExecutionContext context) {
                J j = super.visit(tree, context);
                Object foundCodes = getCursor().pollMessage("FOUND_SNEAKY_CODES");
                if(j != null && foundCodes != null) {
                    //noinspection unchecked
                    j = j.withMarkers(j.getMarkers().searchResult("Found text-direction altering unicode control characters: " + String.join(",", (Set<String>)foundCodes)));
                }

                return j;
            }

            @Override
            public Space visitSpace(Space s, Space.Location loc, ExecutionContext context) {
                Set<String> foundCodes = null;
                if(containsSneakyCode(s.getWhitespace())) {
                    foundCodes = listSneakyCodes(s.getWhitespace());
                }
                if(containsSneakyCode(s.getComments(), Comment::printComment)) {
                    if(foundCodes == null) {
                        foundCodes = new HashSet<>();
                    }
                    foundCodes.addAll(listSneakyCodes(s.getComments(), Comment::printComment));
                }
                if(containsSneakyCode(s.getComments(), Comment::getSuffix)) {
                    if(foundCodes == null) {
                        foundCodes = new HashSet<>();
                    }
                    foundCodes.addAll(listSneakyCodes(s.getComments(), Comment::getSuffix));
                }
                if(foundCodes != null) {
                    getCursor().putMessage("FOUND_SNEAKY_CODES", foundCodes);
                }
                return s;
            }
        };
    }

    private static boolean containsSneakyCode(String s) {
        for (char c : s.toCharArray()) {
            if (sneakyCodes.contains(c)) {
                return true;
            }
        }
        return false;
    }

    private static <T> boolean containsSneakyCode(Collection<T> collection, Function<T, String> conversion) {
        return collection.stream().map(conversion).anyMatch(FindTextDirectionChanges::containsSneakyCode);
    }

    private static Set<String> listSneakyCodes(String s) {
        Set<String> foundCodes = new HashSet<>();
        for (char c : s.toCharArray()) {
            if (sneakyCodes.contains(c)) {
                if (foundCodes == EMPTY_SET) {
                    foundCodes = new HashSet<>();
                }
                foundCodes.add(charToText.get(c));
            }
        }
        return foundCodes;
    }

    private static <T> Set<String> listSneakyCodes(Collection<T> collection, Function<T, String> conversion) {
        return collection.stream()
                .map(conversion)
                .flatMap(suffix -> listSneakyCodes(suffix).stream())
                .collect(Collectors.toSet());
    }
}
