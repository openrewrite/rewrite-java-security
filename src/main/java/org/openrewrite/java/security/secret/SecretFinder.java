package org.openrewrite.java.security.secret;

import org.openrewrite.ExecutionContext;
import org.openrewrite.SourceFile;
import org.openrewrite.internal.ListUtils;
import org.openrewrite.internal.StringUtils;
import org.openrewrite.internal.lang.Nullable;
import org.openrewrite.java.JavaIsoVisitor;
import org.openrewrite.java.tree.J;
import org.openrewrite.java.tree.JavaType;
import org.openrewrite.java.tree.Space;
import org.openrewrite.java.tree.TextComment;
import org.openrewrite.marker.SearchResult;
import org.openrewrite.yaml.YamlIsoVisitor;
import org.openrewrite.yaml.tree.Yaml;

import java.util.function.BiPredicate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.openrewrite.Tree.randomId;

public class SecretFinder {
    private final String name;
    @Nullable
    private final Pattern keyPattern;
    @Nullable
    private final Pattern valuePattern;
    private final BiPredicate<String, ExecutionContext> keyPredicate;
    private final BiPredicate<String, ExecutionContext> valuePredicate;
    private final FindJavaTextVisitor findJavaTextVisitor;
    private final FindYamlSecretVisitor findYamlSecretVisitor;

    private SecretFinder(String name, @Nullable Pattern keyPattern, @Nullable Pattern valuePattern, BiPredicate<String, ExecutionContext> keyPredicate, BiPredicate<String, ExecutionContext> valuePredicate) {
        this.name = name;
        this.keyPattern = keyPattern;
        this.valuePattern = valuePattern;
        this.keyPredicate = keyPredicate;
        this.valuePredicate = valuePredicate;
        findJavaTextVisitor = new FindJavaTextVisitor();
        findYamlSecretVisitor = new FindYamlSecretVisitor();
    }

    public static Builder builder(String name) {
        return new Builder(name);
    }

    public SourceFile findSecrets(SourceFile sourceFile, ExecutionContext ctx) {
        if (findJavaTextVisitor.isValid()) {
            sourceFile = (SourceFile) findJavaTextVisitor.visitNonNull(sourceFile, ctx);
        }
        if (findYamlSecretVisitor.isValid()) {
            sourceFile = (SourceFile) findYamlSecretVisitor.visitNonNull(sourceFile, ctx);
        }
        return sourceFile;
    }

    class FindYamlSecretVisitor extends YamlIsoVisitor<ExecutionContext> {
        boolean isValid() {
            return !(valuePattern == null && keyPattern == null);
        }

        @Override
        public Yaml.Sequence.Entry visitSequenceEntry(Yaml.Sequence.Entry entry, ExecutionContext executionContext) {
            Yaml.Sequence.Entry ent = super.visitSequenceEntry(entry, executionContext);
            if (ent.getBlock() instanceof Yaml.Scalar) {
                Yaml.Scalar scalar = (Yaml.Scalar) ent.getBlock();
                if (valuePattern != null) {
                    Matcher valueMatcher = valuePattern.matcher(scalar.getValue());
                    if (valueMatcher.find()) {
                        if (valuePredicate.test(valueMatcher.group(), executionContext)) {
                            ent = SearchResult.found(ent, name);
                        }
                    }
                }
            }
            return ent;
        }

        @Override
        public Yaml.Mapping.Entry visitMappingEntry(Yaml.Mapping.Entry entry, ExecutionContext executionContext) {
            Yaml.Mapping.Entry ent = super.visitMappingEntry(entry, executionContext);
            if (ent.getKey() instanceof Yaml.Scalar && ent.getValue() instanceof Yaml.Scalar) {
                Yaml.Scalar key = (Yaml.Scalar) ent.getKey();
                Yaml.Scalar val = (Yaml.Scalar) ent.getValue();
                String foundKey = null;
                String foundValue = null;
                if (keyPattern != null) {
                    Matcher keyMatcher = keyPattern.matcher(key.getValue());
                    if (keyMatcher.find()) {
                        foundKey = keyMatcher.group();
                        if (!keyPredicate.test(foundKey, executionContext)) {
                            foundKey = null;
                        }
                    }
                }
                if (valuePattern != null) {
                    Matcher valueMatcher = valuePattern.matcher(val.getValue());
                    if (valueMatcher.find()) {
                        foundValue = valueMatcher.group();
                        if (!valuePredicate.test(foundValue, executionContext)) {
                            foundValue = null;
                        }
                    }
                }
                if (keyPattern != null && valuePattern != null) {
                    if (foundKey != null && foundValue != null) {
                        ent = SearchResult.found(ent, name);
                    }
                } else if (keyPattern != null && foundKey != null) {
                    ent = SearchResult.found(ent, name);
                } else if (valuePattern != null && foundValue != null) {
                    ent = SearchResult.found(ent, name);
                }
            }
            return ent;
        }
    }

    class FindJavaTextVisitor extends JavaIsoVisitor<ExecutionContext> {
        private boolean isValid() {
            return valuePattern != null;
        }

        @Nullable
        private String isSecret(@Nullable String literalValue, ExecutionContext ctx) {
            if (literalValue != null && valuePattern != null) {
                Matcher matcher = valuePattern.matcher(literalValue);
                if (matcher.find()) {
                    String val = matcher.group();
                    if (valuePredicate.test(val, ctx)) {
                        return name;
                    }
                }
            }
            return null;
        }

        @Override
        public Space visitSpace(Space space, Space.Location loc, ExecutionContext ctx) {
            return space.withComments(ListUtils.map(space.getComments(), comment -> {
                if (comment instanceof TextComment) {
                    String secretType = isSecret(((TextComment) comment).getText(), ctx);
                    if (secretType != null) {
                        return comment.withMarkers(comment.getMarkers().
                                computeByType(new SearchResult(randomId(), secretType), (s1, s2) -> s1 == null ? s2 : s1));
                    }
                }
                return comment;
            }));
        }

        @Override
        public J.Literal visitLiteral(J.Literal literal, ExecutionContext ctx) {
            if (literal.getType() == JavaType.Primitive.Null) {
                return literal;
            }
            if (literal.getValue() != null) {
                String secretType = isSecret(literal.getValue().toString(), ctx);
                if (secretType != null) {
                    return SearchResult.found(literal, secretType);
                }
            }
            return literal;
        }
    }

    public static class Builder {
        private final String name;
        private Pattern keyPattern = null;
        private Pattern valuePattern = null;
        private BiPredicate<String, ExecutionContext> keyVerifier = (s, ctx) -> true;
        private BiPredicate<String, ExecutionContext> valueVerifier = (s, ctx) -> true;

        Builder(String name) {
            this.name = name;
        }

        SecretFinder build() {
            return new SecretFinder(name, keyPattern, valuePattern, keyVerifier, valueVerifier);
        }

        Builder keyPattern(String keyPattern) {
            if (!StringUtils.isNullOrEmpty(keyPattern)) {
                this.keyPattern = Pattern.compile(keyPattern);
            }
            return this;
        }

        Builder valuePattern(String valuePattern) {
            if (!StringUtils.isNullOrEmpty(valuePattern)) {
                this.valuePattern = Pattern.compile(valuePattern);
            }
            return this;
        }

        Builder keyVerifier(BiPredicate<String, ExecutionContext> keyVerifier) {
            this.keyVerifier = keyVerifier;
            return this;
        }

        Builder valueVerifier(BiPredicate<String, ExecutionContext> valueVerifier) {
            this.valueVerifier = valueVerifier;
            return this;
        }
    }
}
