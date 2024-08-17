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
package org.openrewrite.java.security.xml;

import fj.data.Option;
import org.openrewrite.Cursor;
import org.openrewrite.ExecutionContext;
import org.openrewrite.Preconditions;
import org.openrewrite.TreeVisitor;
import org.openrewrite.analysis.InvocationMatcher;
import org.openrewrite.analysis.constantfold.ConstantFold;
import org.openrewrite.analysis.dataflow.DataFlowNode;
import org.openrewrite.analysis.dataflow.DataFlowSpec;
import org.openrewrite.analysis.dataflow.Dataflow;
import org.openrewrite.analysis.trait.expr.Expr;
import org.openrewrite.analysis.trait.expr.Literal;
import org.openrewrite.analysis.trait.expr.VarAccess;
import org.openrewrite.analysis.trait.variable.Variable;
import org.openrewrite.java.MethodMatcher;
import org.openrewrite.java.search.UsesType;
import org.openrewrite.java.tree.Expression;
import org.openrewrite.java.tree.J;

import java.util.Arrays;
import java.util.List;

public class DocumentBuilderFactoryFixVisitor<P> extends XmlFactoryVisitor<P> {

    static final InvocationMatcher DBF_NEW_INSTANCE = InvocationMatcher.fromMethodMatcher(new MethodMatcher("javax.xml.parsers.DocumentBuilderFactory newInstance*()"));
    static final InvocationMatcher DBF_PARSER_SET_FEATURE = InvocationMatcher.fromMethodMatcher(new MethodMatcher("javax.xml.parsers.DocumentBuilderFactory setFeature(java.lang.String, boolean)"));
    static final InvocationMatcher DBF_PARSER_SET_X_INCLUDE_AWARE = InvocationMatcher.fromMethodMatcher(new MethodMatcher("javax.xml.parsers.DocumentBuilderFactory setXIncludeAware(boolean)"));
    static final InvocationMatcher DBF_PARSER_SET_EXPAND_ENTITY_REFERENCES = InvocationMatcher.fromMethodMatcher(new MethodMatcher("javax.xml.parsers.DocumentBuilderFactory setExpandEntityReferences(boolean)"));
    private static final String DBF_FQN = "javax.xml.parsers.DocumentBuilderFactory";
    private static final String DISALLOW_DOCTYPE_DECLARATIONS = "http://apache.org/xml/features/disallow-doctype-decl";
    private static final String DISABLE_GENERAL_ENTITIES = "http://xml.org/sax/features/external-general-entities";
    private static final String DISABLE_PARAMETER_ENTITIES = "http://xml.org/sax/features/external-parameter-entities";
    private static final String LOAD_EXTERNAL_DTD = "http://apache.org/xml/features/nonvalidating/load-external-dtd";

    private static final List<String> DISALLOWED_DTD_FEATURES = Arrays.asList(
            DISALLOW_DOCTYPE_DECLARATIONS,
            DISABLE_GENERAL_ENTITIES,
            DISABLE_PARAMETER_ENTITIES,
            LOAD_EXTERNAL_DTD
    );

    private static final String SET_X_INCLUDE_AWARE_PROPERTY_NAME = "setXIncludeAware";
    private static final String SET_EXPAND_ENTITY_REFERENCES_PROPERTY_NAME = "setExpandEntityReferences";
    private static final String FEATURE_SECURE_PROCESSING_PROPERTY_NAME = "FEATURE_SECURE_PROCESSING";
    private static final String DBF_INITIALIZATION_METHOD = "dbf-initialization-method";
    private static final String DBF_VARIABLE_NAME = "dbf-variable-name";

    DocumentBuilderFactoryFixVisitor(ExternalDTDAccumulator acc) {
        super(
                DBF_NEW_INSTANCE,
                DBF_FQN,
                DBF_INITIALIZATION_METHOD,
                DBF_VARIABLE_NAME,
                acc
        );
    }

    private static final class DBFArgumentsSpec extends DataFlowSpec {
        @Override
        public boolean isSource(DataFlowNode srcNode) {
            return findFeatureName(srcNode).isSome();
        }

        @Override
        public boolean isSink(DataFlowNode sinkNode) {
            return DBF_PARSER_SET_FEATURE.advanced().isFirstParameter(sinkNode.getCursor());
        }
    }

    private static Option<String> findFeatureName(DataFlowNode node) {
        return ConstantFold
                .findConstantLiteralValue(node, String.class)
                .filter(DISALLOWED_DTD_FEATURES::contains);
    }

    @Override
    public Expression visitExpression(Expression expression, P p) {
        Dataflow.startingAt(getCursor()).findSinks(new DBFArgumentsSpec()).forEach(sink -> {
            Option<String> featureName = DataFlowNode.of(getCursor()).bind(n -> findFeatureName(n));
            sink.getSinkCursors().forEach(sinkCursor ->
                addMessage(featureName.some(), sinkCursor.dropParentUntil(J.Block.class::isInstance)));
        });
        return super.visitExpression(expression, p);
    }

    @Override
    public J.MethodInvocation visitMethodInvocation(J.MethodInvocation method, P ctx) {
        J.MethodInvocation mi = super.visitMethodInvocation(method, ctx);
        if (DBF_PARSER_SET_X_INCLUDE_AWARE.matches(mi)) {
            addMessage(SET_X_INCLUDE_AWARE_PROPERTY_NAME);
        } else if (DBF_PARSER_SET_EXPAND_ENTITY_REFERENCES.matches(mi)) {
            addMessage(SET_EXPAND_ENTITY_REFERENCES_PROPERTY_NAME);
        }
        return mi;
    }

    @Override
    public J.Block visitBlock(J.Block block, P p) {
        if (J.Block.isInitBlock(getCursor())) {
            addMessage(DBF_INITIALIZATION_METHOD);
        }
        return super.visitBlock(block, p);
    }

    @Override
    public J.ClassDeclaration visitClassDeclaration(J.ClassDeclaration classDecl, P ctx) {
        J.ClassDeclaration cd = super.visitClassDeclaration(classDecl, ctx);
        for (int i = 1; i <= getCount(); i++) {
            Cursor initializationCursor = getCursor().getMessage(DBF_INITIALIZATION_METHOD + i);
            XmlFactoryVariable dbfFactoryVariable = getCursor().getMessage(DBF_VARIABLE_NAME + i);

            Cursor disallowedDTDTrueCursor = getCursor().getMessage(DISALLOW_DOCTYPE_DECLARATIONS + i);
            Cursor generalEntitiesDisabledCursor = getCursor().getMessage(DISABLE_GENERAL_ENTITIES + i);
            Cursor parameterEntitiesDisabledCursor = getCursor().getMessage(DISABLE_PARAMETER_ENTITIES + i);
            Cursor loadExternalDTDCursor = getCursor().getMessage(LOAD_EXTERNAL_DTD + i);
            Cursor setXIncludeAwareCursor = getCursor().getMessage(SET_X_INCLUDE_AWARE_PROPERTY_NAME + i);
            Cursor setExpandEntityReferencesCursor = getCursor().getMessage(SET_EXPAND_ENTITY_REFERENCES_PROPERTY_NAME + i);

            Cursor setPropertyBlockCursor = disallowedDTDTrueCursor == null ? initializationCursor : disallowedDTDTrueCursor;
            if (setPropertyBlockCursor != null && dbfFactoryVariable != null) {
                doAfterVisit(new DBFInsertPropertyStatementVisitor<>(
                        setPropertyBlockCursor.getValue(),
                        dbfFactoryVariable,
                        getAcc().getExternalDTDs().isEmpty(),
                        disallowedDTDTrueCursor == null,
                        generalEntitiesDisabledCursor == null,
                        parameterEntitiesDisabledCursor == null,
                        loadExternalDTDCursor == null,
                        setXIncludeAwareCursor == null,
                        setExpandEntityReferencesCursor == null));
            }
        }
        return cd;
    }

    public static TreeVisitor<?, ExecutionContext> create(ExternalDTDAccumulator acc) {
        return Preconditions.check(new UsesType<>(DBF_FQN, true), new DocumentBuilderFactoryFixVisitor<>(acc));
    }
}
