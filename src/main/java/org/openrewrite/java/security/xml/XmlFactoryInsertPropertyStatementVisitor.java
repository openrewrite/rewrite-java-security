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
package org.openrewrite.java.security.xml;

import org.openrewrite.Cursor;
import org.openrewrite.java.JavaIsoVisitor;
import org.openrewrite.java.JavaTemplate;
import org.openrewrite.java.VariableNameUtils;
import org.openrewrite.java.tree.J;
import org.openrewrite.java.tree.JavaCoordinates;
import org.openrewrite.java.tree.Statement;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

class XmlFactoryInsertPropertyStatementVisitor<P> extends JavaIsoVisitor<P> {
    private final J.Block scope;
    private final StringBuilder propertyTemplate = new StringBuilder();
    private final ExternalDTDAccumulator acc;

    private final boolean generateAllowList;
    private final String xmlFactoryVariableName;

    public XmlFactoryInsertPropertyStatementVisitor(
            J.Block scope,
            String factoryVariableName,
            boolean needsExternalEntitiesDisabled,
            boolean needsSupportDTDFalse,
            boolean accIsEmpty,
            boolean needsSupportDTDTrue,
            boolean needsResolverMethod,
            ExternalDTDAccumulator acc
    ) {
        this.scope = scope;
        this.acc = acc;
        this.xmlFactoryVariableName = factoryVariableName;

        if (needsExternalEntitiesDisabled) {
            propertyTemplate.append(xmlFactoryVariableName).append(".setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);");
        }
        if (needsSupportDTDFalse && accIsEmpty) {
            if (needsSupportDTDTrue) {
                propertyTemplate.append(xmlFactoryVariableName).append(".setProperty(XMLInputFactory.SUPPORT_DTD, false);");
            }
        }
        if (needsSupportDTDFalse && !accIsEmpty) {
            if (needsResolverMethod && needsSupportDTDTrue) {
                propertyTemplate.append(xmlFactoryVariableName).append(".setProperty(XMLInputFactory.SUPPORT_DTD, true);");
            }
            this.generateAllowList = needsResolverMethod;
        } else if (!needsSupportDTDTrue && !accIsEmpty) {
            this.generateAllowList = needsResolverMethod;
        } else {
            this.generateAllowList = false;
        }
    }

    private Set<String> addAllowList(boolean generateAllowList) {
        Set<String> imports = new HashSet<>();
        if (acc.getExternalDTDs().isEmpty() || !generateAllowList) {
            return Collections.emptySet();
        }

        String newAllowListVariableName = VariableNameUtils.generateVariableName(
                "allowList",
                getCursor(),
                VariableNameUtils.GenerationStrategy.INCREMENT_NUMBER
        );
        imports.add("java.util.Collection");
        imports.add("javax.xml.stream.XMLStreamException");

        if (acc.getExternalDTDs().size() > 1) {
            imports.add("java.util.Arrays");
            propertyTemplate.append(
                    "Collection<String>" + newAllowListVariableName + " = Arrays.asList(\n"
            );
        } else {
            imports.add("java.util.Collections");
            propertyTemplate.append(
                    "Collection<String>" + newAllowListVariableName + " = Collections.singleton(\n"
            );
        }

        String allowListContent = acc.getExternalDTDs().stream().map(dtd -> '"' + dtd + '"').collect(Collectors.joining(
                ",\n\t",
                "\t",
                ""
        ));
        propertyTemplate.append(allowListContent).append("\n);\n");
        propertyTemplate.append(xmlFactoryVariableName).append(
                ".setXMLResolver((publicID, systemID, baseURI, namespace) -> {\n" +
                        "   if (" + newAllowListVariableName + ".contains(systemID)){\n" +
                        "       // returning null will cause the parser to resolve the entity\n" +
                        "       return null;\n" +
                        "   }\n" +
                        "   throw new XMLStreamException(\"Loading of DTD was blocked to prevent XXE: \" + systemID);\n" +
                        "});"
        );
        return imports;
    }

    @Override
    public J.Block visitBlock(J.Block block, P ctx) {
        J.Block b = super.visitBlock(block, ctx);
        Statement beforeStatement = null;
        if (b.isScope(scope)) {
            for (int i = b.getStatements().size() - 2; i > -1; i--) {
                Statement st = b.getStatements().get(i);
                Statement stBefore = b.getStatements().get(i + 1);
                if (st instanceof J.MethodInvocation) {
                    J.MethodInvocation m = (J.MethodInvocation) st;
                    if (XmlInputFactoryFixVisitor.XML_PARSER_FACTORY_INSTANCE.matches(m) || XmlInputFactoryFixVisitor.XML_PARSER_FACTORY_SET_PROPERTY.matches(m)) {
                        beforeStatement = stBefore;
                    }
                } else if (st instanceof J.VariableDeclarations) {
                    J.VariableDeclarations vd = (J.VariableDeclarations) st;
                    if (vd.getVariables().get(0).getInitializer() instanceof J.MethodInvocation) {
                        J.MethodInvocation m = (J.MethodInvocation) vd.getVariables().get(0).getInitializer();
                        if (m != null && XmlInputFactoryFixVisitor.XML_PARSER_FACTORY_INSTANCE.matches(m)) {
                            beforeStatement = stBefore;
                        }
                    }
                }
            }

            Set<String> imports = addAllowList(generateAllowList);

            if (getCursor().getParent() != null && getCursor().getParent().getValue() instanceof J.ClassDeclaration) {
                propertyTemplate.insert(0, "{\n").append("}");
            }
            JavaCoordinates insertCoordinates = beforeStatement != null ?
                    beforeStatement.getCoordinates().before() :
                    b.getCoordinates().lastStatement();
            b = JavaTemplate
                    .builder(propertyTemplate.toString())
                    .imports(imports.toArray(new String[0]))
                    .contextSensitive()
                    .build()
                    .apply(new Cursor(getCursor().getParent(), b), insertCoordinates);
            if (b != block) {
                imports.forEach(this::maybeAddImport);
            }
        }
        return b;
    }
}
