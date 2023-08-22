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

import org.openrewrite.java.tree.J;
import org.openrewrite.java.tree.Statement;

import java.util.Set;
import java.util.TreeSet;

public class DBFInsertPropertyStatementVisitor<P> extends XmlFactoryInsertVisitor<P> {

    private final J.Block scope;
    private final StringBuilder propertyTemplate = new StringBuilder();

    private final Set<String> imports = new TreeSet<>();
    private final String dbfVariableName;
    private final boolean disallowDoctypes;

    private final boolean disallowGeneralEntities;
    private final boolean disallowParameterEntities;
    private final boolean disallowLoadExternalDTD;

    public DBFInsertPropertyStatementVisitor(
            J.Block scope,
            String dbfVariableName,
            boolean accIsEmpty,
            boolean needsDisallowDoctypesTrue,
            boolean needsDisableGeneralEntities,
            boolean needsDisableParameterEntities,
            boolean needsLoadExternalDTD
    ) {
        super(
                scope,
                dbfVariableName,
                DocumentBuilderFactoryFixVisitor.DBF_NEW_INSTANCE,
                DocumentBuilderFactoryFixVisitor.DBF_PARSER_SET_FEATURE
        );

        this.scope = scope;
        this.dbfVariableName = dbfVariableName;

        if (needsDisallowDoctypesTrue && accIsEmpty) {
            disallowDoctypes = true;
            disallowGeneralEntities = false;
            disallowParameterEntities = false;
            disallowLoadExternalDTD = false;
        } else if (needsDisallowDoctypesTrue && !accIsEmpty) {
            disallowDoctypes = true;
            disallowGeneralEntities = needsDisableGeneralEntities;
            disallowParameterEntities = needsDisableParameterEntities;
            disallowLoadExternalDTD = needsLoadExternalDTD;

        } else if (!needsDisallowDoctypesTrue && !accIsEmpty) {
            disallowDoctypes = false;
            disallowGeneralEntities = false;
            disallowLoadExternalDTD = false;
            disallowParameterEntities = false;
        } else {
            disallowDoctypes = false;
            disallowGeneralEntities = false;
            disallowLoadExternalDTD = false;
            disallowParameterEntities = false;
        }
    }

    private void generateSetFeature(boolean disallowDoctypes) {
        if (disallowDoctypes && !disallowGeneralEntities && !disallowParameterEntities && !disallowLoadExternalDTD) {
            imports.add("javax.xml.parsers.ParserConfigurationException");
            propertyTemplate.append(
                    "String FEATURE = \"http://apache.org/xml/features/disallow-doctype-decl\";\n" +
                    "try {\n" +
                    "   " + dbfVariableName + ".setFeature(FEATURE, true);\n" +
                    "} catch (ParserConfigurationException e) {\n" +
                    "    throw new IllegalStateException(\"ParserConfigurationException was thrown. The feature '\"\n" +
                    "            + FEATURE + \"' is not supported by your XML processor.\", e);\n" +
                    "}\n"
            );
        } else if (disallowDoctypes && disallowGeneralEntities && disallowParameterEntities && disallowLoadExternalDTD) {
            imports.add("javax.xml.parsers.ParserConfigurationException");
            propertyTemplate.append(
                    "String FEATURE = null;\n" +
                    "try {\n" +
                    "   FEATURE = \"http://xml.org/sax/features/external-parameter-entities\";\n" +
                    "   " + dbfVariableName + ".setFeature(FEATURE, false);\n" +
                    "\n" +
                    "   FEATURE = \"http://apache.org/xml/features/nonvalidating/load-external-dtd\";\n" +
                    "   " + dbfVariableName + ".setFeature(FEATURE, false);\n" +
                    "\n" +
                    "   FEATURE = \"http://xml.org/sax/features/external-general-entities\";\n" +
                    "   " + dbfVariableName + ".setFeature(FEATURE, false);\n" +
                    "\n" +
                    "   " + dbfVariableName + ".setXIncludeAware(false);\n" +
                    "   " + dbfVariableName + ".setExpandEntityReferences(false);\n" +
                    "\n" +
                    "   " + dbfVariableName + ".setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);\n" +
                    "} catch (ParserConfigurationException e) {\n" +
                    "    throw new IllegalStateException(\"ParserConfigurationException was thrown. The feature '\"\n" +
                    "            + FEATURE + \"' is not supported by your XML processor.\", e);\n" +
                    "}\n"
            );

        }
    }

    @Override
    public J.Block visitBlock(J.Block block, P ctx) {
        J.Block b = super.visitBlock(block, ctx);
        if (b.isScope(scope)) {
            Statement beforeStatement = getInsertStatement(b);
            generateSetFeature(disallowDoctypes);
            return updateBlock(
                    b,
                    beforeStatement,
                    imports
            );
        }
        return b;
    }
}
