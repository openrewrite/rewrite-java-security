package org.openrewrite.java.security;

import org.openrewrite.Recipe;

public class ZipSlip extends Recipe {
    @Override
    public String getDisplayName() {
        return "Zip Slip";
    }
}
