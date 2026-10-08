/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.qa.tooling.sbom.component;

/**
 * Classification of a CycloneDX SBOM component for installation verification purposes.
 */
public enum ComponentKind {
    /** Sub-artifact declared in a parent POM; never installed as a standalone file. */
    POM_DERIVED,
    /** Installed as a native {@code .so}/{@code .dll} inside a module {@code lib/} directory. */
    NATIVE_LIB,
    /** A regular JAR installed on disk. */
    REGULAR_JAR
}
