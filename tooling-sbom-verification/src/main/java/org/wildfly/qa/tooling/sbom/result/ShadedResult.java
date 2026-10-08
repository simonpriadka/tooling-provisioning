/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.qa.tooling.sbom.result;

import java.util.List;
import java.util.Map;

/**
 * Groups shaded/POM-derived artifacts by parent purl.
 *
 * <p>Key: parent purl (e.g. {@code pkg:maven/org.bouncycastle/bcprov-jdk18on@1.78.1}),
 * or the literal string {@code "(no parent)"} for orphans.<br>
 * Value: sorted list of child purls — POM-derived artifacts bundled inside that parent JAR.</p>
 *
 * <p>{@link #totalArtifacts()} is derived from the map and is always consistent.</p>
 */
public record ShadedResult(Map<String, List<String>> byParentPurl) {

    /** @return total number of shaded child artifacts across all parent groups. */
    public int totalArtifacts() {
        return byParentPurl.values().stream().mapToInt(List::size).sum();
    }
}
