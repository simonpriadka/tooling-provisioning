/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.qa.tooling.sbom.result;

import java.util.List;

/**
 * The result of a single SBOM check: a (possibly empty) list of issue strings.
 * An empty list means the check passed.
 */
public record CheckResult(List<String> issues) {
    /** @return {@code true} when no issues were found. */
    public boolean passed() { return issues.isEmpty(); }
}
