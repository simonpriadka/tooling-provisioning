/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.qa.tooling.sbom.result;

import java.util.Collections;

/**
 * The combined result of a single {@link org.wildfly.sbom.SbomChecker#check} invocation.
 *
 * <p>Call {@link #passed()} to determine overall success, or inspect the
 * individual {@link CheckResult} accessors for fine-grained details.</p>
 */
public final class SbomCheckResult {

    private final CheckResult sbomVsDisk;
    private final CheckResult diskVsSbom;
    private final CheckResult sbomVsManifest;
    /** {@code true} when {@link org.wildfly.sbom.SbomChecker#check} found no {@code sbom.cdx.json}. */
    private final boolean noSbom;

    public SbomCheckResult(
            CheckResult sbomVsDisk, CheckResult diskVsSbom, CheckResult sbomVsManifest,
            boolean noSbom) {
        this.sbomVsDisk = sbomVsDisk;
        this.diskVsSbom = diskVsSbom;
        this.sbomVsManifest = sbomVsManifest;
        this.noSbom = noSbom;
    }

    /** Returns an empty result representing the case where no {@code sbom.cdx.json} was found. */
    public static SbomCheckResult noSbom() {
        var empty = new CheckResult(Collections.emptyList());
        return new SbomCheckResult(empty, empty, empty, true);
    }

    /**
     * @return {@code true} if all three checks passed.
     * When no manifest was present {@link #sbomVsManifest()} carries an empty issue list
     * and contributes {@code true} here.
     */
    public boolean passed() {
        return sbomVsDisk.passed() && diskVsSbom.passed() && sbomVsManifest.passed();
    }

    /** @return {@code true} if no {@code sbom.cdx.json} was found; all other results are empty. */
    public boolean isNoSbom() {
        return noSbom;
    }

    /** CHECK 1 — every SBOM maven component must be verifiable on disk. */
    public CheckResult sbomVsDisk() { return sbomVsDisk; }

    /** CHECK 2 — every JAR on disk must be declared in the SBOM. */
    public CheckResult diskVsSbom() { return diskVsSbom; }

    /**
     * CHECK 3 — every SBOM maven component must match {@code manifest.yaml}.
     * {@link CheckResult#passed()} is {@code true} and issues are empty when no manifest was present.
     */
    public CheckResult sbomVsManifest() { return sbomVsManifest; }
}
