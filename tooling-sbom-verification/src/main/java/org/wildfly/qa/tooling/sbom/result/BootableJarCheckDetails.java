/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.qa.tooling.sbom.result;

import java.nio.file.Path;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * The combined result of a bootable JAR check performed by
 * {@link org.wildfly.qa.tooling.sbom.SbomChecker#checkBootableJar(java.nio.file.Path)}.
 *
 * <p>Encapsulates results from two internal phases (outer SBOM and inner WildFly installation)
 * without exposing the phase split to callers. Use {@link #passed()} for the overall result
 * and {@link #getCpe()} to retrieve the verified CPE string.</p>
 *
 * <p>When no {@code META-INF/sbom/sbom.cdx.json} was found, {@link #isNoSbom()} returns
 * {@code true}, {@link #passed()} returns {@code true} (vacuously), and {@link #getCpe()}
 * returns {@code null}.</p>
 */
public final class BootableJarCheckDetails {

    private final SbomCheckDetails outerResult;
    private final SbomCheckDetails innerResult;
    private final CheckResult cpeCrossCheck;
    private final boolean noSbom;

    /** Normal constructor — both phases ran. */
    public BootableJarCheckDetails(SbomCheckDetails outerResult, SbomCheckDetails innerResult) {
        this.outerResult = outerResult;
        this.innerResult = innerResult;
        this.noSbom = false;
        this.cpeCrossCheck = buildCpeCrossCheck(outerResult, innerResult);
    }

    /** No-SBOM constructor. */
    private BootableJarCheckDetails(Path bootableRoot) {
        this.outerResult = SbomCheckDetails.noSbom(bootableRoot);
        this.innerResult = SbomCheckDetails.noSbom(bootableRoot);
        this.noSbom = true;
        this.cpeCrossCheck = new CheckResult(Collections.emptyList());
    }

    /**
     * Returns a details object representing the case where no bootable JAR SBOM
     * ({@code META-INF/sbom/sbom.cdx.json}) was found.
     */
    public static BootableJarCheckDetails noSbom(Path bootableRoot) {
        return new BootableJarCheckDetails(bootableRoot);
    }

    /**
     * @return {@code true} if no {@code META-INF/sbom/sbom.cdx.json} was found.
     */
    public boolean isNoSbom() { return noSbom; }

    /**
     * @return {@code true} when all checks in both phases pass and the CPE values match.
     *         {@code true} vacuously when {@link #isNoSbom()} is {@code true}.
     */
    public boolean passed() {
        return noSbom || (outerResult.passed() && innerResult.passed() && cpeCrossCheck.passed());
    }

    /**
     * Returns the CPE string verified across both SBOMs, or {@code null} when:
     * <ul>
     *   <li>no SBOM was found ({@link #isNoSbom()} is {@code true}), or</li>
     *   <li>the CPE field is absent or blank in either SBOM, or</li>
     *   <li>the two CPE values do not match.</li>
     * </ul>
     */
    public String getCpe() {
        if (noSbom || !cpeCrossCheck.passed()) return null;
        return outerResult.getCpe();
    }

    /**
     * The Phase 1 result — outer {@code META-INF/sbom/sbom.cdx.json}.
     * Exposed for diagnostics; prefer {@link #passed()} and {@link #getCpe()} for normal use.
     */
    public SbomCheckDetails outerResult() { return outerResult; }

    /**
     * The Phase 2 result — extracted {@code wildfly/} installation.
     * Exposed for diagnostics; prefer {@link #passed()} and {@link #getCpe()} for normal use.
     */
    public SbomCheckDetails innerResult() { return innerResult; }

    // -----------------------------------------------------------------------

    private static CheckResult buildCpeCrossCheck(SbomCheckDetails outer, SbomCheckDetails inner) {
        var outerCpe = outer.getCpe();
        var innerCpe = inner.getCpe();
        if (outerCpe == null) {
            return new CheckResult(List.of("Outer SBOM (META-INF/sbom/sbom.cdx.json) has no CPE"));
        }
        if (innerCpe == null) {
            return new CheckResult(List.of("Inner SBOM (wildfly/sbom.cdx.json) has no CPE"));
        }
        if (!Objects.equals(outerCpe, innerCpe)) {
            return new CheckResult(List.of(
                    "CPE mismatch: outer=" + outerCpe + " inner=" + innerCpe));
        }
        return new CheckResult(Collections.emptyList());
    }
}
