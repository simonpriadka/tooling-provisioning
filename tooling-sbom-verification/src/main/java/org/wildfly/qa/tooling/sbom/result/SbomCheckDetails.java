/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.qa.tooling.sbom.result;

import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.wildfly.qa.tooling.sbom.manifest.Manifest;
import org.wildfly.qa.tooling.sbom.scanner.InstalledArtifact;

import java.nio.file.Path;
import java.util.List;

/**
 * The full context produced by {@link org.wildfly.qa.tooling.sbom.SbomChecker#checkWithDetails(Path)}.
 *
 * <p>Contains both the lean {@link SbomCheckResult} (check outcomes only) and all
 * intermediate data collected during the check — useful for printing, diagnostics,
 * and detailed assertions.</p>
 *
 * <p>Use {@link #result()} when only pass/fail information is needed.
 * Use this object directly when access to the parsed BOM, component lists,
 * manifest, or shaded artifact grouping is required.</p>
 */
public final class SbomCheckDetails {

    private final SbomCheckResult result;
    private final Path installRoot;
    private final Bom bom;
    private final List<Component> mavenComponents;
    private final List<InstalledArtifact> installedJars;
    private final Manifest manifest;
    private final ShadedResult shadedResult;

    public SbomCheckDetails(
            SbomCheckResult result,
            Path installRoot,
            Bom bom,
            List<Component> mavenComponents,
            List<InstalledArtifact> installedJars,
            Manifest manifest,
            ShadedResult shadedResult) {
        this.result = result;
        this.installRoot = installRoot;
        this.bom = bom;
        this.mavenComponents = mavenComponents;
        this.installedJars = installedJars;
        this.manifest = manifest;
        this.shadedResult = shadedResult;
    }

    /** Returns an empty details object representing the case where no {@code sbom.cdx.json} was found. */
    public static SbomCheckDetails noSbom(Path installRoot) {
        return new SbomCheckDetails(
                SbomCheckResult.noSbom(),
                installRoot, null,
                List.of(), List.of(),
                Manifest.empty(), null);
    }

    /** The lean check result — pass/fail outcomes for all four checks. */
    public SbomCheckResult result() { return result; }

    /** Convenience delegation — equivalent to {@code result().passed()}. */
    public boolean passed() { return result.passed(); }

    /** Convenience delegation — equivalent to {@code result().isNoSbom()}. */
    public boolean isNoSbom() { return result.isNoSbom(); }

    /** The installation root that was checked. */
    public Path installRoot() { return installRoot; }

    /** The parsed BOM, or {@code null} when {@link #isNoSbom()} is {@code true}. */
    public Bom bom() { return bom; }

    /**
     * The CPE string from {@code metadata.component.cpe}, or {@code null} when the
     * SBOM was not found, metadata is absent, or the CPE field is blank.
     */
    public String getCpe() {
        if (bom == null) return null;
        var meta = bom.getMetadata();
        if (meta == null) return null;
        var comp = meta.getComponent();
        if (comp == null) return null;
        var cpe = comp.getCpe();
        return (cpe != null && !cpe.isBlank()) ? cpe : null;
    }

    /** All maven components collected from the SBOM component tree. */
    public List<Component> mavenComponents() { return mavenComponents; }

    /** All JARs found on disk during the scan. */
    public List<InstalledArtifact> installedJars() { return installedJars; }

    /**
     * The parsed {@code manifest.yaml}.
     * {@link Manifest#isEmpty()} is {@code true} when no manifest was found.
     */
    public Manifest manifest() { return manifest; }

    /**
     * Shaded/POM-derived artifact grouping.
     * {@code null} when {@link #isNoSbom()} is {@code true}.
     */
    public ShadedResult shadedResult() { return shadedResult; }
}
