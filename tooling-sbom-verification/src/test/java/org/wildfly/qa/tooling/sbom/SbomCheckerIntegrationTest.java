/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.qa.tooling.sbom;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIf;
import org.wildfly.qa.tooling.sbom.result.SbomCheckDetails;

import java.nio.file.Path;
import java.nio.file.Paths;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Integration tests that run against a real JBoss EAP 8.1 installation at
 * {@code /Users/spriadka/jboss-eap-8.1}. The tests are skipped automatically
 * when that path is absent (e.g. in CI).
 */
@EnabledIf("installationPresent")
class SbomCheckerIntegrationTest {

    static final Path INSTALL_ROOT = Paths.get("/Users/spriadka/jboss-eap-8.1");

    static boolean installationPresent() {
        return INSTALL_ROOT.resolve("sbom.cdx.json").toFile().exists();
    }

    static SbomCheckDetails details;

    @BeforeAll
    static void runCheck() throws Exception {
        details = SbomChecker.checkWithDetails(INSTALL_ROOT);
    }

    // ---- overall result ----------------------------------------------------

    @Test
    void allChecksPassed() {
        assertTrue(details.passed(), "Expected all checks to pass against the EAP 8.1 installation");
    }

    @Test
    void sbomFileFound() {
        assertFalse(details.isNoSbom(), "Expected sbom.cdx.json to be present");
    }

    @Test
    void installRootIsPreserved() {
        assertEquals(INSTALL_ROOT.toAbsolutePath().normalize(), details.installRoot());
    }

    // ---- SBOM contents -----------------------------------------------------

    @Test
    void bomIsParsed() {
        assertNotNull(details.bom());
        assertNotNull(details.bom().getBomFormat());
        assertNotNull(details.bom().getSpecVersion());
    }

    @Test
    void mavenComponentCount() {
        assertEquals(856, details.mavenComponents().size(),
                "Expected 856 maven components in the SBOM");
    }

    // ---- disk scan ---------------------------------------------------------

    @Test
    void installedJarCount() {
        assertEquals(661, details.installedJars().size(),
                "Expected 661 JARs on disk");
    }

    // ---- manifest ----------------------------------------------------------

    @Test
    void manifestIsPresent() {
        assertFalse(details.manifest().isEmpty(), "Expected manifest.yaml to be present");
    }

    @Test
    void manifestEntryCount() {
        assertEquals(672, details.manifest().size(),
                "Expected 672 manifest entries");
    }

    // ---- check results -----------------------------------------------------

    @Test
    void check1_sbomVsDisk_passes() {
        assertTrue(details.result().sbomVsDisk().passed(),
                "CHECK 1 failed — SBOM components missing from disk: " + details.result().sbomVsDisk().issues());
    }

    @Test
    void check2_diskVsSbom_passes() {
        assertTrue(details.result().diskVsSbom().passed(),
                "CHECK 2 failed — disk JARs not declared in SBOM: " + details.result().diskVsSbom().issues());
    }

    @Test
    void check3_sbomVsManifest_passes() {
        assertTrue(details.result().sbomVsManifest().passed(),
                "CHECK 3 failed — SBOM/manifest version mismatches: " + details.result().sbomVsManifest().issues());
    }

    // ---- shaded artifacts --------------------------------------------------

    @Test
    void shadedResultIsPresent() {
        assertNotNull(details.shadedResult());
    }

    @Test
    void shadedArtifactTotal() {
        assertEquals(33, details.shadedResult().totalArtifacts(),
                "Expected 33 shaded/POM-derived artifacts not tracked by manifest");
    }

    @Test
    void shadedGroupCount() {
        assertEquals(10, details.shadedResult().byParentPurl().size(),
                "Expected 10 parent JAR groups containing shaded dependencies");
    }
}
