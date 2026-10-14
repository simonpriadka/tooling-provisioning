/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.qa.tooling.sbom;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.wildfly.qa.tooling.sbom.result.SbomCheckDetails;

import java.nio.file.Path;
import java.nio.file.Paths;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Integration tests for {@link SbomChecker}. Requires a complete WildFly installation (the full server, not the
 * thin build) at the path given by the {@code wildfly.home} system property. The SBOM may be packaged either as
 * {@code sbom.cdx.json} or as {@code sbom.cdx.json.gz}, as WildFly builds do. Run with:
 * <pre>
 *     mvn verify -pl tooling-sbom-verification -Pintegration-tests -Dwildfly.home=/path/to/wildfly
 * </pre>
 *
 * <p>Assertions are deliberately independent of the WildFly version: no component or JAR counts are hard-coded.
 * The CPE check is covered by {@link #allChecksPass()}: community WildFly SBOMs do not carry
 * {@code metadata.component.cpe} and are not required to, while other products are.</p>
 */
class SbomCheckerIT {

    private static Path wildflyHome;
    private static SbomCheckDetails details;

    @BeforeAll
    static void setUp() throws Exception {
        String home = System.getProperty("wildfly.home");
        assertNotNull(home, "wildfly.home system property must be set");
        wildflyHome = Paths.get(home);
        assertTrue(wildflyHome.toFile().isDirectory(), "WildFly home must exist: " + wildflyHome);
        details = SbomChecker.checkWithDetails(wildflyHome);
    }

    // ---- SBOM discovery and parsing ----------------------------------------

    @Test
    void sbomFileFound() {
        assertTrue(SbomChecker.findSbomFile(wildflyHome).isPresent(),
                "Expected sbom.cdx.json or sbom.cdx.json.gz in " + wildflyHome);
        assertFalse(details.isNoSbom(), "Expected the SBOM to be found");
    }

    @Test
    void installRootIsPreserved() {
        assertEquals(wildflyHome, details.installRoot());
    }

    @Test
    void bomIsParsed() {
        assertNotNull(details.bom());
        assertNotNull(details.bom().getBomFormat());
        assertNotNull(details.bom().getSpecVersion());
        assertNotNull(details.bom().getMetadata().getComponent().getName(),
                "Expected the product name in metadata.component");
    }

    @Test
    void mavenComponentsFound() {
        assertFalse(details.mavenComponents().isEmpty(), "Expected maven components in the SBOM");
    }

    // ---- disk scan and manifest --------------------------------------------

    @Test
    void installedJarsFound() {
        assertFalse(details.installedJars().isEmpty(), "Expected JARs on disk");
    }

    @Test
    void manifestIsPresent() {
        assertFalse(details.manifest().getStreams().isEmpty(),
                "Expected .installation/manifest.yaml to be present and non-empty");
    }

    // ---- check results -----------------------------------------------------

    @Test
    void allChecksPass() {
        assertTrue(details.result().passed(), "SBOM checks failed: " + details.result());
    }

    @Test
    void sbomVsDisk_passes() {
        assertTrue(details.result().sbomVsDisk().passed(),
                "SBOM components missing from disk: " + details.result().sbomVsDisk().issues());
    }

    @Test
    void diskVsSbom_passes() {
        assertTrue(details.result().diskVsSbom().passed(),
                "Disk JARs not declared in SBOM: " + details.result().diskVsSbom().issues());
    }

    @Test
    void sbomVsManifest_passes() {
        assertTrue(details.result().sbomVsManifest().passed(),
                "SBOM/manifest version mismatches: " + details.result().sbomVsManifest().issues());
    }

    // ---- shaded artifacts --------------------------------------------------

    @Test
    void shadedResultIsPresent() {
        assertNotNull(details.shadedResult());
    }
}
