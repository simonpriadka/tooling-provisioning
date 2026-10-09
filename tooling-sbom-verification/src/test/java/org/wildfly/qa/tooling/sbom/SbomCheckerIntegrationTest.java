/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.qa.tooling.sbom;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIf;
import org.wildfly.qa.tooling.sbom.result.BootableJarCheckDetails;
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
    static final Path BOOTABLE_ROOT = Paths.get(
            "/Users/spriadka/Work/sbom-eap-maven-plugin-verification/" +
            "sbom-eap-maven-plugin-verification/target/" +
            "sbom-eap-maven-plugin-verification-bootable");

    static boolean installationPresent() {
        return INSTALL_ROOT.resolve("sbom.cdx.json").toFile().exists();
    }

    static boolean bootableJarPresent() {
        return BOOTABLE_ROOT.resolve("META-INF/sbom/sbom.cdx.json").toFile().exists()
                && BOOTABLE_ROOT.resolve("wildfly.zip").toFile().exists();
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
    void cpeIsPresentAndNonBlank() {
        assertNotNull(details.getCpe(), "Expected CPE to be present in metadata.component");
        assertFalse(details.getCpe().isBlank(), "Expected CPE to be non-blank");
    }

    @Test
    void cpeCheckPasses() {
        assertTrue(details.result().cpeCheck().passed(),
                "CHECK 1 failed — CPE missing: " + details.result().cpeCheck().issues());
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

    // ---- bootable JAR ------------------------------------------------------

    @Nested
    @EnabledIf("org.wildfly.qa.tooling.sbom.SbomCheckerIntegrationTest#bootableJarPresent")
    class BootableJarTests {

        static BootableJarCheckDetails bootableDetails;

        @BeforeAll
        static void runBootableCheck() throws Exception {
            bootableDetails = SbomChecker.checkBootableJar(BOOTABLE_ROOT);
        }

        @Test
        void allChecksPassed() {
            assertTrue(bootableDetails.passed(),
                    "Expected all bootable JAR checks to pass");
        }

        @Test
        void cpeIsVerified() {
            assertNotNull(bootableDetails.getCpe(),
                    "Expected verified CPE from bootable JAR check");
            assertEquals("cpe:/a:redhat:jboss_enterprise_application_platform:8.1",
                    bootableDetails.getCpe());
        }

        @Test
        void innerMavenComponentCount() {
            assertEquals(434, bootableDetails.innerResult().mavenComponents().size(),
                    "Expected 434 maven components in inner wildfly SBOM");
        }

        @Test
        void innerInstalledJarCount() {
            assertEquals(402, bootableDetails.innerResult().installedJars().size(),
                    "Expected 402 JARs on disk in inner wildfly");
        }

        @Test
        void innerManifestIsPresent() {
            assertFalse(bootableDetails.innerResult().manifest().isEmpty(),
                    "Expected manifest.yaml to be present in inner wildfly");
        }

        @Test
        void innerAllChecksPassed() {
            assertTrue(bootableDetails.innerResult().passed(),
                    "Expected all inner checks to pass");
        }
    }
}
