/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.qa.tooling.sbom;

import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.Evidence;
import org.cyclonedx.model.Metadata;
import org.cyclonedx.model.component.evidence.Identity;
import org.cyclonedx.model.component.evidence.Method;
import org.cyclonedx.model.component.evidence.Occurrence;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.wildfly.qa.tooling.sbom.component.ComponentKind;
import org.wildfly.qa.tooling.sbom.component.ComponentUtils;
import org.wildfly.qa.tooling.sbom.result.CheckResult;
import org.wildfly.qa.tooling.sbom.result.SbomCheckDetails;
import org.wildfly.qa.tooling.sbom.result.SbomCheckResult;

import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.zip.GZIPOutputStream;

import static org.junit.jupiter.api.Assertions.*;

class SbomCheckerTest {

    private static Component mavenComponent(String group, String name, String version) {
        Component c = new Component();
        c.setGroup(group);
        c.setName(name);
        c.setVersion(version);
        c.setPurl("pkg:maven/" + group + "/" + name + "@" + version);
        return c;
    }

    private static Component mavenComponentWithClassifier(
            String group, String name, String version, String classifier) {
        Component c = new Component();
        c.setGroup(group);
        c.setName(name);
        c.setVersion(version);
        c.setPurl("pkg:maven/" + group + "/" + name + "@" + version + "?classifier=" + classifier);
        return c;
    }

    private static Component mavenComponentWithType(
            String group, String name, String version, String type) {
        Component c = new Component();
        c.setGroup(group);
        c.setName(name);
        c.setVersion(version);
        c.setPurl("pkg:maven/" + group + "/" + name + "@" + version + "?type=" + type);
        return c;
    }

    // ---- collectMavenComponents -------------------------------------------

    @Test
    void collectMavenComponents_skipsGenericTopLevel() {
        Component generic = new Component();
        generic.setPurl("pkg:generic/jboss-cli-client@8.1");
        generic.setName("jboss-cli-client");
        generic.setVersion("8.1");
        Component child = mavenComponent("org.jboss", "jboss-dmr", "1.7.0.Final");
        generic.setComponents(List.of(child));

        List<Component> result = ComponentUtils.collectMavenComponents(List.of(generic));
        assertEquals(1, result.size());
        assertEquals("jboss-dmr", result.get(0).getName());
    }

    @Test
    void collectMavenComponents_includesFlatMavenEntries() {
        Component c = mavenComponent("org.jboss", "jboss-dmr", "1.7.0.Final");
        assertEquals(1, ComponentUtils.collectMavenComponents(List.of(c)).size());
    }

    @Test
    void collectMavenComponents_nullListReturnsEmpty() {
        assertTrue(ComponentUtils.collectMavenComponents(null).isEmpty());
    }

    // ---- expectedJarFileName ----------------------------------------------

    @Test
    void expectedJarFileName_simple() {
        Component c = mavenComponent("org.jboss.logging", "jboss-logging", "3.6.1.Final");
        assertEquals("jboss-logging-3.6.1.Final.jar", ComponentUtils.expectedJarFileName(c));
    }

    @Test
    void expectedJarFileName_withClassifier() {
        Component c = mavenComponentWithClassifier(
                "io.netty", "netty-transport-native-unix-common", "4.1.116.Final", "linux-x86_64");
        assertEquals("netty-transport-native-unix-common-4.1.116.Final-linux-x86_64.jar",
                ComponentUtils.expectedJarFileName(c));
    }

    @Test
    void expectedJarFileName_artifactIdWithDigitSegment() {
        // The critical case: artifact id itself contains a digit segment
        Component c = mavenComponent(
                "org.wildfly.clustering",
                "wildfly-clustering-session-spec-servlet-6.0",
                "5.0.11.Final");
        assertEquals("wildfly-clustering-session-spec-servlet-6.0-5.0.11.Final.jar",
                ComponentUtils.expectedJarFileName(c));
    }

    // ---- isNonJarType -----------------------------------------------------

    @Test
    void isNonJarType_txtIsTrue() {
        Component c = mavenComponentWithType(
                "org.wildfly", "wildfly-ee-feature-pack-product-conf", "8.1.1.GA-SNAPSHOT", "txt");
        assertTrue(ComponentUtils.isNonJarType(c));
    }

    @Test
    void isNonJarType_noTypeIsFalse() {
        Component c = mavenComponent("org.foo", "foo", "1.0");
        assertFalse(ComponentUtils.isNonJarType(c));
    }

    @Test
    void isNonJarType_explicitJarIsFalse() {
        Component c = mavenComponentWithType("org.foo", "foo", "1.0", "jar");
        assertFalse(ComponentUtils.isNonJarType(c));
    }

    // ---- componentKind ----------------------------------------------------

    @Test
    void componentKind_noEvidence_isRegularJar() {
        assertEquals(ComponentKind.REGULAR_JAR,
                ComponentUtils.componentKind(mavenComponent("org.foo", "foo", "1.0")));
    }

    @Test
    void componentKind_pomDerived() {
        Component c = new Component();
        c.setName("jansi-linux64");
        c.setVersion("1.8");
        Evidence ev = new Evidence();
        Identity id = new Identity();
        Method m = new Method();
        m.setTechnique(Method.Technique.MANIFEST_ANALYSIS);
        m.setValue("maven-pom-analysis");
        id.setMethods(List.of(m));
        ev.setIdentities(List.of(id));
        c.setEvidence(ev);
        assertEquals(ComponentKind.POM_DERIVED, ComponentUtils.componentKind(c));
    }

    @Test
    void componentKind_nativeLib() {
        Component c = new Component();
        c.setName("wildfly-openssl-linux-ppc64le");
        c.setVersion("2.2.2.Final-redhat-00002");
        Occurrence occ = new Occurrence();
        occ.setLocation("modules/system/layers/base/org/wildfly/openssl/main/lib");
        Evidence ev = new Evidence();
        ev.setOccurrences(List.of(occ));
        c.setEvidence(ev);
        assertEquals(ComponentKind.NATIVE_LIB, ComponentUtils.componentKind(c));
    }

    @Test
    void componentKind_pomDerived_skippedInManifestCheck() {
        Component c = new Component();
        c.setName("gson");
        c.setVersion("2.10.1");
        c.setGroup("com.google.code.gson");
        c.setPurl("pkg:maven/com.google.code.gson/gson@2.10.1");
        Evidence ev = new Evidence();
        Identity id = new Identity();
        Method m = new Method();
        m.setTechnique(Method.Technique.MANIFEST_ANALYSIS);
        m.setValue("maven-pom-analysis");
        id.setMethods(List.of(m));
        ev.setIdentities(List.of(id));
        c.setEvidence(ev);
        assertEquals(ComponentKind.POM_DERIVED, ComponentUtils.componentKind(c));
    }

    @Test
    void componentKind_occurrenceNotLib_isRegularJar() {
        Component c = new Component();
        c.setName("wildfly-openssl-java");
        c.setVersion("2.2.5.Final");
        Occurrence occ = new Occurrence();
        occ.setLocation("modules/system/layers/base/org/wildfly/openssl/main/wildfly-openssl-java-2.2.5.Final.jar");
        Evidence ev = new Evidence();
        ev.setOccurrences(List.of(occ));
        c.setEvidence(ev);
        assertEquals(ComponentKind.REGULAR_JAR, ComponentUtils.componentKind(c));
    }

    // ---- checkMetadataCpe -------------------------------------------------

    @Test
    void checkMetadataCpe_cpePresent_passes() {
        Bom bom = new Bom();
        Metadata meta = new Metadata();
        Component comp = new Component();
        comp.setCpe("cpe:/a:redhat:jboss_enterprise_application_platform:8.1");
        meta.setComponent(comp);
        bom.setMetadata(meta);

        CheckResult result = SbomChecker.checkMetadataCpe(bom);
        assertTrue(result.passed());
        assertTrue(result.issues().isEmpty());
    }

    @Test
    void checkMetadataCpe_cpeBlank_fails() {
        Bom bom = new Bom();
        Metadata meta = new Metadata();
        Component comp = new Component();
        comp.setCpe("   ");
        meta.setComponent(comp);
        bom.setMetadata(meta);

        CheckResult result = SbomChecker.checkMetadataCpe(bom);
        assertFalse(result.passed());
        assertEquals(1, result.issues().size());
    }

    @Test
    void checkMetadataCpe_cpeNull_fails() {
        Bom bom = new Bom();
        Metadata meta = new Metadata();
        meta.setComponent(new Component());
        bom.setMetadata(meta);

        CheckResult result = SbomChecker.checkMetadataCpe(bom);
        assertFalse(result.passed());
    }

    @Test
    void checkMetadataCpe_noMetadata_fails() {
        CheckResult result = SbomChecker.checkMetadataCpe(new Bom());
        assertFalse(result.passed());
    }

    private static Bom bomWithComponent(String name, String cpe) {
        Bom bom = new Bom();
        Metadata meta = new Metadata();
        Component comp = new Component();
        comp.setName(name);
        comp.setCpe(cpe);
        meta.setComponent(comp);
        bom.setMetadata(meta);
        return bom;
    }

    @Test
    void checkMetadataCpe_communityWildFly_noCpe_passes() {
        CheckResult result = SbomChecker.checkMetadataCpe(bomWithComponent("WildFly", null));
        assertTrue(result.passed());
        assertTrue(result.issues().isEmpty());
    }

    @Test
    void checkMetadataCpe_communityWildFly_withCpe_passes() {
        CheckResult result = SbomChecker.checkMetadataCpe(
                bomWithComponent("WildFly", "cpe:/a:wildfly:wildfly:42"));
        assertTrue(result.passed());
    }

    @Test
    void checkMetadataCpe_product_noCpe_fails() {
        CheckResult result = SbomChecker.checkMetadataCpe(bomWithComponent("JBoss EAP", null));
        assertFalse(result.passed());
        assertEquals(1, result.issues().size());
    }

    @Test
    void checkMetadataCpe_product_withCpe_passes() {
        CheckResult result = SbomChecker.checkMetadataCpe(bomWithComponent(
                "JBoss EAP", "cpe:/a:redhat:jboss_enterprise_application_platform:8.1"));
        assertTrue(result.passed());
    }

    @Test
    void checkMetadataCpe_nameMatchIsExact() {
        // Only the exact community name is exempt; look-alikes must still declare a CPE.
        assertFalse(SbomChecker.checkMetadataCpe(bomWithComponent("wildfly", null)).passed());
        assertFalse(SbomChecker.checkMetadataCpe(bomWithComponent("WildFly Preview", null)).passed());
    }

    // ---- check() API -------------------------------------------------------

    @Test
    void check_noSbomFile_returnsNoSbomResult(@TempDir Path installRoot) throws Exception {
        SbomCheckResult result = SbomChecker.check(installRoot);

        assertTrue(result.isNoSbom());
        assertTrue(result.passed());
    }

    @Test
    void check_noSbomFile_checkResultsAreEmpty(@TempDir Path installRoot) throws Exception {
        SbomCheckResult result = SbomChecker.check(installRoot);

        assertTrue(result.cpeCheck().passed());
        assertTrue(result.cpeCheck().issues().isEmpty());
        assertTrue(result.sbomVsDisk().passed());
        assertTrue(result.diskVsSbom().passed());
        assertTrue(result.sbomVsDisk().issues().isEmpty());
        assertTrue(result.diskVsSbom().issues().isEmpty());
        assertNotNull(result.sbomVsManifest());
        assertTrue(result.sbomVsManifest().passed());
        assertTrue(result.sbomVsManifest().issues().isEmpty());
    }

    // ---- SBOM file discovery / gzip ----------------------------------------

    private static final String MINIMAL_SBOM = """
            {"bomFormat":"CycloneDX","specVersion":"1.6","version":1,
             "metadata":{"component":{"type":"application","name":"WildFly",
                         "cpe":"cpe:/a:wildfly:wildfly:42"}},
             "components":[]}
            """;

    private static void writeGzip(Path target, String content) throws Exception {
        try (OutputStream out = new GZIPOutputStream(Files.newOutputStream(target))) {
            out.write(content.getBytes(StandardCharsets.UTF_8));
        }
    }

    @Test
    void findSbomFile_neither_isEmpty(@TempDir Path installRoot) {
        assertTrue(SbomChecker.findSbomFile(installRoot).isEmpty());
    }

    @Test
    void findSbomFile_prefersPlainOverGzip(@TempDir Path installRoot) throws Exception {
        Files.writeString(installRoot.resolve("sbom.cdx.json"), MINIMAL_SBOM);
        writeGzip(installRoot.resolve("sbom.cdx.json.gz"), MINIMAL_SBOM);

        assertEquals(installRoot.resolve("sbom.cdx.json"), SbomChecker.findSbomFile(installRoot).orElseThrow());
    }

    @Test
    void check_gzippedSbomOnly_isParsed(@TempDir Path installRoot) throws Exception {
        writeGzip(installRoot.resolve("sbom.cdx.json.gz"), MINIMAL_SBOM);

        SbomCheckDetails details = SbomChecker.checkWithDetails(installRoot);

        assertFalse(details.isNoSbom());
        assertEquals("cpe:/a:wildfly:wildfly:42", details.getCpe());
        assertTrue(details.passed());
    }

    @Test
    void check_plainAndGzippedSbom_yieldSameResult(@TempDir Path plainRoot, @TempDir Path gzRoot) throws Exception {
        Files.writeString(plainRoot.resolve("sbom.cdx.json"), MINIMAL_SBOM);
        writeGzip(gzRoot.resolve("sbom.cdx.json.gz"), MINIMAL_SBOM);

        SbomCheckDetails plain = SbomChecker.checkWithDetails(plainRoot);
        SbomCheckDetails gz = SbomChecker.checkWithDetails(gzRoot);

        assertEquals(plain.getCpe(), gz.getCpe());
        assertEquals(plain.mavenComponents().size(), gz.mavenComponents().size());
        assertEquals(plain.passed(), gz.passed());
    }

    // ---- CheckResult -------------------------------------------------------

    @Test
    void checkResult_emptyIssues_isPassed() {
        CheckResult r = new CheckResult(List.of());
        assertTrue(r.passed());
    }

    @Test
    void checkResult_withIssues_isNotPassed() {
        CheckResult r = new CheckResult(List.of("some issue"));
        assertFalse(r.passed());
        assertEquals(1, r.issues().size());
    }
}
