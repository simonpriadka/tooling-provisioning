/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.qa.tooling.sbom;

import org.cyclonedx.model.Component;
import org.cyclonedx.model.Evidence;
import org.cyclonedx.model.component.evidence.Identity;
import org.cyclonedx.model.component.evidence.Method;
import org.cyclonedx.model.component.evidence.Occurrence;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.wildfly.qa.tooling.sbom.component.ComponentKind;
import org.wildfly.qa.tooling.sbom.component.ComponentUtils;
import org.wildfly.qa.tooling.sbom.result.CheckResult;

import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class SbomCheckerTest {

    private static Component mavenComponent(String group, String name, String version) {
        var c = new Component();
        c.setGroup(group);
        c.setName(name);
        c.setVersion(version);
        c.setPurl("pkg:maven/" + group + "/" + name + "@" + version);
        return c;
    }

    private static Component mavenComponentWithClassifier(
            String group, String name, String version, String classifier) {
        var c = new Component();
        c.setGroup(group);
        c.setName(name);
        c.setVersion(version);
        c.setPurl("pkg:maven/" + group + "/" + name + "@" + version + "?classifier=" + classifier);
        return c;
    }

    private static Component mavenComponentWithType(
            String group, String name, String version, String type) {
        var c = new Component();
        c.setGroup(group);
        c.setName(name);
        c.setVersion(version);
        c.setPurl("pkg:maven/" + group + "/" + name + "@" + version + "?type=" + type);
        return c;
    }

    // ---- collectMavenComponents -------------------------------------------

    @Test
    void collectMavenComponents_skipsGenericTopLevel() {
        var generic = new Component();
        generic.setPurl("pkg:generic/jboss-cli-client@8.1");
        generic.setName("jboss-cli-client");
        generic.setVersion("8.1");
        var child = mavenComponent("org.jboss", "jboss-dmr", "1.7.0.Final");
        generic.setComponents(List.of(child));

        var result = ComponentUtils.collectMavenComponents(List.of(generic));
        assertEquals(1, result.size());
        assertEquals("jboss-dmr", result.get(0).getName());
    }

    @Test
    void collectMavenComponents_includesFlatMavenEntries() {
        var c = mavenComponent("org.jboss", "jboss-dmr", "1.7.0.Final");
        assertEquals(1, ComponentUtils.collectMavenComponents(List.of(c)).size());
    }

    @Test
    void collectMavenComponents_nullListReturnsEmpty() {
        assertTrue(ComponentUtils.collectMavenComponents(null).isEmpty());
    }

    // ---- expectedJarFileName ----------------------------------------------

    @Test
    void expectedJarFileName_simple() {
        var c = mavenComponent("org.jboss.logging", "jboss-logging", "3.6.1.Final");
        assertEquals("jboss-logging-3.6.1.Final.jar", ComponentUtils.expectedJarFileName(c));
    }

    @Test
    void expectedJarFileName_withClassifier() {
        var c = mavenComponentWithClassifier(
                "io.netty", "netty-transport-native-unix-common", "4.1.116.Final", "linux-x86_64");
        assertEquals("netty-transport-native-unix-common-4.1.116.Final-linux-x86_64.jar",
                ComponentUtils.expectedJarFileName(c));
    }

    @Test
    void expectedJarFileName_artifactIdWithDigitSegment() {
        // The critical case: artifact id itself contains a digit segment
        var c = mavenComponent(
                "org.wildfly.clustering",
                "wildfly-clustering-session-spec-servlet-6.0",
                "5.0.11.Final");
        assertEquals("wildfly-clustering-session-spec-servlet-6.0-5.0.11.Final.jar",
                ComponentUtils.expectedJarFileName(c));
    }

    // ---- isNonJarType -----------------------------------------------------

    @Test
    void isNonJarType_txtIsTrue() {
        var c = mavenComponentWithType(
                "org.wildfly", "wildfly-ee-feature-pack-product-conf", "8.1.1.GA-SNAPSHOT", "txt");
        assertTrue(ComponentUtils.isNonJarType(c));
    }

    @Test
    void isNonJarType_noTypeIsFalse() {
        var c = mavenComponent("org.foo", "foo", "1.0");
        assertFalse(ComponentUtils.isNonJarType(c));
    }

    @Test
    void isNonJarType_explicitJarIsFalse() {
        var c = mavenComponentWithType("org.foo", "foo", "1.0", "jar");
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
        var c = new Component();
        c.setName("jansi-linux64");
        c.setVersion("1.8");
        var ev = new Evidence();
        var id = new Identity();
        var m = new Method();
        m.setTechnique(Method.Technique.MANIFEST_ANALYSIS);
        m.setValue("maven-pom-analysis");
        id.setMethods(List.of(m));
        ev.setIdentities(List.of(id));
        c.setEvidence(ev);
        assertEquals(ComponentKind.POM_DERIVED, ComponentUtils.componentKind(c));
    }

    @Test
    void componentKind_nativeLib() {
        var c = new Component();
        c.setName("wildfly-openssl-linux-ppc64le");
        c.setVersion("2.2.2.Final-redhat-00002");
        var occ = new Occurrence();
        occ.setLocation("modules/system/layers/base/org/wildfly/openssl/main/lib");
        var ev = new Evidence();
        ev.setOccurrences(List.of(occ));
        c.setEvidence(ev);
        assertEquals(ComponentKind.NATIVE_LIB, ComponentUtils.componentKind(c));
    }

    @Test
    void componentKind_pomDerived_skippedInManifestCheck() {
        var c = new Component();
        c.setName("gson");
        c.setVersion("2.10.1");
        c.setGroup("com.google.code.gson");
        c.setPurl("pkg:maven/com.google.code.gson/gson@2.10.1");
        var ev = new Evidence();
        var id = new Identity();
        var m = new Method();
        m.setTechnique(Method.Technique.MANIFEST_ANALYSIS);
        m.setValue("maven-pom-analysis");
        id.setMethods(List.of(m));
        ev.setIdentities(List.of(id));
        c.setEvidence(ev);
        assertEquals(ComponentKind.POM_DERIVED, ComponentUtils.componentKind(c));
    }

    @Test
    void componentKind_occurrenceNotLib_isRegularJar() {
        var c = new Component();
        c.setName("wildfly-openssl-java");
        c.setVersion("2.2.5.Final");
        var occ = new Occurrence();
        occ.setLocation("modules/system/layers/base/org/wildfly/openssl/main/wildfly-openssl-java-2.2.5.Final.jar");
        var ev = new Evidence();
        ev.setOccurrences(List.of(occ));
        c.setEvidence(ev);
        assertEquals(ComponentKind.REGULAR_JAR, ComponentUtils.componentKind(c));
    }

    // ---- check() API -------------------------------------------------------

    @Test
    void check_noSbomFile_returnsNoSbomResult(@TempDir Path installRoot) throws Exception {
        var result = SbomChecker.check(installRoot);

        assertTrue(result.isNoSbom());
        assertTrue(result.passed());
    }

    @Test
    void check_noSbomFile_checkResultsAreEmpty(@TempDir Path installRoot) throws Exception {
        var result = SbomChecker.check(installRoot);

        assertTrue(result.sbomVsDisk().passed());
        assertTrue(result.diskVsSbom().passed());
        assertTrue(result.sbomVsDisk().issues().isEmpty());
        assertTrue(result.diskVsSbom().issues().isEmpty());
        assertNotNull(result.sbomVsManifest());
        assertTrue(result.sbomVsManifest().passed());
        assertTrue(result.sbomVsManifest().issues().isEmpty());
    }

    // ---- CheckResult -------------------------------------------------------

    @Test
    void checkResult_emptyIssues_isPassed() {
        var r = new CheckResult(List.of());
        assertTrue(r.passed());
    }

    @Test
    void checkResult_withIssues_isNotPassed() {
        var r = new CheckResult(List.of("some issue"));
        assertFalse(r.passed());
        assertEquals(1, r.issues().size());
    }
}
