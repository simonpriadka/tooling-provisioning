/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.qa.tooling.sbom.print;

import org.cyclonedx.model.Component;
import org.wildfly.qa.tooling.sbom.component.ComponentKind;
import org.wildfly.qa.tooling.sbom.component.ComponentUtils;
import org.wildfly.qa.tooling.sbom.manifest.Manifest;
import org.wildfly.qa.tooling.sbom.result.CheckResult;
import org.wildfly.qa.tooling.sbom.result.SbomCheckDetails;

import java.io.PrintStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Prints a human-readable summary of a {@link SbomCheckDetails} to a {@link PrintStream}.
 *
 * <p>Call {@link #print(SbomCheckDetails)} to write to {@code System.out}, or
 * {@link #print(SbomCheckDetails, PrintStream)} to redirect output.</p>
 */
public final class SbomPrinter {

    private SbomPrinter() {}

    /**
     * Prints a human-readable summary of {@code details} to {@code System.out}.
     *
     * @param details the full check details returned by
     *                {@link org.wildfly.sbom.SbomChecker#checkWithDetails()}
     */
    public static void print(SbomCheckDetails details) {
        print(details, System.out);
    }

    /**
     * Prints a human-readable summary of {@code details} to the given {@link PrintStream}.
     *
     * @param details the full check details
     * @param out     the stream to write to
     */
    public static void print(SbomCheckDetails details, PrintStream out) {
        if (details.isNoSbom()) {
            out.println("No sbom.cdx.json found in " + details.installRoot() + " — skipping.");
            return;
        }

        var bom = details.bom();
        var mavenComponents = details.mavenComponents();
        var installedJars = details.installedJars();
        var manifest = details.manifest();
        var shadedResult = details.shadedResult();
        var result = details.result();

        out.println("Installation root : " + details.installRoot());
        var sbomSizeKb = details.installRoot().resolve("sbom.cdx.json").toFile().length() / 1024;
        out.println("SBOM format      : " + bom.getBomFormat() + " " + bom.getSpecVersion()
                + " (" + sbomSizeKb + " KB)");

        if (bom.getMetadata() != null && bom.getMetadata().getComponent() != null) {
            var product = bom.getMetadata().getComponent();
            out.println("Product          : " + product.getName() + " " + product.getVersion());
        }

        var sbomAnnotation = buildSbomAnnotation(mavenComponents, manifest);
        out.println("Maven components in SBOM : " + mavenComponents.size() + sbomAnnotation);
        out.println("JARs found on disk       : " + installedJars.size());
        out.println("Manifest entries         : "
                + (manifest.isEmpty() ? "n/a (no manifest.yaml)" : manifest.size()));
        out.println();

        printSbomBreakdown(bom.getComponents(), mavenComponents,
                ComponentUtils.countByPurlScheme(bom.getComponents(), "pkg:npm/"), out);

        printResult("CHECK 1 — SBOM components present on disk", result.sbomVsDisk(), out);
        printResult("CHECK 2 — Disk JARs declared in SBOM", result.diskVsSbom(), out);

        if (!manifest.isEmpty()) {
            printResult("CHECK 3 — SBOM versions match manifest.yaml", result.sbomVsManifest(), out);
            printNotInManifest("INFO — SBOM components not present in manifest.yaml",
                    mavenComponents, manifest, shadedResult.totalArtifacts(), out);
        } else {
            printSkipped("CHECK 3 — SBOM versions match manifest.yaml",
                    "no .installation/manifest.yaml found in this installation", out);
        }

        printShadedInfo("INFO — Parent JARs containing shaded dependencies not tracked by manifest",
                shadedResult.byParentPurl(), out);

        out.println();
        out.println(details.passed() ? "RESULT: ALL CHECKS PASSED" : "RESULT: SOME CHECKS FAILED");
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    private static String buildSbomAnnotation(List<Component> mavenComponents, Manifest manifest) {
        if (manifest.isEmpty()) return "";
        var notPresent = mavenComponents.stream()
                .filter(c -> !manifest.contains(c.getGroup(), c.getName()))
                .count();
        var wrongVersion = mavenComponents.stream()
                .filter(c -> manifest.version(c.getGroup(), c.getName())
                        .map(v -> !v.equals(c.getVersion()))
                        .orElse(false))
                .count();
        if (notPresent == 0 && wrongVersion == 0) return "";
        var parts = new ArrayList<String>();
        if (notPresent > 0) parts.add(notPresent + " SBOM-only");
        if (wrongVersion > 0) parts.add(wrongVersion + " with multiple versions in SBOM");
        return " (" + String.join(", ", parts) + " vs manifest)";
    }

    private static void printSbomBreakdown(
            List<Component> topLevel, List<Component> allMaven, long npm, PrintStream out) {

        var genericTopNames = topLevel == null ? Collections.<String>emptyList() :
                topLevel.stream()
                        .filter(c -> c.getPurl() != null && c.getPurl().startsWith("pkg:generic/"))
                        .map(Component::getName)
                        .sorted()
                        .collect(Collectors.toList());

        long nativeLib = 0, pomDerived = 0, nonJarType = 0, installable = 0;
        for (var c : allMaven) {
            var k = ComponentUtils.componentKind(c);
            if      (k == ComponentKind.NATIVE_LIB)  nativeLib++;
            else if (k == ComponentKind.POM_DERIVED)  pomDerived++;
            else if (ComponentUtils.isNonJarType(c))  nonJarType++;
            else                                       installable++;
        }

        var total = genericTopNames.size() + allMaven.size() + npm;
        out.println("┌─ SBOM entry breakdown");
        out.printf("│  Total entries                                : %4d%n", total);
        out.printf("│  Bundled fat JARs (no version on disk)        : %4d (%s)%n",
                genericTopNames.size(), String.join(", ", genericTopNames));
        out.printf("│  Native .so/.dll                              : %4d (installed as shared libraries under lib/)%n", nativeLib);
        out.printf("│  POM-derived / shaded                         : %4d (bundled inside a parent JAR)%n", pomDerived);
        out.printf("│  Non-JAR type                                 : %4d (type=txt or similar, not a JAR)%n", nonJarType);
        if (npm > 0) {
            out.printf("│  npm (JS/front-end, not checked)              : %4d (bundled inside hal-console resources JAR)%n", npm);
        }
        out.printf("│  Installable JARs                             : %4d (expected on disk)%n", installable);
        out.println();
    }

    private static void printShadedInfo(String title, Map<String, List<String>> byParentPurl, PrintStream out) {
        out.println("┌─ " + title);
        if (byParentPurl.isEmpty()) {
            out.println("│  (none)");
        } else {
            var total = byParentPurl.values().stream().mapToInt(List::size).sum();
            out.println("│  " + total + " artifact(s) in " + byParentPurl.size() + " group(s):");
            byParentPurl.forEach((parent, children) -> {
                out.println("│");
                out.println("│  ┌ " + parent);
                for (var child : children) out.println("│  │  ℹ " + child);
            });
        }
        out.println();
    }

    private static void printNotInManifest(String title, List<Component> mavenComponents,
            Manifest manifest, int shadedTotal, PrintStream out) {

        var sbomVersionsByGa = new java.util.LinkedHashMap<String, List<String>>();
        for (var c : mavenComponents) {
            var ga = c.getGroup() + ":" + c.getName();
            var kind = ComponentUtils.componentKind(c) == ComponentKind.POM_DERIVED ? "shaded" : "installed";
            sbomVersionsByGa.computeIfAbsent(ga, k -> new ArrayList<>())
                    .add(c.getVersion() + " (" + kind + ")");
        }

        var notPresent = new ArrayList<String>();
        var multiVersion = new ArrayList<String>();
        int notPresentArtifacts = 0, multiVersionArtifacts = 0;

        for (var entry : sbomVersionsByGa.entrySet()) {
            var ga = entry.getKey();
            var versions = entry.getValue();
            var colon = ga.indexOf(':');
            var manifestVersion = manifest.version(ga.substring(0, colon), ga.substring(colon + 1));
            if (manifestVersion.isEmpty()) {
                var shadedCount = versions.stream().filter(v -> v.endsWith("(shaded)")).count();
                notPresentArtifacts += (int) shadedCount;
                var repr = versions.stream().filter(v -> v.endsWith("(installed)"))
                        .findFirst().orElse(versions.get(0));
                notPresent.add(ga + "@" + repr.replaceAll(" \\(.*\\)", ""));
            } else {
                var mv = manifestVersion.get();
                var anyMismatch = versions.stream().anyMatch(v -> !v.startsWith(mv + " "));
                if (anyMismatch) {
                    var shadedMismatch = versions.stream()
                            .filter(v -> v.endsWith("(shaded)") && !v.startsWith(mv + " "))
                            .count();
                    multiVersionArtifacts += (int) shadedMismatch;
                    multiVersion.add(ga + " manifest=" + mv
                            + " sbom contains " + versions.size() + " version(s): "
                            + String.join(", ", versions));
                }
            }
        }

        Collections.sort(notPresent);
        Collections.sort(multiVersion);

        var infoTotal = notPresentArtifacts + multiVersionArtifacts;
        out.println("┌─ " + title);
        if (notPresent.isEmpty() && multiVersion.isEmpty()) {
            out.println("│  (none)");
        } else {
            var crossCheck = infoTotal == shadedTotal
                    ? "= " + shadedTotal + " shaded artifacts in next INFO section"
                    : "WARNING: expected " + shadedTotal + " but counted " + infoTotal;
            out.println("│  Total shaded artifacts accounted for: " + notPresentArtifacts
                    + " not in manifest + " + multiVersionArtifacts + " version mismatch = "
                    + infoTotal + " (" + crossCheck + ")");
            out.println("│");
            if (!multiVersion.isEmpty()) {
                out.println("│  Multiple versions in SBOM (" + multiVersion.size() + " artifact(s)):");
                for (var e : multiVersion) out.println("│    ⚠ " + e);
            }
            if (!notPresent.isEmpty()) {
                if (!multiVersion.isEmpty()) out.println("│");
                out.println("│  Not in manifest (" + notPresentArtifacts + " artifact(s) across "
                        + notPresent.size() + " group(s)):");
                for (var e : notPresent) out.println("│    ℹ " + e);
            }
        }
        out.println();
    }

    private static void printSkipped(String title, String reason, PrintStream out) {
        out.println("┌─ " + title);
        out.println("│  SKIPPED – " + reason);
        out.println();
    }

    private static void printResult(String title, CheckResult result, PrintStream out) {
        out.println("┌─ " + title);
        if (result.passed()) {
            out.println("│  OK – no issues found");
        } else {
            out.println("│  FAILED – " + result.issues().size() + " issue(s):");
            for (var issue : result.issues()) out.println("│    • " + issue);
        }
        out.println();
    }
}
