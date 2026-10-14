/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.qa.tooling.sbom.print;

import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.wildfly.channel.ChannelManifest;
import org.wildfly.channel.Stream;
import org.wildfly.qa.tooling.sbom.SbomChecker;
import org.wildfly.qa.tooling.sbom.component.ComponentKind;
import org.wildfly.qa.tooling.sbom.component.ComponentUtils;
import org.wildfly.qa.tooling.sbom.result.BootableJarCheckDetails;
import org.wildfly.qa.tooling.sbom.result.CheckResult;
import org.wildfly.qa.tooling.sbom.result.SbomCheckDetails;
import org.wildfly.qa.tooling.sbom.result.SbomCheckResult;
import org.wildfly.qa.tooling.sbom.result.ShadedResult;
import org.wildfly.qa.tooling.sbom.scanner.InstalledArtifact;

import java.io.PrintStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
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
     *                {@link org.wildfly.qa.tooling.sbom.SbomChecker#checkWithDetails(java.nio.file.Path)}
     */
    public static void print(SbomCheckDetails details) {
        print(details, System.out);
    }

    /**
     * Prints a human-readable summary of {@code bootableDetails} to {@code System.out}.
     *
     * @param bootableDetails the full bootable JAR check details returned by
     *                        {@link org.wildfly.qa.tooling.sbom.SbomChecker#checkBootableJar(java.nio.file.Path)}
     */
    public static void print(BootableJarCheckDetails bootableDetails) {
        print(bootableDetails, System.out);
    }

    /**
     * Prints a human-readable summary of {@code bootableDetails} to the given {@link PrintStream}.
     *
     * @param bootableDetails the full bootable JAR check details
     * @param out             the stream to write to
     */
    public static void print(BootableJarCheckDetails bootableDetails, PrintStream out) {
        out.println("╔═ BOOTABLE JAR CHECK");
        out.println("║  Bootable JAR root : " + bootableDetails.outerResult().installRoot()
                .getParent().getParent());
        out.println();
        out.println("╠═ PHASE 1 — Outer SBOM (META-INF/sbom/sbom.cdx.json)");
        print(bootableDetails.outerResult(), out);

        out.println("╠═ PHASE 2 — Inner WildFly installation (from wildfly.zip)");
        print(bootableDetails.innerResult(), out);

        out.println("╠═ CPE CROSS-CHECK");
        String cpe = bootableDetails.getCpe();
        if (cpe != null) {
            out.println("║  OK – CPEs match: " + cpe);
        } else {
            String outerCpe = bootableDetails.outerResult().getCpe();
            String innerCpe = bootableDetails.innerResult().getCpe();
            out.println("║  FAILED");
            out.println("║    outer : " + (outerCpe != null ? outerCpe : "(none)"));
            out.println("║    inner : " + (innerCpe != null ? innerCpe : "(none)"));
        }
        out.println();
        out.println(bootableDetails.passed() ? "RESULT: ALL CHECKS PASSED" : "RESULT: SOME CHECKS FAILED");
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

        Bom bom = details.bom();
        List<Component> mavenComponents = details.mavenComponents();
        List<InstalledArtifact> installedJars = details.installedJars();
        ChannelManifest manifest = details.manifest();
        ShadedResult shadedResult = details.shadedResult();
        SbomCheckResult result = details.result();

        out.println("Installation root : " + details.installRoot());
        long sbomSizeKb = SbomChecker.findSbomFile(details.installRoot())
                .map(p -> p.toFile().length() / 1024)
                .orElse(0L);
        out.println("SBOM format      : " + bom.getBomFormat() + " " + bom.getSpecVersion()
                + " (" + sbomSizeKb + " KB)");

        if (bom.getMetadata() != null && bom.getMetadata().getComponent() != null) {
            Component product = bom.getMetadata().getComponent();
            out.println("Product          : " + product.getName() + " " + product.getVersion());
        }

        String sbomAnnotation = buildSbomAnnotation(mavenComponents, manifest);
        out.println("Maven components in SBOM : " + mavenComponents.size() + sbomAnnotation);
        out.println("JARs found on disk       : " + installedJars.size());
        out.println("Manifest entries         : "
                + (manifest.getStreams().isEmpty() ? "n/a (no manifest.yaml)" : manifest.getStreams().size()));
        out.println();

        printSbomBreakdown(bom.getComponents(), mavenComponents,
                ComponentUtils.countByPurlScheme(bom.getComponents(), "pkg:npm/"), out);

        printResult("CHECK 1 — CPE present in metadata.component", result.cpeCheck(), out);
        printResult("CHECK 2 — SBOM components present on disk", result.sbomVsDisk(), out);
        printResult("CHECK 3 — Disk JARs declared in SBOM", result.diskVsSbom(), out);

        if (!manifest.getStreams().isEmpty()) {
            printResult("CHECK 4 — SBOM versions match manifest.yaml", result.sbomVsManifest(), out);
            printNotInManifest("INFO — SBOM components not present in manifest.yaml",
                    mavenComponents, manifest, shadedResult.totalArtifacts(), out);
        } else {
            printSkipped("CHECK 4 — SBOM versions match manifest.yaml",
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

    private static String buildSbomAnnotation(List<Component> mavenComponents, ChannelManifest manifest) {
        if (manifest.getStreams().isEmpty()) return "";
        long notPresent = mavenComponents.stream()
                .filter(c -> manifest.findStreamFor(c.getGroup(), c.getName()).isEmpty())
                .count();
        long wrongVersion = mavenComponents.stream()
                .filter(c -> manifest.findStreamFor(c.getGroup(), c.getName())
                        .map(Stream::getVersion)
                        .map(v -> !v.equals(c.getVersion()))
                        .orElse(false))
                .count();
        if (notPresent == 0 && wrongVersion == 0) return "";
        List<String> parts = new ArrayList<>();
        if (notPresent > 0) parts.add(notPresent + " SBOM-only");
        if (wrongVersion > 0) parts.add(wrongVersion + " with multiple versions in SBOM");
        return " (" + String.join(", ", parts) + " vs manifest)";
    }

    private static void printSbomBreakdown(
            List<Component> topLevel, List<Component> allMaven, long npm, PrintStream out) {

        List<String> genericTopNames = topLevel == null ? Collections.<String>emptyList() :
                topLevel.stream()
                        .filter(c -> c.getPurl() != null && c.getPurl().startsWith("pkg:generic/"))
                        .map(Component::getName)
                        .sorted()
                        .collect(Collectors.toList());

        long nativeLib = 0, pomDerived = 0, nonJarType = 0, installable = 0;
        for (Component c : allMaven) {
            ComponentKind k = ComponentUtils.componentKind(c);
            if      (k == ComponentKind.NATIVE_LIB)  nativeLib++;
            else if (k == ComponentKind.POM_DERIVED)  pomDerived++;
            else if (ComponentUtils.isNonJarType(c))  nonJarType++;
            else                                       installable++;
        }

        long total = genericTopNames.size() + allMaven.size() + npm;
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
            int total = byParentPurl.values().stream().mapToInt(List::size).sum();
            out.println("│  " + total + " artifact(s) in " + byParentPurl.size() + " group(s):");
            byParentPurl.forEach((parent, children) -> {
                out.println("│");
                out.println("│  ┌ " + parent);
                for (String child : children) out.println("│  │  ℹ " + child);
            });
        }
        out.println();
    }

    private static void printNotInManifest(String title, List<Component> mavenComponents,
            ChannelManifest manifest, int shadedTotal, PrintStream out) {

        Map<String, List<String>> sbomVersionsByGa = new java.util.LinkedHashMap<>();
        for (Component c : mavenComponents) {
            String ga = c.getGroup() + ":" + c.getName();
            String kind = ComponentUtils.componentKind(c) == ComponentKind.POM_DERIVED ? "shaded" : "installed";
            sbomVersionsByGa.computeIfAbsent(ga, k -> new ArrayList<>())
                    .add(c.getVersion() + " (" + kind + ")");
        }

        List<String> notPresent = new ArrayList<>();
        List<String> multiVersion = new ArrayList<>();
        int notPresentArtifacts = 0, multiVersionArtifacts = 0;

        for (Map.Entry<String, List<String>> entry : sbomVersionsByGa.entrySet()) {
            String ga = entry.getKey();
            List<String> versions = entry.getValue();
            int colon = ga.indexOf(':');
            Optional<String> manifestVersion = manifest.findStreamFor(ga.substring(0, colon), ga.substring(colon + 1))
                    .map(Stream::getVersion);
            if (manifestVersion.isEmpty()) {
                long shadedCount = versions.stream().filter(v -> v.endsWith("(shaded)")).count();
                notPresentArtifacts += (int) shadedCount;
                String repr = versions.stream().filter(v -> v.endsWith("(installed)"))
                        .findFirst().orElse(versions.get(0));
                notPresent.add(ga + "@" + repr.replaceAll(" \\(.*\\)", ""));
            } else {
                String mv = manifestVersion.get();
                boolean anyMismatch = versions.stream().anyMatch(v -> !v.startsWith(mv + " "));
                if (anyMismatch) {
                    long shadedMismatch = versions.stream()
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

        int infoTotal = notPresentArtifacts + multiVersionArtifacts;
        out.println("┌─ " + title);
        if (notPresent.isEmpty() && multiVersion.isEmpty()) {
            out.println("│  (none)");
        } else {
            String crossCheck = infoTotal == shadedTotal
                    ? "= " + shadedTotal + " shaded artifacts in next INFO section"
                    : "WARNING: expected " + shadedTotal + " but counted " + infoTotal;
            out.println("│  Total shaded artifacts accounted for: " + notPresentArtifacts
                    + " not in manifest + " + multiVersionArtifacts + " version mismatch = "
                    + infoTotal + " (" + crossCheck + ")");
            out.println("│");
            if (!multiVersion.isEmpty()) {
                out.println("│  Multiple versions in SBOM (" + multiVersion.size() + " artifact(s)):");
                for (String e : multiVersion) out.println("│    ⚠ " + e);
            }
            if (!notPresent.isEmpty()) {
                if (!multiVersion.isEmpty()) out.println("│");
                out.println("│  Not in manifest (" + notPresentArtifacts + " artifact(s) across "
                        + notPresent.size() + " group(s)):");
                for (String e : notPresent) out.println("│    ℹ " + e);
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
            for (String issue : result.issues()) out.println("│    • " + issue);
        }
        out.println();
    }
}
