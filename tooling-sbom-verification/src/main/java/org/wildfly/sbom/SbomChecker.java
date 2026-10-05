/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.sbom;

import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.Evidence;
import org.cyclonedx.model.component.evidence.Identity;
import org.cyclonedx.model.component.evidence.Method;
import org.cyclonedx.model.component.evidence.Occurrence;
import org.cyclonedx.parsers.JsonParser;
import org.wildfly.sbom.manifest.ManifestReader;
import org.wildfly.sbom.scanner.InstalledArtifact;
import org.wildfly.sbom.scanner.InstallationScanner;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Entry point for the WildFly SBOM checker.
 *
 * Usage:
 *
 * java -jar sbom-checker.jar &lt;install-root&gt;
 *
 *
 * The tool performs three independent checks:
 *
 * SBOM ↔ disk: every maven component listed in the SBOM must be
 * verifiable on disk.
 * Disk ↔ SBOM: every JAR found on disk must be declared in the
 * SBOM (no undeclared artifacts).
 * SBOM ↔ manifest: every maven component in the SBOM must appear
 * in {@code .installation/manifest.yaml} with the same version.
 *
 */
public class SbomChecker {

    public static void main(String[] args) throws Exception {
        if (args.length < 1 || args.length > 2 || (args.length == 2 && !args[0].equals("--verbose"))) {
            System.err.println("Usage: sbom-checker [--verbose] <install-root>");
            System.exit(1);
        }

        boolean verbose = args.length == 2;
        Path installRoot = Paths.get(args[verbose ? 1 : 0]).toAbsolutePath().normalize();

        if (!Files.isDirectory(installRoot)) {
            System.err.println("ERROR: not a directory: " + installRoot);
            System.exit(1);
        }

        System.out.println("Installation root : " + installRoot);

        // ---- 1. Parse the SBOM ----------------------------------------
        File sbomFile = installRoot.resolve("sbom.cdx.json").toFile();
        if (!sbomFile.exists()) {
            System.out.println("No sbom.cdx.json found in " + installRoot + " — skipping.");
            return;
        }

        long sbomSizeKb = sbomFile.length() / 1024;
        Bom bom = new JsonParser().parse(sbomFile);
        System.out.println("SBOM format      : " + bom.getBomFormat() + " " + bom.getSpecVersion()
                + " (" + sbomSizeKb + " KB)");

        if (bom.getMetadata() != null && bom.getMetadata().getComponent() != null) {
            Component product = bom.getMetadata().getComponent();
            System.out.println("Product          : " + product.getName() + " " + product.getVersion());
        }

        // Collect all maven components from the SBOM (flatten the two-level tree)
        // pkg:npm sub-components (e.g. HAL console JS deps) are counted separately but excluded from all checks.
        List<Component> mavenComponents = collectMavenComponents(bom.getComponents());
        long npmComponents = countByPurlScheme(bom.getComponents(), "pkg:npm/");

        // ---- 2. Scan the installation on disk --------------------------
        InstallationScanner scanner = new InstallationScanner(installRoot);
        List<InstalledArtifact> installedJars = scanner.scan();

        // ---- 3. Read manifest.yaml (optional) --------------------------
        Map<String, String> manifest = ManifestReader.read(installRoot);
        boolean hasManifest = !manifest.isEmpty();

        // Compute manifest annotation for the SBOM component count line
        String sbomAnnotation = "";
        if (hasManifest) {
            long notPresent = mavenComponents.stream()
                    .filter(c -> !manifest.containsKey(c.getGroup() + ":" + c.getName()))
                    .count();
            long wrongVersion = mavenComponents.stream()
                    .filter(c -> {
                        String v = manifest.get(c.getGroup() + ":" + c.getName());
                        return v != null && !v.equals(c.getVersion());
                    })
                    .count();
            if (notPresent > 0 || wrongVersion > 0) {
                List<String> parts = new ArrayList<>();
                if (notPresent > 0) parts.add(notPresent + " SBOM-only");
                if (wrongVersion > 0) parts.add(wrongVersion + " with multiple versions in SBOM");
                sbomAnnotation = " (" + String.join(", ", parts) + " vs manifest)";
            }
        }

        System.out.println("Maven components in SBOM : " + mavenComponents.size() + sbomAnnotation);
        System.out.println("JARs found on disk       : " + installedJars.size());
        System.out.println("Manifest entries         : "
                + (hasManifest ? manifest.size() : "n/a (no manifest.yaml)"));
        System.out.println();

        printSbomBreakdown(bom.getComponents(), mavenComponents, npmComponents);

        // ---- Run checks ------------------------------------------------
        // Build shared indexes once
        Set<String> diskFileNames = installedJars.stream()
                .map(InstalledArtifact::jarFileName)
                .collect(Collectors.toSet());
        Map<String, String> parentIndex = buildParentIndex(bom.getComponents());

        CheckResult sbomVsDisk = checkSbomVsDisk(mavenComponents, installedJars, installRoot);
        CheckResult diskVsSbom = checkDiskVsSbom(installedJars, mavenComponents);
        ShadedResult shadedResult = collectShadedArtifacts(mavenComponents, diskFileNames, parentIndex, manifest);

        printResult("CHECK 1 — SBOM components present on disk", sbomVsDisk);
        printResult("CHECK 2 — Disk JARs declared in SBOM", diskVsSbom);

        if (hasManifest) {
            CheckResult sbomVsManifest = checkSbomVsManifest(mavenComponents, manifest);
            printResult("CHECK 3 — SBOM versions match manifest.yaml", sbomVsManifest);
            if (verbose) {
                printNotInManifest("INFO — SBOM components not present in manifest.yaml",
                        mavenComponents, manifest, shadedResult.totalArtifacts());
            }
        } else {
            printSkipped("CHECK 3 — SBOM versions match manifest.yaml",
                    "no .installation/manifest.yaml found in this installation");
        }

        if (verbose) {
            printShadedInfo("INFO — Parent JARs containing shaded dependencies not tracked by manifest",
                    shadedResult.grouped());
        }

        boolean allOk = sbomVsDisk.passed() && diskVsSbom.passed();
        System.out.println();
        System.out.println(allOk ? "RESULT: ALL CHECKS PASSED" : "RESULT: SOME CHECKS FAILED");
        if (!verbose) {
            System.out.println("  (use --verbose for detailed INFO sections)");
        }
        System.exit(allOk ? 0 : 1);
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /**
     * Maven artifacts that are installed under a fixed, unversioned filename.
     * These are real maven coordinates but their installed file does not follow
     * the {@code <name>-<version>.jar} convention.
     * Key: SBOM component {@code name}; value: path relative to install root.
     */
    static final Map<String, String> FAT_JAR_NAMES = Map.of(
            "wildfly-launcher", "bin/launcher.jar",
            "jboss-modules",    "jboss-modules.jar"
    );

    /**
     * Filenames of assembled fat JARs in {@code bin/} that are represented in
     * the SBOM only as {@code pkg:generic} top-level entries (never as maven
     * components). They are excluded from maven-level checks but must be
     * recognised in check 2 so they are not reported as undeclared.
     */
    static final Set<String> GENERIC_FAT_JAR_FILENAMES = Set.of(
            "jboss-cli-client.jar",
            "jboss-client.jar",
            "wildfly-elytron-tool.jar",
            "launcher.jar"
    );

    /**
     * Recursively collects all maven-coordinate components from the SBOM
     * component tree.
     */
    static List<Component> collectMavenComponents(List<Component> components) {
        if (components == null) return Collections.emptyList();
        List<Component> result = new ArrayList<>();
        for (Component c : components) {
            if (c.getPurl() != null && c.getPurl().startsWith("pkg:maven/")) {
                result.add(c);
            }
            result.addAll(collectMavenComponents(c.getComponents()));
        }
        return result;
    }

    /** Recursively counts all components whose purl starts with the given scheme. */
    static long countByPurlScheme(List<Component> components, String scheme) {
        if (components == null) return 0;
        long count = 0;
        for (Component c : components) {
            if (c.getPurl() != null && c.getPurl().startsWith(scheme)) count++;
            count += countByPurlScheme(c.getComponents(), scheme);
        }
        return count;
    }

    /**
     * Builds a map from each maven component's purl to the purl of its
     * nearest parent in the SBOM component tree (the component whose
     * {@code components} list directly contains it).
     *
     * Top-level components (with no parent) are not present in the map.
     */
    static Map<String, String> buildParentIndex(List<Component> components) {
        Map<String, String> index = new java.util.LinkedHashMap<>();
        buildParentIndexRecursive(components, null, index);
        return index;
    }

    private static void buildParentIndexRecursive(
            List<Component> components,
            String parentPurl,
            Map<String, String> index) {
        if (components == null) return;
        for (Component c : components) {
            String purl = c.getPurl();
            if (purl != null && parentPurl != null) {
                index.put(purl, parentPurl);
            }
            buildParentIndexRecursive(c.getComponents(), purl, index);
        }
    }

    private static CheckResult checkSbomVsDisk(
            List<Component> sbomComponents,
            List<InstalledArtifact> installedJars,
            Path installRoot) {

        Set<String> diskFileNames = installedJars.stream()
                .map(InstalledArtifact::jarFileName)
                .collect(Collectors.toSet());

        List<String> missing = new ArrayList<>();

        for (Component c : sbomComponents) {
            switch (componentKind(c)) {
                case POM_DERIVED -> { /* nothing to check */ }
                case NATIVE_LIB -> {
                    String libDir = nativeLibDir(c);
                    if (libDir != null && !Files.isDirectory(installRoot.resolve(libDir))) {
                        missing.add(c.getPurl() + " [native lib dir missing: " + libDir + "]");
                    }
                }
                case REGULAR_JAR -> {
                    if (isNonJarType(c)) break;
                    String fatJar = FAT_JAR_NAMES.get(c.getName());
                    if (fatJar != null) {
                        if (!Files.exists(installRoot.resolve(fatJar))) {
                            missing.add(c.getPurl() + " [expected: " + fatJar + "]");
                        }
                        break;
                    }
                    String expected = expectedJarFileName(c);
                    if (!diskFileNames.contains(expected)) {
                        missing.add(c.getPurl() + " [expected: " + expected + "]");
                    }
                }
            }
        }
        return new CheckResult(missing);
    }

    private static CheckResult checkDiskVsSbom(
            List<InstalledArtifact> installedJars,
            List<Component> sbomComponents) {

        Set<String> sbomFileNames = new HashSet<>();
        for (Component c : sbomComponents) {
            if (componentKind(c) == ComponentKind.POM_DERIVED) continue;
            if (isNonJarType(c)) continue;
            String fatJar = FAT_JAR_NAMES.get(c.getName());
            if (fatJar != null) {
                sbomFileNames.add(Path.of(fatJar).getFileName().toString());
            } else {
                sbomFileNames.add(expectedJarFileName(c));
            }
        }

        Set<String> reported = new HashSet<>();
        List<String> undeclared = new ArrayList<>();
        for (InstalledArtifact jar : installedJars) {
            String name = jar.jarFileName();
            if (!sbomFileNames.contains(name) && !GENERIC_FAT_JAR_FILENAMES.contains(name) && reported.add(name)) {
                undeclared.add(name);
            }
        }
        return new CheckResult(undeclared);
    }

    private static CheckResult checkSbomVsManifest(
            List<Component> sbomComponents,
            Map<String, String> manifest) {

        List<String> issues = new ArrayList<>();
        for (Component c : sbomComponents) {
            if (componentKind(c) == ComponentKind.POM_DERIVED) continue;
            String coord = c.getGroup() + ":" + c.getName();
            String manifestVersion = manifest.get(coord);
            if (manifestVersion == null) {
                issues.add("NOT IN MANIFEST " + coord + " (sbom: " + c.getVersion() + ")");
            } else if (!manifestVersion.equals(c.getVersion())) {
                issues.add("VERSION MISMATCH " + coord
                        + " sbom=" + c.getVersion() + " manifest=" + manifestVersion);
            }
        }
        return new CheckResult(issues);
    }

    // -----------------------------------------------------------------------
    // Component classification
    // -----------------------------------------------------------------------

    enum ComponentKind {
        POM_DERIVED, NATIVE_LIB, REGULAR_JAR
    }

    static ComponentKind componentKind(Component c) {
        Evidence ev = c.getEvidence();
        if (ev == null) return ComponentKind.REGULAR_JAR;

        List<Occurrence> occurrences = ev.getOccurrences();
        if (occurrences != null && !occurrences.isEmpty()) {
            boolean allLib = occurrences.stream()
                    .allMatch(o -> o.getLocation() != null && o.getLocation().endsWith("/lib"));
            return allLib ? ComponentKind.NATIVE_LIB : ComponentKind.REGULAR_JAR;
        }

        List<Identity> identities = ev.getIdentities();
        if (identities != null && !identities.isEmpty()) {
            boolean allPomDerived = identities.stream().allMatch(id -> {
                List<Method> methods = id.getMethods();
                if (methods == null || methods.isEmpty()) return false;
                return methods.stream().allMatch(m ->
                        m.getTechnique() == Method.Technique.MANIFEST_ANALYSIS
                                && "maven-pom-analysis".equals(m.getValue()));
            });
            if (allPomDerived) return ComponentKind.POM_DERIVED;
        }
        return ComponentKind.REGULAR_JAR;
    }

    static String nativeLibDir(Component c) {
        Evidence ev = c.getEvidence();
        if (ev == null || ev.getOccurrences() == null) return null;
        return ev.getOccurrences().stream()
                .map(Occurrence::getLocation)
                .filter(loc -> loc != null && loc.endsWith("/lib"))
                .findFirst()
                .orElse(null);
    }

    // -----------------------------------------------------------------------
    // Filename helpers
    // -----------------------------------------------------------------------

    static String expectedJarFileName(Component c) {
        String classifier = purlClassifier(c.getPurl());
        String versionSuffix = (classifier != null && !classifier.isBlank())
                ? c.getVersion() + "-" + classifier
                : c.getVersion();
        return c.getName() + "-" + versionSuffix + ".jar";
    }

    static boolean isNonJarType(Component c) {
        String purl = c.getPurl();
        if (purl == null) return false;
        int q = purl.indexOf('?');
        if (q < 0) return false;
        for (String param : purl.substring(q + 1).split("&")) {
            if (param.startsWith("type=") && !param.equals("type=jar")) {
                return true;
            }
        }
        return false;
    }

    static String purlClassifier(String purl) {
        if (purl == null) return null;
        int q = purl.indexOf('?');
        if (q < 0) return null;
        for (String param : purl.substring(q + 1).split("&")) {
            if (param.startsWith("classifier=")) {
                return param.substring("classifier=".length());
            }
        }
        return null;
    }

    record ShadedResult(Map<String, List<String>> grouped, int totalArtifacts) {}

    private static ShadedResult collectShadedArtifacts(
            List<Component> allMavenComponents,
            Set<String> diskFileNames,
            Map<String, String> parentIndex,
            Map<String, String> manifest) {

        Map<String, List<String>> grouped = new java.util.TreeMap<>();
        allMavenComponents.stream()
                .filter(c -> componentKind(c) == ComponentKind.POM_DERIVED)
                .filter(c -> !diskFileNames.contains(expectedJarFileName(c)))
                .filter(c -> {
                    String fatJar = FAT_JAR_NAMES.get(c.getName());
                    if (fatJar == null) return true;
                    return !diskFileNames.contains(Path.of(fatJar).getFileName().toString());
                })
                .filter(c -> {
                    String manifestVersion = manifest.get(c.getGroup() + ":" + c.getName());
                    return manifestVersion == null || !manifestVersion.equals(c.getVersion());
                })
                .forEach(c -> {
                    String parent = parentIndex.getOrDefault(c.getPurl(), "(no parent)");
                    grouped.computeIfAbsent(parent, k -> new ArrayList<>()).add(c.getPurl());
                });
        grouped.values().forEach(Collections::sort);
        int total = grouped.values().stream().mapToInt(List::size).sum();
        return new ShadedResult(grouped, total);
    }

    private static void printSbomBreakdown(List<Component> topLevel, List<Component> allMaven, long npm) {
        List<String> genericTopNames = topLevel == null ? Collections.emptyList() :
                topLevel.stream()
                        .filter(c -> c.getPurl() != null && c.getPurl().startsWith("pkg:generic/"))
                        .map(Component::getName)
                        .sorted()
                        .collect(Collectors.toList());

        long nativeLib = 0, pomDerived = 0, nonJarType = 0, installable = 0;
        for (Component c : allMaven) {
            ComponentKind k = componentKind(c);
            if (k == ComponentKind.NATIVE_LIB)       nativeLib++;
            else if (k == ComponentKind.POM_DERIVED)  pomDerived++;
            else if (isNonJarType(c))                 nonJarType++;
            else                                       installable++;
        }

        long total = genericTopNames.size() + allMaven.size() + npm;
        System.out.println("┌─ SBOM entry breakdown");
        System.out.printf("│  Total entries                                : %4d%n", total);
        System.out.printf("│  Bundled fat JARs (no version on disk)        : %4d (%s)%n",
                genericTopNames.size(), String.join(", ", genericTopNames));
        System.out.printf("│  Native .so/.dll                              : %4d (installed as shared libraries under lib/)%n", nativeLib);
        System.out.printf("│  POM-derived / shaded                         : %4d (bundled inside a parent JAR)%n", pomDerived);
        System.out.printf("│  Non-JAR type                                 : %4d (type=txt or similar, not a JAR)%n", nonJarType);
        if (npm > 0) {
            System.out.printf("│  npm (JS/front-end, not checked)              : %4d (bundled inside hal-console resources JAR)%n", npm);
        }
        System.out.printf("│  Installable JARs                             : %4d (expected on disk)%n", installable);
        System.out.println();
    }

    private static void printShadedInfo(String title, Map<String, List<String>> grouped) {
        System.out.println("┌─ " + title);
        if (grouped.isEmpty()) {
            System.out.println("│  (none)");
        } else {
            int total = grouped.values().stream().mapToInt(List::size).sum();
            System.out.println("│  " + total + " artifact(s) in " + grouped.size() + " group(s):");
            grouped.forEach((parent, children) -> {
                System.out.println("│");
                System.out.println("│  ┌ " + parent);
                for (String child : children) {
                    System.out.println("│  │  ℹ " + child);
                }
            });
        }
        System.out.println();
    }

    private static void printNotInManifest(String title, List<Component> mavenComponents,
            Map<String, String> manifest, int shadedTotal) {

        java.util.LinkedHashMap<String, List<String>> sbomVersionsByGa = new java.util.LinkedHashMap<>();
        for (Component c : mavenComponents) {
            String ga = c.getGroup() + ":" + c.getName();
            String kind = componentKind(c) == ComponentKind.POM_DERIVED ? "shaded" : "installed";
            sbomVersionsByGa.computeIfAbsent(ga, k -> new ArrayList<>())
                    .add(c.getVersion() + " (" + kind + ")");
        }

        List<String> notPresent = new ArrayList<>();
        List<String> multiVersion = new ArrayList<>();
        int notPresentArtifacts = 0;
        int multiVersionArtifacts = 0;

        for (Map.Entry<String, List<String>> entry : sbomVersionsByGa.entrySet()) {
            String ga = entry.getKey();
            List<String> versions = entry.getValue();
            String manifestVersion = manifest.get(ga);
            if (manifestVersion == null) {
                long shadedCount = versions.stream().filter(v -> v.endsWith("(shaded)")).count();
                notPresentArtifacts += (int) shadedCount;
                String repr = versions.stream()
                        .filter(v -> v.endsWith("(installed)"))
                        .findFirst()
                        .orElse(versions.get(0));
                notPresent.add(ga + "@" + repr.replaceAll(" \\(.*\\)", ""));
            } else {
                boolean anyMismatch = versions.stream().anyMatch(v -> !v.startsWith(manifestVersion + " "));
                if (anyMismatch) {
                    long shadedMismatch = versions.stream()
                            .filter(v -> v.endsWith("(shaded)") && !v.startsWith(manifestVersion + " "))
                            .count();
                    multiVersionArtifacts += (int) shadedMismatch;
                    String allVersions = String.join(", ", versions);
                    multiVersion.add(ga + " manifest=" + manifestVersion
                            + " sbom contains " + versions.size() + " version(s): " + allVersions);
                }
            }
        }

        Collections.sort(notPresent);
        Collections.sort(multiVersion);

        int infoTotal = notPresentArtifacts + multiVersionArtifacts;
        System.out.println("┌─ " + title);
        if (notPresent.isEmpty() && multiVersion.isEmpty()) {
            System.out.println("│  (none)");
        } else {
            String crossCheck = infoTotal == shadedTotal
                    ? "= " + shadedTotal + " shaded artifacts in next INFO section"
                    : "WARNING: expected " + shadedTotal + " but counted " + infoTotal;
            System.out.println("│  Total shaded artifacts accounted for: " + notPresentArtifacts
                    + " not in manifest + " + multiVersionArtifacts + " version mismatch = "
                    + infoTotal + " (" + crossCheck + ")");
            System.out.println("│");
            if (!multiVersion.isEmpty()) {
                System.out.println("│  Multiple versions in SBOM (" + multiVersion.size() + " artifact(s)):");
                for (String e : multiVersion) System.out.println("│    ⚠ " + e);
            }
            if (!notPresent.isEmpty()) {
                if (!multiVersion.isEmpty()) System.out.println("│");
                System.out.println("│  Not in manifest (" + notPresentArtifacts + " artifact(s) across "
                        + notPresent.size() + " group(s)):");
                for (String e : notPresent) System.out.println("│    ℹ " + e);
            }
        }
        System.out.println();
    }

    private static void printSkipped(String title, String reason) {
        System.out.println("┌─ " + title);
        System.out.println("│  SKIPPED – " + reason);
        System.out.println();
    }

    private static void printResult(String title, CheckResult result) {
        System.out.println("┌─ " + title);
        if (result.passed()) {
            System.out.println("│  OK – no issues found");
        } else {
            System.out.println("│  FAILED – " + result.issues().size() + " issue(s):");
            for (String issue : result.issues()) System.out.println("│    • " + issue);
        }
        System.out.println();
    }

    record CheckResult(List<String> issues) {
        boolean passed() { return issues.isEmpty(); }
    }
}
