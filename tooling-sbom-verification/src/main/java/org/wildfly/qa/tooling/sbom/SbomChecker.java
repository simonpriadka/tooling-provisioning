/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.qa.tooling.sbom;

import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.parsers.JsonParser;
import org.wildfly.qa.tooling.sbom.component.ComponentKind;
import org.wildfly.qa.tooling.sbom.component.ComponentUtils;
import org.wildfly.qa.tooling.sbom.manifest.Manifest;
import org.wildfly.qa.tooling.sbom.manifest.ManifestReader;
import org.wildfly.qa.tooling.sbom.print.SbomPrinter;
import org.wildfly.qa.tooling.sbom.result.BootableJarCheckDetails;
import org.wildfly.qa.tooling.sbom.result.CheckResult;
import org.wildfly.qa.tooling.sbom.result.SbomCheckDetails;
import org.wildfly.qa.tooling.sbom.result.SbomCheckResult;
import org.wildfly.qa.tooling.sbom.result.ShadedResult;
import org.wildfly.qa.tooling.sbom.scanner.InstalledArtifact;
import org.wildfly.qa.tooling.sbom.scanner.InstallationScanner;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * WildFly SBOM checker.
 *
 * <p>The entry point is {@link #check(Path)}, which performs all three checks
 * and returns a {@link SbomCheckResult} without any I/O side effects.</p>
 *
 * <p>The three checks are:</p>
 * <ul>
 *   <li>SBOM ↔ disk: every maven component listed in the SBOM must be verifiable on disk.</li>
 *   <li>Disk ↔ SBOM: every JAR found on disk must be declared in the SBOM.</li>
 *   <li>SBOM ↔ manifest: every maven component in the SBOM must appear in
 *       {@code .installation/manifest.yaml} with the same version.</li>
 * </ul>
 */
public class SbomChecker {

    // -----------------------------------------------------------------------
    // Public API
    // -----------------------------------------------------------------------

    /**
     * Maven artifacts that are installed under a fixed, unversioned filename.
     * Key: SBOM component {@code name}; value: path relative to install root.
     */
    static final Map<String, String> FAT_JAR_NAMES = Map.of(
            "wildfly-launcher", "bin/launcher.jar",
            "jboss-modules",    "jboss-modules.jar"
    );

    /**
     * Filenames of assembled fat JARs represented in the SBOM only as
     * {@code pkg:generic} entries. Excluded from maven-level checks but
     * recognised in check 2 so they are not reported as undeclared.
     */
    static final Set<String> GENERIC_FAT_JAR_FILENAMES = Set.of(
            "jboss-cli-client.jar",
            "jboss-client.jar",
            "wildfly-elytron-tool.jar",
            "launcher.jar"
    );

    /**
     * Runs all SBOM checks against the given WildFly installation root and
     * returns a lean {@link SbomCheckResult} containing only the check outcomes.
     *
     * <p>Use {@link #checkWithDetails(Path)} when access to the parsed BOM,
     * component lists, manifest, or shaded artifact grouping is also needed.</p>
     *
     * <p>This method has no I/O side effects: it does not print to stdout/stderr
     * and does not call {@link System#exit}.</p>
     *
     * @param installRoot path to the WildFly installation root (the directory that
     *                    contains {@code jboss-modules.jar}, {@code modules/},
     *                    {@code bin/}, etc.)
     * @return the combined result of all checks; never {@code null}
     * @throws IOException if the installation tree or SBOM file cannot be read
     * @throws org.cyclonedx.exception.ParseException if the SBOM file is malformed
     */
    public static SbomCheckResult check(Path installRoot) throws Exception {
        return checkWithDetails(installRoot).result();
    }

    /**
     * Checks a bootable JAR installation by running two phases:
     * <ol>
     *   <li>Phase 1 — parses {@code META-INF/sbom/sbom.cdx.json} and checks only the CPE header
     *       (CHECKs 2–4 pass vacuously: no JARs on disk, no manifest).</li>
     *   <li>Phase 2 — unzips {@code wildfly.zip} to a temporary directory and runs all four
     *       checks against the extracted WildFly installation, then deletes the temp dir.</li>
     * </ol>
     *
     * @param bootableRoot path to the extracted bootable JAR directory (the directory that
     *                     contains {@code META-INF/}, {@code wildfly.zip}, etc.)
     * @return the combined bootable JAR check details; never {@code null}
     * @throws IllegalArgumentException if {@code META-INF/sbom/sbom.cdx.json} or
     *                                  {@code wildfly.zip} is not found under {@code bootableRoot}
     * @throws IOException if any file cannot be read or extracted
     * @throws org.cyclonedx.exception.ParseException if either SBOM file is malformed
     */
    public static BootableJarCheckDetails checkBootableJar(Path bootableRoot) throws Exception {
        var outerSbom = bootableRoot.resolve("META-INF/sbom/sbom.cdx.json");
        if (!Files.exists(outerSbom)) {
            return BootableJarCheckDetails.noSbom(bootableRoot);
        }
        var wildflyZip = bootableRoot.resolve("wildfly.zip");
        if (!Files.exists(wildflyZip)) {
            throw new IllegalArgumentException(
                    "wildfly.zip not found in: " + bootableRoot);
        }

        // Phase 1 — outer SBOM (CPE check only; other checks pass vacuously)
        var outerDetails = checkWithDetails(bootableRoot.resolve("META-INF/sbom"));

        // Phase 2 — unzip wildfly.zip, run full check, clean up
        var tempDir = Files.createTempDirectory("wildfly-sbom-check-");
        try {
            unzip(wildflyZip, tempDir);
            var innerDetails = checkWithDetails(tempDir);
            return new BootableJarCheckDetails(outerDetails, innerDetails);
        } finally {
            deleteRecursively(tempDir);
        }
    }

    /**
     * Runs all SBOM checks, optionally printing a summary to {@code System.out},
     * and returns a {@link SbomCheckDetails} containing both the check outcomes
     * and all intermediate data.
     *
     * @param installRoot path to the WildFly installation root
     * @param print       if {@code true}, prints a human-readable summary via
     *                    {@link SbomPrinter#print(SbomCheckDetails)} before returning
     * @return full check details; never {@code null}
     * @throws IOException if the installation tree or SBOM file cannot be read
     * @throws org.cyclonedx.exception.ParseException if the SBOM file is malformed
     */
    public static SbomCheckDetails checkWithDetails(Path installRoot, boolean print) throws Exception {
        var details = checkWithDetails(installRoot);
        if (print) SbomPrinter.print(details);
        return details;
    }

    /**
     * Runs all SBOM checks and returns a {@link SbomCheckDetails} containing both
     * the check outcomes and all intermediate data (parsed BOM, component lists,
     * manifest, shaded artifact grouping).
     *
     * @param installRoot path to the WildFly installation root
     * @return full check details; never {@code null}
     * @throws IOException if the installation tree or SBOM file cannot be read
     * @throws org.cyclonedx.exception.ParseException if the SBOM file is malformed
     */
    public static SbomCheckDetails checkWithDetails(Path installRoot) throws Exception {
        // ---- 1. Parse the SBOM -----------------------------------------
        var sbomFile = installRoot.resolve("sbom.cdx.json").toFile();
        if (!sbomFile.exists()) {
            return SbomCheckDetails.noSbom(installRoot);
        }

        var bom = new JsonParser().parse(sbomFile);

        // Collect all maven components from the SBOM (flatten the two-level tree).
        // pkg:npm sub-components (e.g. HAL console JS deps) are counted separately
        // but excluded from all checks.
        var mavenComponents = ComponentUtils.collectMavenComponents(bom.getComponents());

        // ---- 2. Scan the installation on disk --------------------------
        var installedJars = new InstallationScanner(installRoot).scan();

        // ---- 3. Read manifest.yaml (optional) --------------------------
        var manifest = ManifestReader.read(installRoot);

        // ---- Run checks ------------------------------------------------
        var diskFileNames = installedJars.stream()
                .map(InstalledArtifact::jarFileName)
                .collect(Collectors.toSet());
        var parentIndex = buildParentIndex(bom.getComponents());

        var cpeCheck = checkMetadataCpe(bom);
        var sbomVsDisk = checkSbomVsDisk(mavenComponents, installedJars, installRoot);
        var diskVsSbom = checkDiskVsSbom(installedJars, mavenComponents);
        var sbomVsManifest = checkSbomVsManifest(mavenComponents, manifest);
        var shadedResult = collectShadedArtifacts(mavenComponents, diskFileNames, parentIndex, manifest);

        var result = new SbomCheckResult(cpeCheck, sbomVsDisk, diskVsSbom, sbomVsManifest, false);
        return new SbomCheckDetails(result, installRoot, bom, mavenComponents, installedJars, manifest, shadedResult);
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /**
     * CHECK 1 — verifies that {@code metadata.component.cpe} is present and non-blank.
     */
    static CheckResult checkMetadataCpe(Bom bom) {
        var meta = bom.getMetadata();
        if (meta == null || meta.getComponent() == null) {
            return new CheckResult(List.of("No metadata.component defined in SBOM"));
        }
        var cpe = meta.getComponent().getCpe();
        if (cpe == null || cpe.isBlank()) {
            return new CheckResult(List.of("metadata.component.cpe is missing or blank"));
        }
        return new CheckResult(Collections.emptyList());
    }

    /**
     * Builds a map from each maven component's purl to the purl of its nearest
     * parent in the SBOM component tree.
     */
    static Map<String, String> buildParentIndex(List<Component> components) {
        var index = new java.util.LinkedHashMap<String, String>();
        parentChildPairs(components, null)
                .forEach(e -> index.put(e.getKey(), e.getValue()));
        return index;
    }

    private static Stream<Map.Entry<String, String>> parentChildPairs(
            List<Component> components, String parentPurl) {
        if (components == null) return Stream.empty();
        return components.stream()
                .flatMap(c -> {
                    String purl = c.getPurl();
                    Stream<Map.Entry<String, String>> self = purl != null && parentPurl != null
                            ? Stream.of(Map.entry(purl, parentPurl))
                            : Stream.empty();
                    return Stream.concat(self, parentChildPairs(c.getComponents(), purl));
                });
    }

    private static CheckResult checkSbomVsDisk(
            List<Component> sbomComponents, List<InstalledArtifact> installedJars, Path installRoot) {

        var diskFileNames = installedJars.stream()
                .map(InstalledArtifact::jarFileName)
                .collect(Collectors.toSet());
        var missing = new ArrayList<String>();

        for (Component c : sbomComponents) {
            switch (ComponentUtils.componentKind(c)) {
                case POM_DERIVED -> { /* nothing to check */ }
                case NATIVE_LIB -> ComponentUtils.nativeLibDir(c).ifPresent(libDir -> {
                    if (!Files.isDirectory(installRoot.resolve(libDir))) {
                        missing.add(c.getPurl() + " [native lib dir missing: " + libDir + "]");
                    }
                });
                case REGULAR_JAR -> {
                    if (ComponentUtils.isNonJarType(c)) break;
                    var fatJar = FAT_JAR_NAMES.get(c.getName());
                    if (fatJar != null) {
                        if (!Files.exists(installRoot.resolve(fatJar))) {
                            missing.add(c.getPurl() + " [expected: " + fatJar + "]");
                        }
                        break;
                    }
                    var expected = ComponentUtils.expectedJarFileName(c);
                    if (!diskFileNames.contains(expected)) {
                        missing.add(c.getPurl() + " [expected: " + expected + "]");
                    }
                }
            }
        }
        return new CheckResult(missing);
    }

    private static CheckResult checkDiskVsSbom(
            List<InstalledArtifact> installedJars, List<Component> sbomComponents) {

        var sbomFileNames = sbomComponents.stream()
                .filter(c -> ComponentUtils.componentKind(c) != ComponentKind.POM_DERIVED)
                .filter(c -> !ComponentUtils.isNonJarType(c))
                .map(c -> {
                    var fatJar = FAT_JAR_NAMES.get(c.getName());
                    return fatJar != null
                            ? Path.of(fatJar).getFileName().toString()
                            : ComponentUtils.expectedJarFileName(c);
                })
                .collect(Collectors.toSet());

        var reported = new HashSet<String>();
        var undeclared = installedJars.stream()
                .map(InstalledArtifact::jarFileName)
                .filter(name -> !sbomFileNames.contains(name))
                .filter(name -> !GENERIC_FAT_JAR_FILENAMES.contains(name))
                .filter(reported::add)
                .collect(Collectors.toList());

        return new CheckResult(undeclared);
    }

    private static CheckResult checkSbomVsManifest(
            List<Component> sbomComponents, Manifest manifest) {

        if (manifest.isEmpty()) {
            return new CheckResult(Collections.emptyList());
        }
        var issues = sbomComponents.stream()
                .filter(c -> ComponentUtils.componentKind(c) != ComponentKind.POM_DERIVED)
                .flatMap(c -> {
                    String coord = c.getGroup() + ":" + c.getName();
                    return manifest.version(c.getGroup(), c.getName())
                            .map(v -> v.equals(c.getVersion())
                                    ? Stream.<String>empty()
                                    : Stream.of("VERSION MISMATCH " + coord
                                            + " sbom=" + c.getVersion() + " manifest=" + v))
                            .orElseGet(() -> Stream.of("NOT IN MANIFEST " + coord
                                    + " (sbom: " + c.getVersion() + ")"));
                })
                .collect(Collectors.toList());

        return new CheckResult(issues);
    }

    // -----------------------------------------------------------------------
    // Shaded-artifact collection
    // -----------------------------------------------------------------------

    private static ShadedResult collectShadedArtifacts(
            List<Component> allMavenComponents, Set<String> diskFileNames,
            Map<String, String> parentIndex, Manifest manifest) {

        var grouped = new java.util.TreeMap<String, List<String>>();
        allMavenComponents.stream()
                .filter(c -> ComponentUtils.componentKind(c) == ComponentKind.POM_DERIVED)
                .filter(c -> !diskFileNames.contains(ComponentUtils.expectedJarFileName(c)))
                .filter(c -> {
                    var fatJar = FAT_JAR_NAMES.get(c.getName());
                    return fatJar == null || !diskFileNames.contains(Path.of(fatJar).getFileName().toString());
                })
                .filter(c -> manifest.version(c.getGroup(), c.getName())
                        .map(v -> !v.equals(c.getVersion()))
                        .orElse(true))
                .forEach(c -> {
                    var parent = parentIndex.getOrDefault(c.getPurl(), "(no parent)");
                    grouped.computeIfAbsent(parent, k -> new ArrayList<>()).add(c.getPurl());
                });
        grouped.values().forEach(Collections::sort);
        return new ShadedResult(Collections.unmodifiableMap(grouped));
    }

    // -----------------------------------------------------------------------
    // Bootable JAR helpers
    // -----------------------------------------------------------------------

    private static void unzip(Path zipFile, Path targetDir) throws IOException {
        try (var zf = new ZipFile(zipFile.toFile())) {
            var entries = zf.entries();
            while (entries.hasMoreElements()) {
                var entry = (ZipEntry) entries.nextElement();
                var entryPath = targetDir.resolve(entry.getName()).normalize();
                if (!entryPath.startsWith(targetDir)) {
                    throw new IOException("ZIP entry outside target directory: " + entry.getName());
                }
                if (entry.isDirectory()) {
                    Files.createDirectories(entryPath);
                } else {
                    Files.createDirectories(entryPath.getParent());
                    try (InputStream in = zf.getInputStream(entry)) {
                        Files.copy(in, entryPath);
                    }
                }
            }
        }
    }

    private static void deleteRecursively(Path dir) throws IOException {
        if (!Files.exists(dir)) return;
        try (var walk = Files.walk(dir)) {
            walk.sorted(java.util.Comparator.reverseOrder())
                    .forEach(p -> {
                        try { Files.delete(p); } catch (IOException ignored) {}
                    });
        }
    }
}
