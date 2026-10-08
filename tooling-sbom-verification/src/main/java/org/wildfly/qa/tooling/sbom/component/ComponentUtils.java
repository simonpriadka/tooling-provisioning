/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.qa.tooling.sbom.component;

import org.cyclonedx.model.Component;
import org.cyclonedx.model.component.evidence.Method;
import org.cyclonedx.model.component.evidence.Occurrence;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Utility methods for inspecting and classifying CycloneDX {@link Component} objects.
 */
public final class ComponentUtils {

    private ComponentUtils() {}

    /**
     * Classifies a component for installation verification purposes.
     *
     * <ul>
     *   <li>{@link ComponentKind#POM_DERIVED} — only {@code maven-pom-analysis} evidence and no
     *       occurrences; never installed as a standalone file.</li>
     *   <li>{@link ComponentKind#NATIVE_LIB} — all occurrences end with {@code /lib}; installed
     *       as a shared library.</li>
     *   <li>{@link ComponentKind#REGULAR_JAR} — everything else.</li>
     * </ul>
     */
    public static ComponentKind componentKind(Component c) {
        var ev = c.getEvidence();
        if (ev == null) return ComponentKind.REGULAR_JAR;

        var occurrences = ev.getOccurrences();
        if (occurrences != null && !occurrences.isEmpty()) {
            var allLib = occurrences.stream()
                    .allMatch(o -> o.getLocation() != null && o.getLocation().endsWith("/lib"));
            return allLib ? ComponentKind.NATIVE_LIB : ComponentKind.REGULAR_JAR;
        }

        var identities = ev.getIdentities();
        if (identities != null && !identities.isEmpty()) {
            var allPomDerived = identities.stream().allMatch(id -> {
                var methods = id.getMethods();
                if (methods == null || methods.isEmpty()) return false;
                return methods.stream().allMatch(m ->
                        m.getTechnique() == Method.Technique.MANIFEST_ANALYSIS
                                && "maven-pom-analysis".equals(m.getValue()));
            });
            if (allPomDerived) return ComponentKind.POM_DERIVED;
        }
        return ComponentKind.REGULAR_JAR;
    }

    /**
     * Returns the relative path of the native lib directory from the first matching
     * occurrence, or an empty {@link Optional} if none is found.
     */
    public static Optional<String> nativeLibDir(Component c) {
        var ev = c.getEvidence();
        if (ev == null || ev.getOccurrences() == null) return Optional.empty();
        return ev.getOccurrences().stream()
                .map(Occurrence::getLocation)
                .filter(loc -> loc != null && loc.endsWith("/lib"))
                .findFirst();
    }

    /**
     * Builds the expected on-disk JAR filename from a component's SBOM metadata:
     * {@code <name>-<version>[-<classifier>].jar}.
     */
    public static String expectedJarFileName(Component c) {
        var versionSuffix = purlClassifier(c.getPurl())
                .filter(cl -> !cl.isBlank())
                .map(cl -> c.getVersion() + "-" + cl)
                .orElse(c.getVersion());
        return c.getName() + "-" + versionSuffix + ".jar";
    }

    /**
     * Returns {@code true} when the purl declares a {@code type} qualifier that is not
     * {@code jar} (e.g. {@code type=txt}).
     */
    public static boolean isNonJarType(Component c) {
        var purl = c.getPurl();
        if (purl == null) return false;
        var q = purl.indexOf('?');
        if (q < 0) return false;
        return Arrays.stream(purl.substring(q + 1).split("&"))
                .anyMatch(p -> p.startsWith("type=") && !p.equals("type=jar"));
    }

    /** Recursively flattens a component tree into a single stream of all components. */
    public static Stream<Component> collectAllComponents(List<Component> components) {
        if (components == null) return Stream.empty();
        return components.stream()
                .flatMap(c -> Stream.concat(Stream.of(c), collectAllComponents(c.getComponents())));
    }

    /** Recursively collects all maven-coordinate components from the SBOM component tree. */
    public static List<Component> collectMavenComponents(List<Component> components) {
        if (components == null) return Collections.emptyList();
        return collectAllComponents(components)
                .filter(c -> c.getPurl() != null && c.getPurl().startsWith("pkg:maven/"))
                .collect(Collectors.toList());
    }

    /** Recursively counts all components whose purl starts with the given scheme. */
    public static long countByPurlScheme(List<Component> components, String scheme) {
        if (components == null) return 0;
        return collectAllComponents(components)
                .filter(c -> c.getPurl() != null && c.getPurl().startsWith(scheme))
                .count();
    }

    /**
     * Extracts the {@code classifier} query parameter from a purl, or an empty
     * {@link Optional} if absent.
     */
    public static Optional<String> purlClassifier(String purl) {
        if (purl == null) return Optional.empty();
        var q = purl.indexOf('?');
        if (q < 0) return Optional.empty();
        return Arrays.stream(purl.substring(q + 1).split("&"))
                .filter(p -> p.startsWith("classifier="))
                .map(p -> p.substring("classifier=".length()))
                .findFirst();
    }
}
