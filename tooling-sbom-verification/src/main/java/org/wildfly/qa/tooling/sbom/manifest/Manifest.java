/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.qa.tooling.sbom.manifest;

import java.util.Collections;
import java.util.List;
import java.util.Optional;

/**
 * The parsed contents of {@code .installation/manifest.yaml}, held as an
 * immutable list of {@link ManifestArtifact} records.
 *
 * <p>Use {@link #version(String, String)} for coordinate-based lookups, and
 * {@link #artifacts()} to iterate over all entries.</p>
 */
public final class Manifest {

    private static final Manifest EMPTY = new Manifest(Collections.emptyList());

    private final List<ManifestArtifact> artifacts;

    Manifest(List<ManifestArtifact> artifacts) {
        this.artifacts = Collections.unmodifiableList(artifacts);
    }

    /** Returns the empty manifest singleton (no {@code manifest.yaml} was found). */
    public static Manifest empty() {
        return EMPTY;
    }

    /** @return {@code true} when no {@code manifest.yaml} was found. */
    public boolean isEmpty() {
        return artifacts.isEmpty();
    }

    /** @return the number of stream entries. */
    public int size() {
        return artifacts.size();
    }

    /** @return all stream entries, in file order. */
    public List<ManifestArtifact> artifacts() {
        return artifacts;
    }

    /**
     * Returns the version recorded for the given coordinates, or an empty
     * {@link Optional} if no entry exists for that {@code groupId:artifactId}.
     *
     * @param groupId    Maven group ID
     * @param artifactId Maven artifact ID
     * @return version string wrapped in an {@link Optional}
     */
    public Optional<String> version(String groupId, String artifactId) {
        return artifacts.stream()
                .filter(a -> a.groupId().equals(groupId) && a.artifactId().equals(artifactId))
                .map(ManifestArtifact::version)
                .findFirst();
    }

    /**
     * Returns {@code true} if an entry exists for the given coordinates.
     *
     * @param groupId    Maven group ID
     * @param artifactId Maven artifact ID
     */
    public boolean contains(String groupId, String artifactId) {
        return artifacts.stream()
                .anyMatch(a -> a.groupId().equals(groupId) && a.artifactId().equals(artifactId));
    }
}
