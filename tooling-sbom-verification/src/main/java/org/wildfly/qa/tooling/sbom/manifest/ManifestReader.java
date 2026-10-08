/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.qa.tooling.sbom.manifest;

import org.yaml.snakeyaml.Yaml;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * Reads the Prospero {@code .installation/manifest.yaml} file and returns a
 * {@link Manifest} containing all stream entries as {@link ManifestArtifact} records.
 *
 * <p>The manifest uses the schema:</p>
 * <pre>
 * schemaVersion: "1.1.0"
 * streams:
 *   - groupId: "com.fasterxml.jackson.core"
 *     artifactId: "jackson-databind"
 *     version: "2.18.2"
 * </pre>
 */
public class ManifestReader {

    private ManifestReader() {}

    /**
     * Parses the manifest and returns a {@link Manifest} containing all stream entries.
     *
     * @param installRoot path to the WildFly installation root
     * @return parsed manifest; {@link Manifest#isEmpty()} is {@code true} if the file is absent
     * @throws IOException on I/O errors
     */
    @SuppressWarnings("unchecked")
    public static Manifest read(Path installRoot) throws IOException {
        var manifestPath = installRoot.resolve(".installation").resolve("manifest.yaml");
        if (!Files.exists(manifestPath)) {
            return Manifest.empty();
        }
        var yaml = new Yaml();
        try (var is = Files.newInputStream(manifestPath)) {
            var root = yaml.<Map<String, Object>>load(is);
            var streams =
                    (List<Map<String, String>>) root.getOrDefault("streams", Collections.emptyList());
            var artifacts = new ArrayList<ManifestArtifact>(streams.size());
            for (var entry : streams) {
                var groupId = entry.get("groupId");
                var artifactId = entry.get("artifactId");
                var version = entry.get("version");
                if (groupId != null && artifactId != null && version != null) {
                    artifacts.add(new ManifestArtifact(groupId, artifactId, version));
                }
            }
            return new Manifest(artifacts);
        }
    }
}
