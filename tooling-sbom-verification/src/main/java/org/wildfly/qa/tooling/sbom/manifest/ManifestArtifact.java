/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.qa.tooling.sbom.manifest;

/**
 * A single stream entry from {@code .installation/manifest.yaml}.
 *
 * @param groupId    Maven group ID
 * @param artifactId Maven artifact ID
 * @param version    resolved version
 */
public record ManifestArtifact(String groupId, String artifactId, String version) {}
