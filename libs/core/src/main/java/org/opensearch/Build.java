/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

/*
 * Licensed to Elasticsearch under one or more contributor
 * license agreements. See the NOTICE file distributed with
 * this work for additional information regarding copyright
 * ownership. Elasticsearch licenses this file to you under
 * the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

/*
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch;

import org.opensearch.common.Booleans;
import org.opensearch.core.util.FileSystemUtils;

import java.io.IOException;
import java.net.URL;
import java.security.CodeSource;
import java.util.Objects;
import java.util.jar.JarInputStream;
import java.util.jar.Manifest;

/**
 * Information about a build of OpenSearch.
 * 构建插件下载 URL 时需要版本号
 * 验证插件兼容性时需要知道当前版本
 * 区分快照版本和正式版本以决定下载哪个插件
 * @opensearch.internal
 */
public class Build {
    /**
     * The current build of OpenSearch. Filled with information scanned at
     * startup from the jar.
     */
    // 当前运行的 OpenSearch 构建实例，在静态代码块中初始化。
    public static final Build CURRENT;

    /**
     * The type of build
     *
     * @opensearch.internal
     */
    public enum Type {

        DEB("deb"),  // Debian 包
        DOCKER("docker"),  // Docker 镜像
        RPM("rpm"), // RPM 包
        TAR("tar"), // Tar 压缩包
        ZIP("zip"),  // ZIP 压缩包
        UNKNOWN("unknown");  // 未知类型

        final String displayName;

        // 返回类型的显示名称。
        public String displayName() {
            return displayName;
        }

        // 私有构造函数，初始化显示名称
        Type(final String displayName) {
            this.displayName = displayName;
        }

        /**
         * 根据显示名称转换为 Type 枚举值
         * 匹配已知的类型名称返回对应枚举值
         * 严格模式下遇到未知类型抛出异常
         * 非严格模式下返回 UNKNOWN
         * @param displayName   显示名称字符串
         * @param strict        是否严格模式
         * @return
         */
        public static Type fromDisplayName(final String displayName, final boolean strict) {
            switch (displayName) {
                case "deb":
                    return Type.DEB;
                case "docker":
                    return Type.DOCKER;
                case "rpm":
                    return Type.RPM;
                case "tar":
                    return Type.TAR;
                case "zip":
                    return Type.ZIP;
                case "unknown":
                    return Type.UNKNOWN;
                default:
                    if (strict) {
                        throw new IllegalStateException("unexpected distribution type [" + displayName + "]; your distribution is broken");
                    } else {
                        return Type.UNKNOWN;
                    }
            }
        }

    }

    static {
        final Type type;
        final String hash;
        final String date;
        final boolean isSnapshot;
        final String version;
        final String distribution = "opensearch";

        // these are parsed at startup, and we require that we are able to recognize the values passed in by the startup scripts
        type = Type.fromDisplayName(System.getProperty("opensearch.distribution.type", "unknown"), true);

        // 判断是否从正式的 OpenSearch JAR 文件运行（不是测试或 IDE 环境）。
        final String opensearchPrefix = distribution;
        final URL url = getOpenSearchCodeSourceLocation();
        final String urlStr = url == null ? "" : url.toString();
        if (urlStr.startsWith("file:/")
            && (urlStr.endsWith(opensearchPrefix + "-" + Version.CURRENT + ".jar")
                || urlStr.matches(
                    "(.*)" + opensearchPrefix + "(-)?(.*?)" + Version.CURRENT + "(-)?((alpha|beta|rc)[0-9]+)?(-SNAPSHOT)?.jar"
                ))) {
            try (JarInputStream jar = new JarInputStream(FileSystemUtils.openFileURLStream(url))) {
                Manifest manifest = jar.getManifest();
                hash = manifest.getMainAttributes().getValue("Change"); // Change：Git 提交哈希
                date = manifest.getMainAttributes().getValue("Build-Date"); // Build-Date：构建日期
                isSnapshot = "true".equals(manifest.getMainAttributes().getValue("X-Compile-OpenSearch-Snapshot")); // X-Compile-OpenSearch-Snapshot：是否为快照版本
                version = manifest.getMainAttributes().getValue("X-Compile-OpenSearch-Version"); // X-Compile-OpenSearch-Version：编译版本
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        } else { // 处理测试、IDE 等非正式环境的场景。
            // not running from the official opensearch jar file (unit tests, IDE, uber client jar, shadiness)
            hash = "unknown";
            date = "unknown";
            version = Version.CURRENT.toString();
            final String buildSnapshot = System.getProperty("build.snapshot");
            if (buildSnapshot != null) {
                try {
                    Class.forName("com.carrotsearch.randomizedtesting.RandomizedContext");
                } catch (final ClassNotFoundException e) {
                    // we are not in tests but build.snapshot is set, bail hard
                    throw new IllegalStateException("build.snapshot set to [" + buildSnapshot + "] but not running tests");
                }
                isSnapshot = Booleans.parseBoolean(buildSnapshot);
            } else {
                isSnapshot = true;
            }
        }
        // 确保关键信息存在，否则阻止系统启动（防止出现难以调试的问题）。
        if (hash == null) {
            throw new IllegalStateException(
                "Error finding the build hash. "
                    + "Stopping OpenSearch now so it doesn't run in subtly broken ways. This is likely a build bug."
            );
        }
        if (date == null) {
            throw new IllegalStateException(
                "Error finding the build date. "
                    + "Stopping OpenSearch now so it doesn't run in subtly broken ways. This is likely a build bug."
            );
        }
        if (version == null) {
            throw new IllegalStateException(
                "Error finding the build version. "
                    + "Stopping OpenSearch now so it doesn't run in subtly broken ways. This is likely a build bug."
            );
        }

        CURRENT = new Build(type, hash, date, isSnapshot, version, distribution);
    }

    // 是否为快照版本
    private final boolean isSnapshot;

    /**
     * The location of the code source for OpenSearch
     *
     * @return the location of the code source for OpenSearch which may be null
     */
    // 功能：获取 OpenSearch 类的代码源位置（JAR 文件路径）
    // 用途：用于判断是在正式环境还是测试环境中运行
    static URL getOpenSearchCodeSourceLocation() {
        final CodeSource codeSource = Build.class.getProtectionDomain().getCodeSource();
        return codeSource == null ? null : codeSource.getLocation();
    }

    // 分发包类型
    private final Type type;
    // Git 提交哈希
    private final String hash;
    // 构建日期
    private final String date;
    // 版本号
    private final String version;
    // 发行版名称
    private final String distribution;

    public Build(final Type type, final String hash, final String date, boolean isSnapshot, String version, String distribution) {
        this.type = type;
        this.hash = hash;
        this.date = date;
        this.isSnapshot = isSnapshot;
        this.version = version;
        this.distribution = distribution;
    }

    public String hash() {
        return hash;
    }

    public String date() {
        return date;
    }

    /**
     * Get the distribution name (expected to be OpenSearch; empty if legacy; something else if forked)
     * @return distribution name as a string
     */
    // 返回发行版名称（通常是"opensearch"）
    public String getDistribution() {
        return distribution;
    }

    /**
     * Get the version as considered at build time
     * <p>
     * Offers a way to get the fully qualified version as configured by the build.
     * This will be the same as {@link Version} for production releases, but may include on of the qualifier ( e.x alpha1 )
     * or -SNAPSHOT for others.
     *
     * @return the fully qualified build
     */
    // 返回完整的版本号，可能包含 alpha、beta、rc 等限定符或 SNAPSHOT 标记。
    public String getQualifiedVersion() {
        return version;
    }

    // 返回分发包类型
    public Type type() {
        return type;
    }

    // 判断是否为快照版本。
    public boolean isSnapshot() {
        return isSnapshot;
    }

    /**
     * Provides information about the intent of the build
     *
     * @return true if the build is intended for production use
     */
    // 功能：判断是否为生产发布版本
    //逻辑：使用正则表达式匹配语义化版本号格式（如 2.11.0），不包含 SNAPSHOT 或预发布标记
    public boolean isProductionRelease() {
        return version.matches("[0-9]+\\.[0-9]+\\.[0-9]+");
    }

    // 返回格式化的构建信息字符串，例如：[tar][abc123][2023-10-01][2.11.0]
    @Override
    public String toString() {
        return "[" + type.displayName + "][" + hash + "][" + date + "][" + version + "]";
    }

    // 比较两个 Build 对象是否相等，需要所有字段都相同。
    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }

        Build build = (Build) o;

        if (!type.equals(build.type)) {
            return false;
        }

        if (isSnapshot != build.isSnapshot) {
            return false;
        }
        if (hash.equals(build.hash) == false) {
            return false;
        }
        if (version.equals(build.version) == false) {
            return false;
        }
        return date.equals(build.date);
    }

    // 返回 Build 对象的哈希码，用于比较相等性。
    @Override
    public int hashCode() {
        return Objects.hash(type, isSnapshot, hash, date, version);
    }

}
