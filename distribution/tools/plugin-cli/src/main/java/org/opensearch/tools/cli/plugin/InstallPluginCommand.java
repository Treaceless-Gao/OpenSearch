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
 *    http://www.apache.org/licenses/LICENSE-2.0
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

package org.opensearch.tools.cli.plugin;

import joptsimple.OptionSet;
import joptsimple.OptionSpec;
import org.apache.commons.compress.archivers.zip.ZipArchiveEntry;
import org.apache.commons.compress.archivers.zip.ZipFile;
import org.apache.lucene.search.spell.LevenshteinDistance;
import org.apache.lucene.util.CollectionUtil;
import org.apache.lucene.util.Constants;
import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
import org.opensearch.Build;
import org.opensearch.Version;
import org.opensearch.cli.ExitCodes;
import org.opensearch.cli.Terminal;
import org.opensearch.cli.UserException;
import org.opensearch.common.SuppressForbidden;
import org.opensearch.common.bootstrap.JarHell;
import org.opensearch.common.cli.EnvironmentAwareCommand;
import org.opensearch.common.collect.Tuple;
import org.opensearch.common.hash.MessageDigests;
import org.opensearch.common.util.io.IOUtils;
import org.opensearch.env.Environment;
import org.opensearch.plugins.Platforms;
import org.opensearch.plugins.PluginInfo;
import org.opensearch.plugins.PluginsService;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Collectors;

import static org.opensearch.cli.Terminal.Verbosity.VERBOSE;

/**
 * A command for the plugin cli to install a plugin into opensearch.
 * <p>
 * The install command takes a plugin id, which may be any of the following:
 * <ul>
 * <li>An official opensearch plugin name</li>
 * <li>Maven coordinates to a plugin zip</li>
 * <li>A URL to a plugin zip</li>
 * </ul>
 *
 * Plugins are packaged as zip files. Each packaged plugin must contain a plugin properties file.
 * See {@link PluginInfo}.
 * <p>
 * The installation process first extracts the plugin files into a temporary
 * directory in order to verify the plugin satisfies the following requirements:
 * <ul>
 * <li>Jar hell does not exist, either between the plugin's own jars, or with opensearch</li>
 * <li>The plugin is not a module already provided with opensearch</li>
 * <li>If the plugin contains extra security permissions, the policy file is validated</li>
 * </ul>
 * <p>
 * A plugin may also contain an optional {@code bin} directory which contains scripts. The
 * scripts will be installed into a subdirectory of the opensearch bin directory, using
 * the name of the plugin, and the scripts will be marked executable.
 * <p>
 * A plugin may also contain an optional {@code config} directory which contains configuration
 * files specific to the plugin. The config files be installed into a subdirectory of the
 * opensearch config directory, using the name of the plugin. If any files to be installed
 * already exist, they will be skipped.
 */
class InstallPluginCommand extends EnvironmentAwareCommand {

    // exit codes for install
    /** A plugin with the same name is already installed. */
    static final int PLUGIN_EXISTS = 1;
    /** The plugin zip is not properly structured. */
    static final int PLUGIN_MALFORMED = 2;

    /** The builtin modules, which are plugins, but cannot be installed or removed. */
    static final Set<String> MODULES;
    static {
        try (
            InputStream stream = InstallPluginCommand.class.getResourceAsStream("/modules.txt");
            BufferedReader reader = new BufferedReader(new InputStreamReader(stream, StandardCharsets.UTF_8))
        ) {
            Set<String> modules = new HashSet<>();
            String line = reader.readLine();
            while (line != null) {
                modules.add(line.trim());
                line = reader.readLine();
            }
            MODULES = Collections.unmodifiableSet(modules);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    /** The official plugins that can be installed simply by name. */
    static final Set<String> OFFICIAL_PLUGINS = Collections.emptySet();
    /*static final Set<String> OFFICIAL_PLUGINS;
    static {
        try (
            InputStream stream = InstallPluginCommand.class.getResourceAsStream("/plugins.txt");
            BufferedReader reader = new BufferedReader(new InputStreamReader(stream, StandardCharsets.UTF_8))
        ) {
            Set<String> plugins = new TreeSet<>(); // use tree set to get sorting for help command
            String line = reader.readLine();
            while (line != null) {
                plugins.add(line.trim());
                line = reader.readLine();
            }
            OFFICIAL_PLUGINS = Collections.unmodifiableSet(plugins);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }*/

    private final OptionSpec<Void> batchOption;
    private final OptionSpec<String> arguments;

    static final Set<PosixFilePermission> BIN_DIR_PERMS;
    static final Set<PosixFilePermission> BIN_FILES_PERMS;
    static final Set<PosixFilePermission> CONFIG_DIR_PERMS;
    static final Set<PosixFilePermission> CONFIG_FILES_PERMS;
    static final Set<PosixFilePermission> PLUGIN_DIR_PERMS;
    static final Set<PosixFilePermission> PLUGIN_FILES_PERMS;

    static {
        // Bin directory get chmod 755
        BIN_DIR_PERMS = Collections.unmodifiableSet(PosixFilePermissions.fromString("rwxr-xr-x"));

        // Bin files also get chmod 755
        BIN_FILES_PERMS = BIN_DIR_PERMS;

        // Config directory get chmod 750
        CONFIG_DIR_PERMS = Collections.unmodifiableSet(PosixFilePermissions.fromString("rwxr-x---"));

        // Config files get chmod 660
        CONFIG_FILES_PERMS = Collections.unmodifiableSet(PosixFilePermissions.fromString("rw-rw----"));

        // Plugin directory get chmod 755
        PLUGIN_DIR_PERMS = BIN_DIR_PERMS;

        // Plugins files get chmod 644
        PLUGIN_FILES_PERMS = Collections.unmodifiableSet(PosixFilePermissions.fromString("rw-r--r--"));
    }

    InstallPluginCommand() {
        super("Install a plugin");
        this.batchOption = parser.acceptsAll(
            Arrays.asList("b", "batch"),
            "Enable batch mode explicitly, automatic confirmation of security permission"
        );
        this.arguments = parser.nonOptions("plugin <name|Zip File|URL>");
    }

    @Override
    protected void printAdditionalHelp(Terminal terminal) {
        terminal.println("Plugins are packaged as zip files. Each packaged plugin must contain a plugin properties file.");
        terminal.println("");

        // List possible plugin id inputs
        terminal.println("The install command takes a plugin id, which may be any of the following:");
        terminal.println("  An official opensearch plugin name");
        terminal.println("  Maven coordinates to a plugin zip");
        terminal.println("  A URL to a plugin zip");
        terminal.println("  A local zip file");
        terminal.println("");

        // List official opensearch plugin names
        /*terminal.println("The following official plugins may be installed by name:");
        for (String plugin : OFFICIAL_PLUGINS) {
            terminal.println("  " + plugin);
        }
        terminal.println("");*/
    }

    @Override
    protected void execute(Terminal terminal, OptionSet options, Environment env) throws Exception {
        List<String> pluginId = arguments.values(options);
        final boolean isBatch = options.has(batchOption);
        execute(terminal, pluginId, isBatch, env);
    }

    // pkg private for testing

    /**
     * @param terminal
     * @param pluginIds 要安装的插件 ID 列表（可以是多个）
     * @param isBatch   是否批处理模式 （无交互）
     * @param env       环境配置对象，包含临时目录和插件目录路径
     * @throws Exception
     */
    void execute(Terminal terminal, List<String> pluginIds, boolean isBatch, Environment env) throws Exception {
        if (pluginIds.isEmpty()) {
            throw new UserException(ExitCodes.USAGE, "at least one plugin id is required");
        }
        // 防止重复安装同一个插件造成资源浪费和潜在冲突。
        final Set<String> uniquePluginIds = new HashSet<>(); // 用于存储唯一id
        for (final String pluginId : pluginIds) { // 遍历所有传入的插件id
            if (uniquePluginIds.add(pluginId) == false) { // 将插件id添加到集合中，如果返回false则说明该插件id已经存在，则抛出异常
                throw new UserException(ExitCodes.USAGE, "duplicate plugin id [" + pluginId + "]");
            }
        }
        // key 为插件id，value 为该插件id对应的删除列表 如果安装失败，需要清理所有已创建的文件
        final Map<String, List<Path>> deleteOnFailures = new LinkedHashMap<>(); // 使用 LinkedHashMap 保持插入顺序
        for (final String pluginId : pluginIds) {
            terminal.println("-> Installing " + pluginId);  // 输出正在安装的插件id 输出安装开始信息
            try {
                final List<Path> deleteOnFailure = new ArrayList<>(); // 初始化当前插件的回滚列表 为当前插件创建一个空的路径列表，用于记录安装过程中创建的所有文件。
                deleteOnFailures.put(pluginId, deleteOnFailure);    // 立即将解压后的路径加入回滚列表，如果后续失败需要删除这个目录。

                final Path pluginZip = download(terminal, pluginId, env.tmpDir(), isBatch); // 从网络或本地下载插件包到临时目录。
                final Path extractedZip = unzip(pluginZip, env.pluginsDir());  // 将下载的 ZIP 文件解压到插件目录。
                deleteOnFailure.add(extractedZip); // 将解压后的路径加入回滚列表，如果后续失败需要删除这个目录。
                final PluginInfo pluginInfo = installPlugin(terminal, isBatch, extractedZip, env, deleteOnFailure);
                terminal.println("-> Installed " + pluginInfo.getName() + " with folder name " + pluginInfo.getTargetFolderName());
                // swap the entry by plugin id for one with the installed plugin name, it gives a cleaner error message for URL installs
                deleteOnFailures.remove(pluginId); // 删除之前添加的插件id
                deleteOnFailures.put(pluginInfo.getName(), deleteOnFailure); // 安装成功后知道了插件的实际的插件名称，替换为实际的插件名称，便于错误消息显示
            } catch (final Exception installProblem) {
                terminal.println("-> Failed installing " + pluginId); // 安装失败，输出安装失败信息
                // 遍历回滚映射中的每个条目
                // 包括当前失败的插件和之前成功安装的其他插件
                for (final Map.Entry<String, List<Path>> deleteOnFailureEntry : deleteOnFailures.entrySet()) {
                    terminal.println("-> Rolling back " + deleteOnFailureEntry.getKey());
                    // 初始化成功标志为 false
                    boolean success = false;
                    try {
                        // 调用工具方法删除所有记录的文件和目录；转换为数组是因为 rm() 方法接受可变参数
                        IOUtils.rm(deleteOnFailureEntry.getValue().toArray(new Path[0]));
                        // 如果删除成功，设置标志为 true
                        success = true;
                    } catch (final IOException exceptionWhileRemovingFiles) { // 创建新的异常，说明回滚哪个插件失败了
                        final Exception exception = new Exception(
                            "failed rolling back installation of [" + deleteOnFailureEntry.getKey() + "]",
                            exceptionWhileRemovingFiles
                        );
                        // 将回滚的异常作为被抑制的异常附加到原异常上；这样不会丢失原始错误信息，同时记录回滚问题
                        installProblem.addSuppressed(exception);
                        // 输出回滚失败信息
                        terminal.println("-> Failed rolling back " + deleteOnFailureEntry.getKey());
                    }
                    // 回滚成功，输出确认信息
                    if (success) {
                        terminal.println("-> Rolled back " + deleteOnFailureEntry.getKey());
                    }
                }
                // 抛出原始异常，即安装时候的异常，确保调用者知道安装失败了
                throw installProblem;
            }
        }
    }

    /** Downloads the plugin and returns the file it was downloaded to. */
    private Path download(Terminal terminal, String pluginId, Path tmpDir, boolean isBatch) throws Exception {

        if (OFFICIAL_PLUGINS.contains(pluginId)) {
            // 若插件是官方插件，这调用getOpenSearchUrl获取插件地址
            final String url = getOpenSearchUrl(terminal, Version.CURRENT, isSnapshot(), pluginId, Platforms.PLATFORM_NAME);
            // 在终端显示下载进度，插件id，下载与opensearch
            terminal.println("-> Downloading " + pluginId + " from opensearch");
            // 调用downloadAndValidate下载插件
            return downloadAndValidate(terminal, url, tmpDir, true, isBatch);
        }

        // now try as maven coordinates, a valid URL would only have a colon and slash
        // maven 坐标下载
        String[] coordinates = pluginId.split(":");
        if (coordinates.length == 3 && pluginId.contains("/") == false && pluginId.startsWith("file:") == false) {
            /*
             *  调用getMavenUrl方法生成Maven中央仓库的插件下载URL。
             * 它传入终端对象、坐标数组和平台名称，构建标准的Maven仓库URL格式，用于从Maven中央仓库下载OpenSearch插件
             * */
            String mavenUrl = getMavenUrl(terminal, coordinates, Platforms.PLATFORM_NAME);
            terminal.println("-> Downloading " + pluginId + " from maven central");
            return downloadAndValidate(terminal, mavenUrl, tmpDir, false, isBatch);
        }

        // fall back to plain old URL
        // 检查插件是否包含冒号，如果不包含则认为是插件名称
        if (pluginId.contains(":") == false) {
            // definitely not a valid url, so assume it is a plugin name
            // 调用checkMisspelledPlugin寻找相似的官方插件名称
            String msg = "Unknown plugin " + pluginId + ". No official plugins available in this build.";
//            List<String> plugins = checkMisspelledPlugin(pluginId);
            // 构建错误消息并抛出异常
//            String msg = "Unknown plugin " + pluginId;
//            if (plugins.isEmpty() == false) {
//                msg += ", did you mean " + (plugins.size() == 1 ? "[" + plugins.get(0) + "]" : "any of " + plugins.toString()) + "?";
//            }
            throw new UserException(ExitCodes.USAGE, msg);
        }
        /* 这行代码的功能是：在终端上打印下载提示信息，显示正在下载的插件URL。
         * URLDecoder.decode()方法将URL编码的字符串解码为原始字符，确保特殊字符正确显示
         * */
        terminal.println("-> Downloading " + URLDecoder.decode(pluginId, "UTF-8"));
        // 调用downloadZip下载插件
        return downloadZip(terminal, pluginId, tmpDir, isBatch);
    }

    boolean isSnapshot() {
        return Build.CURRENT.isSnapshot();
    }

    /** Returns the url for an official opensearch plugin. */
    private String getOpenSearchUrl(
        final Terminal terminal,
        final Version version,
        final boolean isSnapshot,
        final String pluginId,
        final String platform
    ) throws IOException, UserException {
        final String baseUrl;
        if (isSnapshot == true) {
            baseUrl = String.format(
                Locale.ROOT,
                "https://artifacts.opensearch.org/snapshots/plugins/%s/%s",
                pluginId,
                Build.CURRENT.getQualifiedVersion()
            );
        } else {
            baseUrl = String.format(
                Locale.ROOT,
                "https://artifacts.opensearch.org/releases/plugins/%s/%s",
                pluginId,
                Build.CURRENT.getQualifiedVersion()
            );
        }
        final String platformUrl = String.format(
            Locale.ROOT,
            "%s/%s-%s-%s.zip",
            baseUrl,
            pluginId,
            platform,
            Build.CURRENT.getQualifiedVersion()
        );
        if (urlExists(terminal, platformUrl)) {
            return platformUrl;
        }
        return String.format(Locale.ROOT, "%s/%s-%s.zip", baseUrl, pluginId, Build.CURRENT.getQualifiedVersion());
    }

    /** Returns the url for an opensearch plugin in maven. */
    // 根据坐标获取maven仓库的插件下载URL
    private String getMavenUrl(Terminal terminal, String[] coordinates, String platform) throws IOException {
        // 解析坐标数组获取groupId、artifactId和version
        final String groupId = coordinates[0].replace(".", "/");
        final String artifactId = coordinates[1];
        final String version = coordinates[2];
        // 然后构造基础URL
        final String baseUrl = String.format(Locale.ROOT, "https://repo1.maven.org/maven2/%s/%s/%s", groupId, artifactId, version);
        // 尝试构建特定平台的ZIP文件URL，如果该URL存在则返回，否则返回通用版本的ZIP文件URL
        final String platformUrl = String.format(Locale.ROOT, "%s/%s-%s-%s.zip", baseUrl, artifactId, platform, version);
        if (urlExists(terminal, platformUrl)) {
            return platformUrl;
        }
        // 返回通用版本的ZIP文件URL
        return String.format(Locale.ROOT, "%s/%s-%s.zip", baseUrl, artifactId, version);
    }

    /**
     * Returns {@code true} if the given url exists, and {@code false} otherwise.
     * <p>
     * The given url must be {@code https} and existing means a {@code HEAD} request returns 200.
     */
    // pkg private for tests to manipulate
    @SuppressForbidden(reason = "Make HEAD request using URLConnection.connect()")
    boolean urlExists(Terminal terminal, String urlString) throws IOException {
        terminal.println(VERBOSE, "Checking if url exists: " + urlString);
        URL url = URI.create(urlString).toURL();
        assert "https".equals(url.getProtocol()) : "Use of https protocol is required";
        HttpURLConnection urlConnection = (HttpURLConnection) url.openConnection();
        urlConnection.addRequestProperty("User-Agent", "opensearch-plugin-installer");
        urlConnection.setRequestMethod("HEAD");
        urlConnection.connect();
        return urlConnection.getResponseCode() == 200;
    }

    /** Returns all the official plugin names that look similar to pluginId. **/
    private List<String> checkMisspelledPlugin(String pluginId) {
        LevenshteinDistance ld = new LevenshteinDistance();
        List<Tuple<Float, String>> scoredKeys = new ArrayList<>();
        for (String officialPlugin : OFFICIAL_PLUGINS) {
            float distance = ld.getDistance(pluginId, officialPlugin);
            if (distance > 0.7f) {
                scoredKeys.add(new Tuple<>(distance, officialPlugin));
            }
        }
        CollectionUtil.timSort(scoredKeys, (a, b) -> b.v1().compareTo(a.v1()));
        return scoredKeys.stream().map((a) -> a.v2()).collect(Collectors.toList());
    }

    /** Downloads a zip from the url, into a temp file under the given temp dir. */
    // pkg private for tests
    // 这是一个下载ZIP文件的方法，支持进度显示和批处理两种模式，主要用于OpenSearch插件的在线安装功能
    @SuppressForbidden(reason = "We use getInputStream to download plugins") // 抑制安全检查警告
    Path downloadZip(Terminal terminal, String urlString, Path tmpDir, boolean isBatch) throws IOException {
        // 打印提示信息
        terminal.println(VERBOSE, "Retrieving zip from " + urlString);
        // 将传入的URL字符串转换为URL对象
        URL url = URI.create(urlString).toURL();
        // 创建一个临时文件，用于保存下载的zip文件
        Path zip = Files.createTempFile(tmpDir, null, ".zip");
        // 建立到目标URL的连接，创建URLConnection对象用于网络通信。
        URLConnection urlConnection = url.openConnection();
        // 设置HTTP请求头中的User-Agent字段，标识自己是OpenSearch插件安装器，这有助于服务器识别客户端身份
        urlConnection.addRequestProperty("User-Agent", "opensearch-plugin-installer");
        try (
            // 如果是批处理模式(isBatch=true)：直接使用原始的getInputStream()
            // 如果不是批处理模式：包装成TerminalProgressInputStream，用于显示下载进度
            // getContentLength()获取文件总大小用于进度计算
            InputStream in = isBatch
                ? urlConnection.getInputStream()
                : new TerminalProgressInputStream(urlConnection.getInputStream(), urlConnection.getContentLength(), terminal)
        ) {
            // must overwrite since creating the temp file above actually created the file
            // 复制数据到临时文件
            // 必须使用覆盖选项，因为之前创建临时文件时实际已经创建了空文件
            // StandardCopyOption.REPLACE_EXISTING表示如果目标文件已存在，则覆盖它
            Files.copy(in, zip, StandardCopyOption.REPLACE_EXISTING);
        }
        // 返回创建的zip文件路径
        return zip;
    }

    /**
     * content length might be -1 for unknown and progress only makes sense if the content length is greater than 0
     */
    private class TerminalProgressInputStream extends ProgressInputStream {

        private final Terminal terminal;
        private int width = 50;
        private final boolean enabled;

        TerminalProgressInputStream(InputStream is, int expectedTotalSize, Terminal terminal) {
            super(is, expectedTotalSize);
            this.terminal = terminal;
            this.enabled = expectedTotalSize > 0;
        }

        @Override
        public void onProgress(int percent) {
            if (enabled) {
                int currentPosition = percent * width / 100;
                StringBuilder sb = new StringBuilder("\r[");
                sb.append(String.join("=", Collections.nCopies(currentPosition, "")));
                if (currentPosition > 0 && percent < 100) {
                    sb.append(">");
                }
                sb.append(String.join(" ", Collections.nCopies(width - currentPosition, "")));
                sb.append("] %s   ");
                if (percent == 100) {
                    sb.append("\n");
                }
                terminal.print(Terminal.Verbosity.NORMAL, String.format(Locale.ROOT, sb.toString(), percent + "%"));
            }
        }
    }

    @SuppressForbidden(reason = "URL#openStream")
    private InputStream urlOpenStream(final URL url) throws IOException {
        return url.openStream();
    }

    /**
     * Downloads a ZIP from the URL. This method also validates the downloaded plugin ZIP via the following means:
     * 下载并验证插件的完整性和真实性
     * <ul>
     * <li>
     * For an official plugin we download the SHA-512 checksum and validate the integrity of the downloaded ZIP. We also download the
     * armored signature and validate the authenticity of the downloaded ZIP.
     * </li>
     * <li>
     * For a non-official plugin we download the SHA-512 checksum and fallback to the SHA-1 checksum and validate the integrity of the
     * downloaded ZIP.
     * </li>
     * </ul>
     *
     * @param terminal       a terminal to log messages to
     * @param urlString      the URL of the plugin ZIP
     * @param tmpDir         a temporary directory to write downloaded files to 临时目录路径
     * @param officialPlugin true if the plugin is an official plugin  是否为官方插件 (决定是否需要 PGP 签名验证)
     * @param isBatch        true if the install is running in batch mode 是否批处理模式(无交互)
     * @return the path to the downloaded plugin ZIP
     * @throws IOException   if an I/O exception occurs download or reading files and resources
     * @throws PGPException  if an exception occurs verifying the downloaded ZIP signature
     * @throws UserException if checksum validation fails
     */
    private Path downloadAndValidate(
        final Terminal terminal,
        final String urlString,
        final Path tmpDir,
        final boolean officialPlugin,
        boolean isBatch
    ) throws IOException, PGPException, UserException {
        // 步骤 1:  下载插件 ZIP 文件
        Path zip = downloadZip(terminal, urlString, tmpDir, isBatch);
        // 注册到关闭清理列表，目的是确保临时文件最终被清理，即使程序崩溃也能清理，避免磁盘空间被耗尽
        pathsToDeleteOnShutdown.add(zip);
        // 步骤 2: 获取并验证 SHA 校验和
        // 2.1 尝试获取 SHA-512 校验和文件
        String checksumUrlString = urlString + ".sha512"; // 在原始 URL 后追加 .sha512
        URL checksumUrl = openUrl(checksumUrlString); // 打开 URL 连接
        String digestAlgo = "SHA-512";  // 默认使用 SHA-512 算法
        if (checksumUrl == null && officialPlugin == false) {
            // fallback to sha1, until 7.0, but with warning 降级到 SHA-1（兼容旧版本插件，7.0 后将移除此功能）
            terminal.println(
                "Warning: sha512 not found, falling back to sha1. This behavior is deprecated and will be removed in a "
                    + "future release. Please update the plugin to use a sha512 checksum."
            );
            checksumUrlString = urlString + ".sha1";    // 改用 .sha1 扩展名
            checksumUrl = openUrl(checksumUrlString);
            digestAlgo = "SHA-1";        // 切换为 SHA-1 算法
        }
        // 2.3 校验和文件必须存在
        if (checksumUrl == null) {
            // 如果连 SHA-1 都没有，抛出错误
            throw new UserException(ExitCodes.IO_ERROR, "Plugin checksum missing: " + checksumUrlString);
        }

        // 步骤 3: 读取校验和文件内容
        final String expectedChecksum; // 预期的哈希值
        try (InputStream in = urlOpenStream(checksumUrl)) { // 自动关闭输入流
            /*
             *   支持的校验和文件格式：
             *
             * SHA-1 格式：
             *   单行文件，仅包含 SHA-1 哈希值（40 个十六进制字符）
             *   示例：a94a8fe5ccb19ba61c4c0873d391e987982fbbd3
             *
             * SHA-512 格式：
             *   单行文件，包含 SHA-512 哈希值和文件名，用两个空格分隔
             *   示例：9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca...  plugin.zip
             *
             * 验证规则：
             * - SHA-1: 验证哈希值匹配，且文件只有一行
             * - SHA-512: 验证哈希值和文件名匹配，且文件只有一行
             * The supported format of the SHA-1 files is a single-line file containing the SHA-1. The supported format of the SHA-512 files
             * is a single-line file containing the SHA-512 and the filename, separated by two spaces. For SHA-1, we verify that the hash
             * matches, and that the file contains a single line. For SHA-512, we verify that the hash and the filename match, and that the
             * file contains a single line.
             */
            if (digestAlgo.equals("SHA-1")) {
                // 处理 SHA-1 格式
                final BufferedReader checksumReader = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8));
                expectedChecksum = checksumReader.readLine();
                // 验证文件只有一行
                if (checksumReader.readLine() != null) {
                    throw new UserException(ExitCodes.IO_ERROR, "Invalid checksum file at " + checksumUrl);
                }
            } else {
                // 处理 SHA-512 格式
                final BufferedReader checksumReader = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8));
                final String checksumLine = checksumReader.readLine();
                // 按两个空格分割（标准格式）
                final String[] fields = checksumLine.split(" {2}");

                // 控制台打日志
                terminal.println("===============================================================================================");
                terminal.println("-> Rolled back " + officialPlugin + " \n" + fields.length + "\n " + checksumLine + "\n " + urlString);
                terminal.println("===============================================================================================");

                // 验证字段数量
                // 官方插件必须有 2 个字段（哈希 + 文件名），非官方插件可以有 1-2 个字段
                if (officialPlugin && fields.length != 2 || officialPlugin == false && fields.length > 2) {
                    throw new UserException(ExitCodes.IO_ERROR, "Invalid checksum file at " + checksumUrl);
                }
                // 提取哈希值（第一个字段）
                expectedChecksum = fields[0];
                // 如果有文件名（第二个字段），验证文件名匹配
                if (fields.length == 2) {
                    // checksum line contains filename as well 从 URL 中提取期望的文件名
                    final String[] segments = URI.create(urlString).getPath().split("/");
                    final String expectedFile = segments[segments.length - 1];
                    // 验证校验和文件中的文件名与实际文件名一致
                    if (fields[1].equals(expectedFile) == false) {
                        final String message = String.format(
                            Locale.ROOT,
                            "checksum file at [%s] is not for this plugin, expected [%s] but was [%s]",
                            checksumUrl,
                            expectedFile,
                            fields[1]
                        );
                        throw new UserException(ExitCodes.IO_ERROR, message);
                    }
                }
                // 验证文件只有一行
                if (checksumReader.readLine() != null) {
                    throw new UserException(ExitCodes.IO_ERROR, "Invalid checksum file at " + checksumUrl);
                }
            }
        }
        // 步骤 4: 计算下载文件的实际哈希值并验证
        // read the bytes of the plugin zip in chunks to avoid out of memory errors 分块读取 ZIP 文件，避免大文件导致内存溢出
        try (InputStream zis = Files.newInputStream(zip)) { // 自动关闭文件流
            try {
                // 4.1 创建消息摘要对象
                final MessageDigest digest = MessageDigest.getInstance(digestAlgo);
                final byte[] bytes = new byte[8192]; // 8KB 缓冲区（平衡性能与内存）
                int read;
                // 4.2 分块读取并更新摘要
                while ((read = zis.read(bytes)) != -1) {
                    assert read > 0 : read;  // 确保读取到正数字节数
                    digest.update(bytes, 0, read);  // 将读取的字节添加到摘要计算
                }
                // 4.3 转换为十六进制字符串
                final String actualChecksum = MessageDigests.toHexString(digest.digest());
                // 4.4 比较预期和实际哈希值
                if (expectedChecksum.equals(actualChecksum) == false) {
                    throw new UserException(
                        ExitCodes.IO_ERROR,
                        digestAlgo + " mismatch, expected " + expectedChecksum + " but got " + actualChecksum
                    );
                }
            } catch (final NoSuchAlgorithmException e) {
                // this should never happen as we are using SHA-1 and SHA-512 here
                // 理论上不会发生，因为只使用 SHA-1 和 SHA-512（JDK 内置支持）
                throw new AssertionError(e);
            }
        }
        // 步骤 5: 验证 PGP 签名（仅官方插件）
        if (officialPlugin) {
            verifySignature(zip, urlString);   // 调用签名验证方法
        }
        // 步骤 6: 返回已验证的插件文件
        return zip;  // 返回通过所有验证的 ZIP 文件路径
    }

    /**
     * Verify the signature of the downloaded plugin ZIP. The signature is obtained from the source of the downloaded plugin by appending
     * ".sig" to the URL. It is expected that the plugin is signed with the OpenSearch Release signing key with ID 4E9275EE6BA2427F for 3.0.0 or above.
     *
     * @param zip       the path to the downloaded plugin ZIP
     * @param urlString the URL source of the downloade plugin ZIP
     * @throws IOException  if an I/O exception occurs reading from various input streams
     * @throws PGPException if the PGP implementation throws an internal exception during verification
     */
    void verifySignature(final Path zip, final String urlString) throws IOException, PGPException {
        final String sigUrlString = urlString + ".sig";
        final URL sigUrl = openUrl(sigUrlString);
        try (
            // fin is a file stream over the downloaded plugin zip whose signature to verify
            InputStream fin = pluginZipInputStream(zip);
            // sin is a URL stream to the signature corresponding to the downloaded plugin zip
            InputStream sin = urlOpenStream(sigUrl);
            // ain is a input stream to the public key in ASCII-Armor format (RFC4880)
            InputStream ain = new ArmoredInputStream(getPublicKey())
        ) {
            final JcaPGPObjectFactory factory = new JcaPGPObjectFactory(PGPUtil.getDecoderStream(sin));
            final PGPSignature signature = ((PGPSignatureList) factory.nextObject()).get(0);

            // validate the signature has key ID matching our public key ID
            final String keyId = Long.toHexString(signature.getKeyID()).toUpperCase(Locale.ROOT);
            if (getPublicKeyId().equals(keyId) == false) {
                throw new IllegalStateException("key id [" + keyId + "] does not match expected key id [" + getPublicKeyId() + "]");
            }

            // compute the signature of the downloaded plugin zip
            final PGPPublicKeyRingCollection collection = new PGPPublicKeyRingCollection(ain, new JcaKeyFingerprintCalculator());
            final PGPPublicKey key = collection.getPublicKey(signature.getKeyID());
            Security.addProvider(new BouncyCastleFipsProvider());
            signature.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BCFIPS"), key);
            final byte[] buffer = new byte[1024];
            int read;
            while ((read = fin.read(buffer)) != -1) {
                signature.update(buffer, 0, read);
            }

            // finally we verify the signature of the downloaded plugin zip matches the expected signature
            if (signature.verify() == false) {
                throw new IllegalStateException("signature verification for [" + urlString + "] failed");
            }
        }
    }

    /**
     * An input stream to the raw bytes of the plugin ZIP.
     *
     * @param zip the path to the downloaded plugin ZIP
     * @return an input stream to the raw bytes of the plugin ZIP.
     * @throws IOException if an I/O exception occurs preparing the input stream
     */
    InputStream pluginZipInputStream(final Path zip) throws IOException {
        return Files.newInputStream(zip);
    }

    /**
     * Return the public key ID of the signing key that is expected to have signed the official plugin.
     *
     * @return the public key ID
     */
    String getPublicKeyId() {
        return "4E9275EE6BA2427F";
    }

    /**
     * An input stream to the public key of the signing key.
     *
     * @return an input stream to the public key
     */
    InputStream getPublicKey() {
        return InstallPluginCommand.class.getResourceAsStream("/public_key.sig");
    }

    /**
     * Creates a URL and opens a connection.
     * If the URL returns a 404, {@code null} is returned, otherwise the open URL opject is returned.
     */
    // pkg private for tests 验证 URL 是否存在”，然后返回可用的 URL 对象供后续使用
    URL openUrl(String urlString) throws IOException {
        // 将urlString转换成URI对象, 并调用其toURL方法将URI对象转换成URL对象
        URL checksumUrl = URI.create(urlString).toURL();
        // 调用 checksumUrl.openConnection() 方法，尝试建立到该 URL 的网络连接
        // connection 是一个代表网络连接的对象，可以通过它获取响应头、状态码、输入流等信息
        HttpURLConnection connection = (HttpURLConnection) checksumUrl.openConnection();
        if (connection.getResponseCode() == 404) {
            return null;
        }
        // 返回获取到的URL对象
        return checksumUrl;
    }

    /**
     *
     * @param zip   已下载的插件 ZIP 文件路径（如 /tmp/plugin.zip）
     * @param pluginsDir    OpenSearch 插件目录路径（如 /opt/opensearch/plugins）
     * @return
     * @throws IOException
     * @throws UserException
     */
    private Path unzip(Path zip, Path pluginsDir) throws IOException, UserException {
        // unzip plugin to a staging temp dir 将插件解压到临时暂存目录（而非直接解压到目标位置）
        // 确保安装要么完全成功，要么完全失败，在移动到最终位置前可以验证插件，失败时只需删除临时目录
        // 步骤 1：创建临时解压目录
        final Path target = stagingDirectory(pluginsDir);  // 创建临时解压目录
        pathsToDeleteOnShutdown.add(target); // 将临时目录添加到关闭时的清理列表
        // 步骤 2：打开 ZIP 文件
        try (ZipFile zipFile = new ZipFile(zip,   // 参数 1：ZIP 文件路径
            "UTF8",                               // 参数 2：字符编码（使用 UTF-8 解析文件名）
            true,                                 // 参数 3：是否使用 UTF-8 编码（标记）
            false                                 // 参数 4：是否从 Unicode 注释读取
        )) {
            // 步骤3：获取ZIP条目枚举
            final Enumeration<? extends ZipArchiveEntry> entries = zipFile.getEntries(); //获取zip所有条目
            ZipArchiveEntry entry; // 声明循环变量，在循环外声明，方便在循环内使用
            byte[] buffer = new byte[8192]; // 创建缓冲区 创建一个缓存数组，用于存储解压后的数据
            // 步骤 4：遍历 ZIP 条目
            while (entries.hasMoreElements()) { // 循环遍历zip条目，检查是否有未处理的ZIP条目
                entry = entries.nextElement(); // 获取下一个条目 ZipArchiveEntry：表示 ZIP 中的一个文件或目录
                // 步骤 5：检查旧版插件结构
                if (entry.getName().startsWith("opensearch/")) { // 检查路径前缀
                    // 旧版插件会在 ZIP 内包含一个 opensearch/ 目录; 正确结构应该是根目录直接包含插件文件
                    throw new UserException(
                        PLUGIN_MALFORMED,
                        "This plugin was built with an older plugin structure."
                            + " Contact the plugin author to remove the intermediate \"opensearch\" directory within the plugin zip."
                    );
                }
                // 步骤 6：计算目标文件路径
                // resolve()：将相对路径拼接到目标目录; 保持 ZIP 内的目录结构
                Path targetFile = target.resolve(entry.getName());

                // Using the entry name as a path can result in an entry outside of the plugin dir,
                // either if the name starts with the root of the filesystem, or it is a relative
                // entry like ../whatever. This check attempts to identify both cases by first
                // normalizing the path (which removes foo/..) and ensuring the normalized entry
                // is still rooted with the target plugin directory.
                // 步骤 7：安全检查 - 防止路径遍历攻击
                if (targetFile.normalize().startsWith(target) == false) {
                    throw new UserException( // 抛出安全异常
                        PLUGIN_MALFORMED,
                        "Zip contains entry name '" + entry.getName() + "' resolving outside of plugin directory"
                    );
                }

                // be on the safe side: do not rely on that directories are always extracted
                // before their children (although this makes sense, but is it guaranteed?)
                // 步骤 8：创建父目录
                if (!Files.isSymbolicLink(targetFile.getParent())) { // 符号链接检查
                    // 递归创建所有不存在的父目录； 如果目录已存在，不抛异常（幂等操作）；自动设置默认权限
                    Files.createDirectories(targetFile.getParent());
                }
                // 步骤 9：解压文件内容
                if (entry.isDirectory() == false) { // 跳过目录
                    // streams will be auto-closed with try-with-resources
                    try (OutputStream out = Files.newOutputStream(targetFile); InputStream input = zipFile.getInputStream(entry)) {
                        input.transferTo(out);
                    }
                }
            }
        // 步骤 10：异常处理和清理
        } catch (UserException e) {
            IOUtils.rm(target);
            throw e;
        }
        // 删除原始 ZIP 文件
        Files.delete(zip);
        return target;
    }

    private Path stagingDirectory(Path pluginsDir) throws IOException {
        try {
            return Files.createTempDirectory(pluginsDir, ".installing-", PosixFilePermissions.asFileAttribute(PLUGIN_DIR_PERMS));
        } catch (IllegalArgumentException e) {
            // Jimfs throws an IAE where it should throw an UOE
            // remove when google/jimfs#30 is integrated into Jimfs
            // and the Jimfs test dependency is upgraded to include
            // this pull request
            final StackTraceElement[] elements = e.getStackTrace();
            if (elements.length >= 1
                && elements[0].getClassName().equals("com.google.common.jimfs.AttributeService")
                && elements[0].getMethodName().equals("setAttributeInternal")) {
                return stagingDirectoryWithoutPosixPermissions(pluginsDir);
            } else {
                throw e;
            }
        } catch (UnsupportedOperationException e) {
            return stagingDirectoryWithoutPosixPermissions(pluginsDir);
        }
    }

    private Path stagingDirectoryWithoutPosixPermissions(Path pluginsDir) throws IOException {
        return Files.createTempDirectory(pluginsDir, ".installing-");
    }

    // checking for existing version of the plugin
    private void verifyPluginName(Path pluginPath, String pluginName) throws UserException, IOException {
        // don't let user install plugin conflicting with module...
        // they might be unavoidably in maven central and are packaged up the same way)
        if (MODULES.contains(pluginName)) {
            throw new UserException(ExitCodes.USAGE, "plugin '" + pluginName + "' cannot be installed as a plugin, it is a system module");
        }

        // scan all the installed plugins to see if the plugin being installed already exists
        // either with the plugin name or a custom folder name
        Path destination = PluginHelper.verifyIfPluginExists(pluginPath, pluginName);
        if (Files.exists(destination)) {
            final String message = String.format(
                Locale.ROOT,
                "plugin directory [%s] already exists; if you need to update the plugin, " + "uninstall it first using command 'remove %s'",
                destination,
                pluginName
            );
            throw new UserException(PLUGIN_EXISTS, message);
        }
    }

    /** Load information about the plugin, and verify it can be installed with no errors. */
    private PluginInfo loadPluginInfo(Terminal terminal, Path pluginRoot, Environment env) throws Exception {
        final PluginInfo info = PluginInfo.readFromProperties(pluginRoot);
        if (info.hasNativeController()) {
            throw new IllegalStateException("plugins can not have native controllers");
        }
        PluginsService.verifyCompatibility(info);

        // checking for existing version of the plugin
        verifyPluginName(env.pluginsDir(), info.getName());

        PluginsService.checkForFailedPluginRemovals(env.pluginsDir());

        terminal.println(VERBOSE, info.toString());

        // check for jar hell before any copying
        jarHellCheck(info, pluginRoot, env.pluginsDir(), env.modulesDir());

        return info;
    }

    private static final String LIB_TOOLS_PLUGIN_CLI_CLASSPATH_JAR;

    static {
        LIB_TOOLS_PLUGIN_CLI_CLASSPATH_JAR = String.format(Locale.ROOT, ".+%1$slib%1$stools%1$splugin-cli%1$s[^%1$s]+\\.jar", "(/|\\\\)");
    }

    /** check a candidate plugin for jar hell before installing it */
    void jarHellCheck(PluginInfo candidateInfo, Path candidateDir, Path pluginsDir, Path modulesDir) throws Exception {
        // create list of current jars in classpath
        final Set<URL> classpath = JarHell.parseClassPath().stream().filter(url -> {
            try {
                return url.toURI().getPath().matches(LIB_TOOLS_PLUGIN_CLI_CLASSPATH_JAR) == false;
            } catch (final URISyntaxException e) {
                throw new AssertionError(e);
            }
        }).collect(Collectors.toSet());

        // read existing bundles. this does some checks on the installation too.
        PluginsService.checkJarHellForPlugin(classpath, candidateInfo, candidateDir, pluginsDir, modulesDir);

        // TODO: no jars should be an error
        // TODO: verify the classname exists in one of the jars!
    }

    /**
     * Installs the plugin from {@code tmpRoot} into the plugins dir.
     * If the plugin has a bin dir and/or a config dir, those are moved.
     */
    private PluginInfo installPlugin(Terminal terminal, boolean isBatch, Path tmpRoot, Environment env, List<Path> deleteOnFailure)
        throws Exception {
        final PluginInfo info = loadPluginInfo(terminal, tmpRoot, env);
        // read optional security policy (extra permissions), if it exists, confirm or warn the user
        Path policy = tmpRoot.resolve(PluginInfo.OPENSEARCH_PLUGIN_POLICY);
        final Set<String> permissions;
        if (Files.exists(policy)) {
            permissions = PluginSecurity.parsePermissions(policy, env.tmpDir());
        } else {
            permissions = Collections.emptySet();
        }
        PluginSecurity.confirmPolicyExceptions(terminal, permissions, isBatch);

        String targetFolderName = info.getTargetFolderName();
        final Path destination = env.pluginsDir().resolve(targetFolderName);
        deleteOnFailure.add(destination);

        installPluginSupportFiles(
            info,
            tmpRoot,
            env.binDir().resolve(targetFolderName),
            env.configDir().resolve(targetFolderName),
            deleteOnFailure
        );
        movePlugin(tmpRoot, destination);
        return info;
    }

    /** Moves bin and config directories from the plugin if they exist */
    private void installPluginSupportFiles(PluginInfo info, Path tmpRoot, Path destBinDir, Path destConfigDir, List<Path> deleteOnFailure)
        throws Exception {
        Path tmpBinDir = tmpRoot.resolve("bin");
        if (Files.exists(tmpBinDir)) {
            deleteOnFailure.add(destBinDir);
            installBin(info, tmpBinDir, destBinDir);
        }

        Path tmpConfigDir = tmpRoot.resolve("config");
        if (Files.exists(tmpConfigDir)) {
            // some files may already exist, and we don't remove plugin config files on plugin removal,
            // so any installed config files are left on failure too
            installConfig(info, tmpConfigDir, destConfigDir);
        }
    }

    /** Moves the plugin directory into its final destination. **/
    private void movePlugin(Path tmpRoot, Path destination) throws IOException {
        Files.move(tmpRoot, destination, StandardCopyOption.ATOMIC_MOVE);
        Files.walkFileTree(destination, new SimpleFileVisitor<Path>() {
            @Override
            public FileVisitResult visitFile(final Path file, final BasicFileAttributes attrs) throws IOException {
                final String parentDirName = file.getParent().getFileName().toString();
                if ("bin".equals(parentDirName)
                    // "MacOS" is an alternative to "bin" on macOS
                    || (Constants.MAC_OS_X && "MacOS".equals(parentDirName))) {
                    setFileAttributes(file, BIN_FILES_PERMS);
                } else {
                    setFileAttributes(file, PLUGIN_FILES_PERMS);
                }
                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult postVisitDirectory(final Path dir, final IOException exc) throws IOException {
                setFileAttributes(dir, PLUGIN_DIR_PERMS);
                return FileVisitResult.CONTINUE;
            }
        });
    }

    /** Copies the files from {@code tmpBinDir} into {@code destBinDir}, along with permissions from dest dirs parent. */
    private void installBin(PluginInfo info, Path tmpBinDir, Path destBinDir) throws Exception {
        if (Files.isDirectory(tmpBinDir) == false) {
            throw new UserException(PLUGIN_MALFORMED, "bin in plugin " + info.getName() + " is not a directory");
        }
        Files.createDirectories(destBinDir);
        setFileAttributes(destBinDir, BIN_DIR_PERMS);

        try (DirectoryStream<Path> stream = Files.newDirectoryStream(tmpBinDir)) {
            for (Path srcFile : stream) {
                if (Files.isDirectory(srcFile)) {
                    throw new UserException(
                        PLUGIN_MALFORMED,
                        "Directories not allowed in bin dir " + "for plugin " + info.getName() + ", found " + srcFile.getFileName()
                    );
                }

                Path destFile = destBinDir.resolve(tmpBinDir.relativize(srcFile));
                Files.copy(srcFile, destFile);
                setFileAttributes(destFile, BIN_FILES_PERMS);
            }
        }
        IOUtils.rm(tmpBinDir); // clean up what we just copied
    }

    /**
     * Copies the files from {@code tmpConfigDir} into {@code destConfigDir}.
     * Any files existing in both the source and destination will be skipped.
     */
    private void installConfig(PluginInfo info, Path tmpConfigDir, Path destConfigDir) throws Exception {
        if (Files.isDirectory(tmpConfigDir) == false) {
            throw new UserException(PLUGIN_MALFORMED, "config in plugin " + info.getName() + " is not a directory");
        }

        Files.createDirectories(destConfigDir);
        setFileAttributes(destConfigDir, CONFIG_DIR_PERMS);
        final PosixFileAttributeView destConfigDirAttributesView = Files.getFileAttributeView(
            destConfigDir.getParent(),
            PosixFileAttributeView.class
        );
        final PosixFileAttributes destConfigDirAttributes = destConfigDirAttributesView != null
            ? destConfigDirAttributesView.readAttributes()
            : null;
        if (destConfigDirAttributes != null) {
            setOwnerGroup(destConfigDir, destConfigDirAttributes);
        }

        try (DirectoryStream<Path> stream = Files.newDirectoryStream(tmpConfigDir)) {
            for (Path srcFile : stream) {
                Path destFile = destConfigDir.resolve(tmpConfigDir.relativize(srcFile));
                if (Files.exists(destFile) == false) {
                    if (Files.isDirectory(srcFile)) {
                        copyWithPermissions(srcFile, destFile, CONFIG_DIR_PERMS, destConfigDirAttributes);
                        copyDirectoryRecursively(srcFile, destFile, destConfigDirAttributes);
                    } else {
                        copyWithPermissions(srcFile, destFile, CONFIG_FILES_PERMS, destConfigDirAttributes);
                    }
                }
            }
        }
        IOUtils.rm(tmpConfigDir); // clean up what we just copied
    }

    private static void setOwnerGroup(final Path path, final PosixFileAttributes attributes) throws IOException {
        Objects.requireNonNull(attributes);
        PosixFileAttributeView fileAttributeView = Files.getFileAttributeView(path, PosixFileAttributeView.class);
        assert fileAttributeView != null;
        fileAttributeView.setOwner(attributes.owner());
        fileAttributeView.setGroup(attributes.group());
    }

    /**
     * Sets the attributes for a path iff posix attributes are supported
     */
    private static void setFileAttributes(final Path path, final Set<PosixFilePermission> permissions) throws IOException {
        PosixFileAttributeView fileAttributeView = Files.getFileAttributeView(path, PosixFileAttributeView.class);
        if (fileAttributeView != null) {
            Files.setPosixFilePermissions(path, permissions);
        }
    }

    /**
     * Copies a file and sets permissions and ownership
     */
    private static void copyWithPermissions(
        Path srcFile,
        Path destFile,
        Set<PosixFilePermission> permissions,
        PosixFileAttributes attributes
    ) throws IOException {
        Files.copy(srcFile, destFile);
        setFileAttributes(destFile, permissions);
        if (attributes != null) {
            setOwnerGroup(destFile, attributes);
        }
    }

    /**
     * Recursively copies directory contents from source to destination.
     */
    private static void copyDirectoryRecursively(Path srcDir, Path destDir, PosixFileAttributes destConfigDirAttributes)
        throws IOException {
        try (DirectoryStream<Path> stream = Files.newDirectoryStream(srcDir)) {
            for (Path srcFile : stream) {
                Path destFile = destDir.resolve(srcDir.relativize(srcFile));
                if (Files.exists(destFile) == false) {
                    if (Files.isDirectory(srcFile)) {
                        copyWithPermissions(srcFile, destFile, CONFIG_DIR_PERMS, destConfigDirAttributes);
                        copyDirectoryRecursively(srcFile, destFile, destConfigDirAttributes);
                    } else {
                        copyWithPermissions(srcFile, destFile, CONFIG_FILES_PERMS, destConfigDirAttributes);
                    }
                }
            }
        }
    }

    private final List<Path> pathsToDeleteOnShutdown = new ArrayList<>();

    @Override
    public void close() throws IOException {
        IOUtils.rm(pathsToDeleteOnShutdown.toArray(new Path[0]));
    }

}
