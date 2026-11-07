package com.sorrowblue.kmcifs.dokka

import org.jetbrains.amper.plugins.Classpath
import org.jetbrains.amper.plugins.Input
import org.jetbrains.amper.plugins.Output
import org.jetbrains.amper.plugins.TaskAction
import org.jetbrains.dokka.DokkaConfiguration
import org.jetbrains.dokka.DokkaConfigurationImpl
import org.jetbrains.dokka.DokkaGenerator
import org.jetbrains.dokka.DokkaSourceSetID
import org.jetbrains.dokka.DokkaSourceSetImpl
import org.jetbrains.dokka.Platform
import org.jetbrains.dokka.utilities.DokkaConsoleLogger
import org.jetbrains.dokka.utilities.LoggingLevel
import java.net.URLClassLoader
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.util.Comparator
import kotlin.io.path.exists
import kotlin.io.path.isDirectory
import kotlin.io.path.isRegularFile

@TaskAction
fun generateDokkaHtml(
    moduleName: String,
    @Input moduleRootDir: Path,
    @Input compileClasspath: Classpath,
    @Output outputDir: Path,
) {
    val srcDir = moduleRootDir.resolve("src")
    if (!srcDir.exists()) {
        println("Skipping Dokka generation for '$moduleName': source directory not found at $srcDir")
        return
    }

    Files.createDirectories(outputDir)

    val classpathFiles = compileClasspath.resolvedFiles
        .filter { it.exists() && it.isRegularFile() }
        .map { it.toFile() }

    val configuration = DokkaConfigurationImpl(
        moduleName = moduleName,
        moduleVersion = "0.0.1",
        outputDir = outputDir.toFile(),
        offlineMode = false,
        failOnWarning = false,
        sourceSets = listOf(
            DokkaSourceSetImpl(
                displayName = "common",
                sourceSetID = DokkaSourceSetID(scopeId = moduleName, sourceSetName = "commonMain"),
                analysisPlatform = Platform.common,
                classpath = classpathFiles,
                sourceRoots = setOf(srcDir.toFile()),
                documentedVisibilities = setOf(
                    DokkaConfiguration.Visibility.PUBLIC,
                    DokkaConfiguration.Visibility.PROTECTED,
                ),
                reportUndocumented = false,
                skipEmptyPackages = true,
                skipDeprecated = false,
                jdkVersion = 17,
            ),
        ),
    )

    val logger = DokkaConsoleLogger(LoggingLevel.PROGRESS)
    DokkaGenerator(configuration, logger).generate()

    val projectRoot = moduleRootDir.parent
    val convenientDir = projectRoot?.resolve("build")?.resolve("dokka")?.resolve("html")?.resolve(moduleName)
    if (convenientDir != null) {
        runCatching {
            copyDirectory(outputDir, convenientDir)
        }
    }

    val siteApiDir = projectRoot?.resolve("build")?.resolve("site")?.resolve("api")
    if (siteApiDir != null) {
        runCatching {
            copyDirectory(outputDir, siteApiDir)
        }
    }

    println("Dokka HTML generated for '$moduleName': ${outputDir.resolve("index.html").toAbsolutePath()}")
    if (convenientDir != null) {
        println("Dokka HTML mirror: ${convenientDir.resolve("index.html").toAbsolutePath()}")
    }
    if (siteApiDir != null) {
        println("Zensical API mirror: ${siteApiDir.resolve("index.html").toAbsolutePath()}")
    }

    runCatching {
        pruneUnusedDokkaCache()
    }
}

private fun pruneUnusedDokkaCache() {
    val codeSourceUri = DokkaGenerator::class.java.protectionDomain?.codeSource?.location?.toURI() ?: return
    val coreJarPath = Path.of(codeSourceUri).toAbsolutePath().normalize()
    val activeVersionDir = coreJarPath.parent ?: return
    val activeVersion = activeVersionDir.fileName?.toString() ?: return
    val dokkaGroupDir = activeVersionDir.parent?.parent ?: return
    if (dokkaGroupDir.fileName?.toString() != "dokka" || !dokkaGroupDir.isDirectory()) return

    val activeDirs = (DokkaGenerator::class.java.classLoader as? URLClassLoader)
        ?.urLs
        ?.mapNotNull { url -> runCatching { Path.of(url.toURI()).toAbsolutePath().normalize().parent }.getOrNull() }
        ?.filter { it.startsWith(dokkaGroupDir) }
        ?.toSet()
        .orEmpty()

    Files.list(dokkaGroupDir).use { artifactStream ->
        artifactStream.filter { it.isDirectory() }.forEach { artifactDir ->
            Files.list(artifactDir).use { versionStream ->
                versionStream.filter { it.isDirectory() }.forEach { versionDir ->
                    val normalized = versionDir.toAbsolutePath().normalize()
                    val shouldKeep = if (activeDirs.isNotEmpty()) {
                        normalized in activeDirs
                    } else {
                        normalized.fileName?.toString() == activeVersion
                    }
                    if (!shouldKeep) {
                        deleteDirectory(normalized)
                        println("Pruned unused Dokka cache: $normalized")
                    }
                }
            }
            val isEmpty = Files.list(artifactDir).use { !it.findFirst().isPresent }
            if (isEmpty) {
                Files.deleteIfExists(artifactDir)
            }
        }
    }
}

private fun deleteDirectory(dir: Path) {
    Files.walk(dir).use { stream ->
        stream.sorted(Comparator.reverseOrder()).forEach { path ->
            Files.deleteIfExists(path)
        }
    }
}

private fun copyDirectory(source: Path, target: Path) {
    Files.walk(source).use { stream ->
        stream.forEach { src ->
            val dst = target.resolve(source.relativize(src))
            if (Files.isDirectory(src)) {
                Files.createDirectories(dst)
            } else {
                Files.createDirectories(dst.parent)
                Files.copy(src, dst, StandardCopyOption.REPLACE_EXISTING)
            }
        }
    }
}
