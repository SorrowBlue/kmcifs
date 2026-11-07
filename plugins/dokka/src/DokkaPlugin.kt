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
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import kotlin.io.path.exists
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

    val convenientDir = moduleRootDir.parent?.resolve("build")?.resolve("dokka")?.resolve("html")?.resolve(moduleName)
    if (convenientDir != null) {
        runCatching {
            copyDirectory(outputDir, convenientDir)
        }
    }

    println("Dokka HTML generated for '$moduleName': ${outputDir.resolve("index.html").toAbsolutePath()}")
    if (convenientDir != null) {
        println("Dokka HTML mirror: ${convenientDir.resolve("index.html").toAbsolutePath()}")
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
