package com.sorrowblue.kmcifs.detekt

import dev.detekt.tooling.api.AnalysisMode
import dev.detekt.tooling.api.BaselineProvider
import dev.detekt.tooling.api.DetektProvider
import dev.detekt.tooling.api.spec.ProcessingSpec
import org.jetbrains.amper.plugins.ExecutionAvoidance
import org.jetbrains.amper.plugins.Input
import org.jetbrains.amper.plugins.ModuleSources
import org.jetbrains.amper.plugins.Output
import org.jetbrains.amper.plugins.TaskAction
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock
import kotlin.io.path.exists
import kotlin.io.path.extension
import kotlin.io.path.isDirectory
import kotlin.io.path.isRegularFile
import kotlin.io.path.name

private val detektLock = ReentrantLock()

@TaskAction
fun checkDetekt(
    moduleName: String,
    @Input sources: ModuleSources,
    @Input(inferTaskDependency = false) srcDir: Path,
    @Input(inferTaskDependency = false) testDir: Path,
    @Input(inferTaskDependency = false) configFile: Path,
    @Input(inferTaskDependency = false) baselineFile: Path,
    @Output outputDir: Path,
) {
    Files.createDirectories(outputDir)
    val normalizedSrcDir = srcDir.toAbsolutePath().normalize()
    val moduleRootDir = normalizedSrcDir.parent ?: normalizedSrcDir
    val inputPaths = collectInputPaths(sources, normalizedSrcDir, testDir, moduleRootDir)
    runDetekt(
        moduleName = moduleName,
        moduleRootDir = moduleRootDir,
        inputPaths = inputPaths,
        configFile = configFile,
        baselineFile = baselineFile,
        outputDir = outputDir,
        createBaseline = false,
    )
}

@TaskAction(ExecutionAvoidance.Disabled)
fun generateDetektBaseline(
    moduleName: String,
    @Input sources: ModuleSources,
    @Input(inferTaskDependency = false) srcDir: Path,
    @Input(inferTaskDependency = false) testDir: Path,
    @Input(inferTaskDependency = false) configFile: Path,
    @Input(inferTaskDependency = false) baselineFile: Path,
) {
    val normalizedSrcDir = srcDir.toAbsolutePath().normalize()
    val moduleRootDir = normalizedSrcDir.parent ?: normalizedSrcDir
    val inputPaths = collectInputPaths(sources, normalizedSrcDir, testDir, moduleRootDir)
    runDetekt(
        moduleName = moduleName,
        moduleRootDir = moduleRootDir,
        inputPaths = inputPaths,
        configFile = configFile,
        baselineFile = baselineFile,
        outputDir = null,
        createBaseline = true,
    )
}

private fun runDetekt(
    moduleName: String,
    moduleRootDir: Path,
    inputPaths: List<Path>,
    configFile: Path,
    baselineFile: Path,
    outputDir: Path?,
    createBaseline: Boolean,
) {
    if (inputPaths.isEmpty()) {
        println("Skipping Detekt for '$moduleName': no Kotlin source directories found.")
        return
    }

    val normalizedConfig = configFile.toAbsolutePath().normalize()
    val normalizedBaseline = baselineFile.toAbsolutePath().normalize()
    val pluginClassLoader = DetektProvider::class.java.classLoader

    val spec = buildProcessingSpec(
        moduleRootDir = moduleRootDir,
        inputPaths = inputPaths,
        configFile = normalizedConfig,
        baselineFile = normalizedBaseline,
        outputDir = outputDir?.toAbsolutePath()?.normalize(),
        createBaseline = createBaseline,
        pluginClassLoader = pluginClassLoader,
    )

    val result = detektLock.withLock {
        val currentThread = Thread.currentThread()
        val previousClassLoader = currentThread.contextClassLoader
        currentThread.contextClassLoader = pluginClassLoader
        try {
            DetektProvider.load(pluginClassLoader).get(spec).run()
        } finally {
            currentThread.contextClassLoader = previousClassLoader
        }
    }

    if (createBaseline) {
        cleanupEmptyBaseline(normalizedBaseline, pluginClassLoader)
    } else if (outputDir != null) {
        val projectRootDir = normalizedConfig.parent?.parent?.parent
        val mirrorDir = projectRootDir?.resolve("build")?.resolve("reports")?.resolve("detekt")?.resolve(moduleName)
        if (mirrorDir != null) {
            runCatching {
                copyReports(outputDir, mirrorDir)
            }
        }
    }

    result.error?.let { throw it }
}

private fun buildProcessingSpec(
    moduleRootDir: Path,
    inputPaths: List<Path>,
    configFile: Path,
    baselineFile: Path,
    outputDir: Path?,
    createBaseline: Boolean,
    pluginClassLoader: ClassLoader,
): ProcessingSpec = ProcessingSpec {
    project {
        basePath = moduleRootDir
        this.inputPaths = inputPaths
        analysisMode = AnalysisMode.light
    }
    config {
        useDefaultConfig = true
        shouldValidateBeforeAnalysis = true
        if (configFile.exists() && configFile.isRegularFile()) {
            configPaths = listOf(configFile)
        }
    }
    baseline {
        if (createBaseline || (baselineFile.exists() && baselineFile.isRegularFile())) {
            path = baselineFile
        }
        shouldCreateDuringAnalysis = createBaseline
    }
    rules {
        autoCorrect = false
    }
    extensions {
        fromClassloader { pluginClassLoader }
    }
    if (outputDir != null) {
        reports {
            report { "html" to outputDir.resolve("detekt.html") }
            report { "sarif" to outputDir.resolve("detekt.sarif") }
            report { "checkstyle" to outputDir.resolve("detekt.xml") }
        }
    }
}

private fun collectInputPaths(sources: ModuleSources, srcDir: Path, testDir: Path, moduleRootDir: Path): List<Path> {
    val candidates = linkedSetOf<Path>()
    sources.sourceDirectories.forEach { dir ->
        candidates.add(dir.toAbsolutePath().normalize())
    }
    candidates.add(srcDir)
    candidates.add(testDir.toAbsolutePath().normalize())
    if (moduleRootDir.exists() && moduleRootDir.isDirectory()) {
        Files.list(moduleRootDir).use { stream ->
            stream
                .filter { path ->
                    path.isDirectory() && isKotlinSourceRootName(path.name)
                }
                .forEach { dir ->
                    candidates.add(dir.toAbsolutePath().normalize())
                }
        }
    }
    return candidates.filter { dir -> containsKotlinFiles(dir) }
}

private fun isKotlinSourceRootName(name: String): Boolean =
    name == "src" || name.startsWith("src@") || name == "test" || name.startsWith("test@")

private fun containsKotlinFiles(dir: Path): Boolean {
    if (!dir.exists() || !dir.isDirectory()) {
        return false
    }
    return Files.walk(dir).use { stream ->
        stream.anyMatch { path -> path.isRegularFile() && path.extension == "kt" }
    }
}

private fun cleanupEmptyBaseline(baselineFile: Path, classLoader: ClassLoader) {
    if (!baselineFile.exists() || !baselineFile.isRegularFile()) {
        return
    }
    val baseline = BaselineProvider.load(classLoader).read(baselineFile)
    if (baseline.manuallySuppressedIssues.isEmpty() && baseline.currentIssues.isEmpty()) {
        Files.deleteIfExists(baselineFile)
    }
}

private fun copyReports(sourceDir: Path, targetDir: Path) {
    if (!sourceDir.exists()) {
        return
    }
    Files.walk(sourceDir).use { stream ->
        stream.forEach { src ->
            val dst = targetDir.resolve(sourceDir.relativize(src))
            if (Files.isDirectory(src)) {
                Files.createDirectories(dst)
            } else {
                Files.createDirectories(dst.parent)
                Files.copy(src, dst, StandardCopyOption.REPLACE_EXISTING)
            }
        }
    }
}
