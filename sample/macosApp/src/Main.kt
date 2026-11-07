import com.sorrowblue.kmcifs.sample.SmbSampleRunner
import kotlinx.coroutines.runBlocking

fun main(args: Array<String>) = runBlocking {
    SmbSampleRunner.runCli("macOS (macosArm64)", args)
}
