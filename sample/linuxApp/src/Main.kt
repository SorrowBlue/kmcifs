import com.sorrowblue.kmcifs.sample.SmbSampleRunner
import kotlinx.coroutines.runBlocking

fun main(args: Array<String>) = runBlocking {
    SmbSampleRunner.runCli("Linux Native", args)
}
