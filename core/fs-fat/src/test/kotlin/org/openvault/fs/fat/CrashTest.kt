package org.openvault.fs.fat

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.openvault.fs.*
import org.openvault.io.BlockDevice
import java.time.ZoneOffset

/** Drops every write after the [budget]-th (simulates power loss / process kill). */
class CrashingDevice(val inner: ImageDevice, var budget: Int) : BlockDevice by inner {
    var writes = 0
    override fun writeSectors(firstSector: Long, src: ByteArray, off: Int, count: Int) { writes++; if (writes <= budget) inner.writeSectors(firstSector, src, off, count) }
}

class CrashTest {
    private val base = Mkfs.image(16, 4 * 1024 * 1024, 1)
    init {
        FatFileSystem(base, ZoneOffset.UTC, readOnly = false).use { fs ->
            fs.createDirectory(fs.root(), "keep")
            for (i in 0 until 5) { val n = fs.createFile(fs.resolve(FsPath.parse("keep")), "old$i.bin"); fs.open(n, OpenMode.READ_WRITE).use { it.write(0, ByteArray(3000) { b -> (b + i).toByte() }, 0, 3000) } }
        }
    }
    private val baseline = base.data.copyOf()

    private fun scenario(fs: FileSystem, dir: String) {
        val d = fs.createDirectory(fs.root(), dir)
        val n = fs.createFile(d, "imported.bin")
        fs.open(n, OpenMode.READ_WRITE).use { it.write(0, ByteArray(20_000) { b -> (b * 7).toByte() }, 0, 20_000); it.flush() }
    }

    private fun total(): Int {
        val dev = CrashingDevice(ImageDevice(baseline.copyOf()), Int.MAX_VALUE)
        FatFileSystem(dev, ZoneOffset.UTC, readOnly = false).use { scenario(it, "new") }
        return dev.writes
    }

    @Test fun `killing the import at any write leaves earlier files intact and the volume mountable`() {
        val n = total(); assertTrue(n > 10)
        val problems = HashMap<String, Int>()
        for (budget in 0..n) {
            val img = ImageDevice(baseline.copyOf()); val dev = CrashingDevice(img, budget)
            try { FatFileSystem(dev, ZoneOffset.UTC, readOnly = false).use { scenario(it, "new") } } catch (e: Exception) { /* dropped writes may surface as read-back errors */ }
            // 1. earlier data survives
            FatFileSystem(ImageDevice(img.data.copyOf()), ZoneOffset.UTC).use { fs ->
                for (i in 0 until 5) fs.open(fs.resolve(FsPath.parse("keep/old$i.bin")), OpenMode.READ).use { f ->
                    val b = ByteArray(3000); assertEquals(3000, f.read(0, b, 0, 3000)); assertArrayEquals(ByteArray(3000) { x -> (x + i).toByte() }, b, "budget $budget old$i") }
                fs.list(fs.root()) // still mountable / listable
            }
            // 2. fsck: record what it reports, only allow in-flight-related findings
            val (code, out) = Mkfs.fsck(img.data)
            if (code != 0) out.lines().filter { it.isNotBlank() && !it.startsWith("fsck.fat") && !it.contains("files,") }.forEach { problems.merge(it.trim().replace(Regex("\\d+"), "N"), 1, Int::plus) }
        }
        println("crash findings: $problems")
        val allowed = Regex("(?i)(unused cluster|Leaving filesystem unchanged|FATs differ|Using first FAT|out of range|Setting to EOF)")
        val unexpected = problems.keys.filter { k -> !allowed.containsMatchIn(k) }
        assertTrue(unexpected.isEmpty(), "unexpected fsck findings: $unexpected")
    }
}
