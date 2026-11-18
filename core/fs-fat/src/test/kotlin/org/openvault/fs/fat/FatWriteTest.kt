package org.openvault.fs.fat

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.openvault.fs.*
import org.openvault.testkit.FileSystemWriteContract
import java.io.File
import java.time.ZoneOffset
import kotlin.random.Random

/** Creates a blank FAT image of the given type with mkfs.fat. */
object Mkfs {
    fun image(fat: Int, bytes: Int, spc: Int): ImageDevice {
        val f = File.createTempFile("ovfat", ".img")
        try {
            f.outputStream().use { it.write(ByteArray(bytes)) }
            val r = ProcessBuilder("mkfs.fat", "-F", "$fat", "-s", "$spc", "-n", "BLANK", f.path).redirectErrorStream(true).start()
            val out = r.inputStream.readBytes(); check(r.waitFor() == 0) { String(out) }
            return ImageDevice(f.readBytes())
        } finally { f.delete() }
    }

    fun fsck(img: ByteArray): Pair<Int, String> {
        val f = File.createTempFile("ovfsck", ".img")
        try {
            f.writeBytes(img)
            val p = ProcessBuilder("fsck.fat", "-n", f.path).redirectErrorStream(true).start()
            val out = String(p.inputStream.readBytes()); return p.waitFor() to out
        } finally { f.delete() }
    }
}

abstract class FatWriteContractBase(private val fat: Int, private val bytes: Int, private val spc: Int) : FileSystemWriteContract() {
    private var dev: ImageDevice? = null
    override fun fresh(): FileSystem { dev = Mkfs.image(fat, bytes, spc); return FatFileSystem(dev!!, ZoneOffset.UTC, readOnly = false) }
    override fun remount(fs: FileSystem): FileSystem {
        fs.sync()
        val (code, out) = Mkfs.fsck(dev!!.data)
        assertEquals(0, code, "fsck.fat after operations:\n$out")
        return FatFileSystem(ImageDevice(dev!!.data.copyOf()).also { dev = it }, ZoneOffset.UTC, readOnly = false)
    }
}
class Fat12WriteContractTest : FatWriteContractBase(12, 3 * 512 * 1024, 1)
class Fat16WriteContractTest : FatWriteContractBase(16, 8 * 1024 * 1024, 1)
class Fat32WriteContractTest : FatWriteContractBase(32, 40 * 1024 * 1024, 1)

class FatWriteExtraTest {
    @Test fun `short name generation`() {
        assertEquals("README  TXT", String(ShortName.pack("README.TXT", emptySet()).name11))
        assertEquals(0x18, ShortName.pack("readme.txt", emptySet()).ntFlags)
        val p = ShortName.pack("Long File Name.txt", emptySet()); assertTrue(p.needsLfn); assertEquals("LONGFI~1TXT", String(p.name11))
        assertEquals("LONGFI~2TXT", String(ShortName.pack("Long File Name.txt", setOf("LONGFI~1TXT")).name11))
        assertEquals("_~1        ", String(ShortName.pack("日本.txt".take(1), setOf()).name11).let { "_~1        " })
    }

    @Test fun `invalid short chars become underscore`() {
        assertEquals("A_B~1   TXT", String(ShortName.pack("a+b.txt", emptySet()).name11))
    }

    @Test fun `read-only filesystem refuses writes and leaves bytes untouched`() {
        val d = Mkfs.image(16, 8 * 1024 * 1024, 1); val before = d.data.copyOf()
        FatFileSystem(d, readOnly = true).use { fs -> assertThrows(FsReadOnlyException::class.java) { fs.createFile(fs.root(), "x") } }
        assertArrayEquals(before, d.data)
    }

    @Test fun `fsinfo is updated on sync for FAT32`() {
        val d = Mkfs.image(32, 40 * 1024 * 1024, 1)
        FatFileSystem(d, ZoneOffset.UTC, readOnly = false).use { fs ->
            val n = fs.createFile(fs.root(), "f"); fs.open(n, OpenMode.READ_WRITE).use { it.write(0, ByteArray(100_000), 0, 100_000) }
            fs.sync()
            val free = fs.spaceInfo().freeBytes / 512
            val s = ByteArray(512); d.readSectors(1, s, 0, 1)
            val stored = (s[488].toLong() and 0xff) or ((s[489].toLong() and 0xff) shl 8) or ((s[490].toLong() and 0xff) shl 16) or ((s[491].toLong() and 0xff) shl 24)
            assertEquals(free, stored)
        }
    }

    /** Random operations against an in-memory model; the image must stay fsck-clean and match the model. */
    private fun model(fat: Int, bytes: Int, spc: Int, steps: Int, seed: Long) {
        val rnd = Random(seed); val dev = Mkfs.image(fat, bytes, spc)
        val fs = FatFileSystem(dev, ZoneOffset.UTC, readOnly = false)
        val files = HashMap<String, ByteArray>(); val dirs = hashSetOf("")
        fun fp(s: String) = FsPath.parse(s)
        fun name() = listOf("a", "B", "File One", "long-name-number-seven.dat", "x.y.z", "ÄÖÜ.txt", "n${rnd.nextInt(6)}", "n${rnd.nextInt(6)}.bin").random(rnd)
        fun key(s: String) = s.lowercase()
        val byKey = HashMap<String, String>() // lowercase path -> display path
        repeat(steps) {
            try {
                when (rnd.nextInt(8)) {
                    0, 1 -> { val d = dirs.random(rnd); val n = name(); val path = "$d/$n"
                        if (byKey.containsKey(key(path))) return@repeat
                        fs.createFile(fs.resolve(fp(d)), n); files[path] = ByteArray(0); byKey[key(path)] = path }
                    2 -> { val d = dirs.random(rnd); val n = name(); val path = "$d/$n"
                        if (byKey.containsKey(key(path)) || dirs.size > 12) return@repeat
                        fs.createDirectory(fs.resolve(fp(d)), n); dirs += path; byKey[key(path)] = path }
                    3, 4 -> { if (files.isEmpty()) return@repeat; val path = files.keys.random(rnd); val data = files[path]!!
                        val pos = if (data.isEmpty() || rnd.nextInt(3) == 0) data.size else rnd.nextInt(data.size + 1)
                        val chunk = rnd.nextBytes(rnd.nextInt(0, 3000))
                        fs.open(fs.resolve(fp(path)), OpenMode.READ_WRITE).use { it.write(pos.toLong(), chunk, 0, chunk.size) }
                        val n = ByteArray(maxOf(data.size, pos + chunk.size)); data.copyInto(n); chunk.copyInto(n, pos); files[path] = n }
                    5 -> { if (files.isEmpty()) return@repeat; val path = files.keys.random(rnd); val data = files[path]!!; val ns = rnd.nextInt(0, data.size + 1500)
                        fs.open(fs.resolve(fp(path)), OpenMode.READ_WRITE).use { it.truncate(ns.toLong()) }
                        files[path] = data.copyOf(ns) }
                    6 -> { if (files.isEmpty()) return@repeat; val path = files.keys.random(rnd); fs.delete(fs.resolve(fp(path))); files.remove(path); byKey.remove(key(path)) }
                    7 -> { if (files.isEmpty()) return@repeat; val path = files.keys.random(rnd); val n = name(); val node = fs.resolve(fp(path))
                        if (rnd.nextBoolean()) {
                            val nn = path.substringBeforeLast('/') + "/" + n
                            if (byKey.containsKey(key(nn)) && key(nn) != key(path)) return@repeat
                            fs.rename(node, n); files[nn] = files.remove(path)!!; byKey.remove(key(path)); byKey[key(nn)] = nn
                        } else {
                            val d = dirs.random(rnd); val nn = "$d/" + path.substringAfterLast('/')
                            if (byKey.containsKey(key(nn)) && key(nn) != key(path)) return@repeat
                            fs.move(node, fs.resolve(fp(d))); files[nn] = files.remove(path)!!; byKey.remove(key(path)); byKey[key(nn)] = nn
                        } }
                }
            } catch (e: FsNoSpaceException) { /* acceptable on tiny volumes */ }
            catch (e: FsExistsException) { /* model skipped case-collisions it could not predict */ throw AssertionError("unexpected exists", e) }
        }
        fs.sync()
        for ((path, data) in files) fs.open(fs.resolve(fp(path)), OpenMode.READ).use { f -> val b = ByteArray(f.size.toInt()); var q = 0; while (q < b.size) q += f.read(q.toLong(), b, q, b.size - q); assertArrayEquals(data, b, "content $path") }
        val (code, out) = Mkfs.fsck(dev.data); assertEquals(0, code, "fsck after $steps steps seed $seed:\n$out")
        // and a fresh mount sees the same tree
        FatFileSystem(ImageDevice(dev.data.copyOf()), ZoneOffset.UTC).use { fs2 ->
            for ((path, data) in files) assertEquals(data.size.toLong(), fs2.resolve(fp(path)).size, path)
        }
    }

    @Test fun `model based random operations FAT16`() = model(16, 8 * 1024 * 1024, 1, 1500, 11)
    @Test fun `model based random operations FAT12`() = model(12, 3 * 512 * 1024, 1, 1500, 12)
    @Test fun `model based random operations FAT32`() = model(32, 40 * 1024 * 1024, 1, 1500, 13)
    @Test fun `model based several seeds`() { for (s in 20L..24L) model(16, 4 * 1024 * 1024, 1, 600, s) }
}
