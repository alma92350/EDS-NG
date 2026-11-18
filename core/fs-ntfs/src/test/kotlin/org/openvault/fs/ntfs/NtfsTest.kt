package org.openvault.fs.ntfs

import com.google.gson.JsonObject
import com.google.gson.JsonParser
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource
import org.openvault.fs.*
import org.openvault.io.BlockDevice
import org.openvault.testkit.FileSystemReadContract
import java.io.File
import java.security.MessageDigest

class ImgDev(val data: ByteArray) : BlockDevice {
    override val sectorSize = 512; override val sectorCount = data.size / 512L; override val isReadOnly = true
    override fun readSectors(firstSector: Long, dst: ByteArray, off: Int, count: Int) = System.arraycopy(data, (firstSector * 512).toInt(), dst, off, count * 512)
    override fun writeSectors(firstSector: Long, src: ByteArray, off: Int, count: Int) = throw java.io.IOException("ro")
    override fun flush() {}; override fun close() {}
}

object NtfsFx {
    val dir = File("../../testing/fixtures")
    val catalog: JsonObject = JsonParser.parseString(File(dir, "ntfs_fixtures.json").readText()).asJsonObject
    fun image(n: String) = File(dir, catalog[n].asJsonObject["file"].asString).readBytes()
    fun files(n: String): Map<String, Pair<String, Long>> = catalog[n].asJsonObject["files"].asJsonObject.entrySet().associate { it.key to (it.value.asJsonObject["sha256"].asString to it.value.asJsonObject["size"].asLong) }
    fun path(n: String) = File(dir, catalog[n].asJsonObject["file"].asString).absolutePath
    fun sha(b: ByteArray) = MessageDigest.getInstance("SHA-256").digest(b).joinToString("") { "%02x".format(it) }
    fun readAll(fs: FileSystem, p: String): ByteArray = fs.open(fs.resolve(FsPath.parse(p)), OpenMode.READ).use { f -> ByteArray(f.size.toInt()).also { b -> var q = 0; while (q < b.size) { val r = f.read(q.toLong(), b, q, b.size - q); if (r < 0) break; q += r } } }
}

/** Shared read contract; file contents come from ntfscat (an independent NTFS implementation), not from our reader or the generator. */
class NtfsSmallContractTest : FileSystemReadContract() {
    override fun open(): FileSystem = NtfsFileSystem(ImgDev(NtfsFx.image("ntfs-small")))
    override val expected: Map<String, ByteArray> by lazy {
        NtfsFx.files("ntfs-small").keys.associateWith { p ->
            val pr = ProcessBuilder("ntfscat", "-f", NtfsFx.path("ntfs-small"), p).also { it.environment()["LC_ALL"] = "C.UTF-8" }.start()
            val b = pr.inputStream.readBytes(); check(pr.waitFor() == 0) { "ntfscat failed for $p" }; b
        }
    }
}

class NtfsTest {
    @ParameterizedTest @ValueSource(strings = ["ntfs", "ntfs512"])
    fun `whole tree - 1200 files incl sparse, fragmented, 400-entry index, holes - matches generator hashes`(name: String) {
        NtfsFileSystem(ImgDev(NtfsFx.image(name))).use { fs ->
            val want = NtfsFx.files(name); val seen = HashMap<String, Pair<String, Long>>()
            fun walk(n: FsNode) { for (c in fs.list(n)) if (c.isDirectory) walk(c) else { val b = NtfsFx.readAll(fs, c.path.toString()); seen[c.path.toString().removePrefix("/")] = NtfsFx.sha(b) to c.size } }
            walk(fs.root())
            assertEquals(want.keys.toSortedSet(), seen.keys.toSortedSet(), "file set")
            for ((p, w) in want) assertEquals(w, seen[p], p)
        }
    }

    @Test fun `label, free space (vs ntfsinfo) and read-only`() {
        NtfsFileSystem(ImgDev(NtfsFx.image("ntfs"))).use { fs ->
            assertEquals("NTFSTEST", fs.label); assertTrue(fs.isReadOnly)
            val info = ProcessBuilder("ntfsinfo", "-m", NtfsFx.path("ntfs")).start().inputStream.bufferedReader().readText()
            val free = Regex("Free Clusters:\\s+(\\d+)").find(info)!!.groupValues[1].toLong()
            assertEquals(free * 4096, fs.spaceInfo().freeBytes, "free space must match ntfsinfo")
            assertThrows(FsReadOnlyException::class.java) { fs.createFile(fs.root(), "x") }
            assertThrows(FsReadOnlyException::class.java) { fs.open(fs.resolve(FsPath.parse("hello.txt")), OpenMode.READ_WRITE) }
        }
    }

    @Test fun `attribute list and extension records are resolved (512-byte clusters)`() {
        NtfsFileSystem(ImgDev(NtfsFx.image("ntfs512"))).use { fs ->
            val b = NtfsFx.readAll(fs, "fragmented-big.bin")
            assertEquals(NtfsFx.files("ntfs512")["fragmented-big.bin"]!!.first, NtfsFx.sha(b))
            assertTrue(fs.attributeListReads > 0, "image must exercise \$ATTRIBUTE_LIST")
        }
    }

    @Test fun `sparse file reads zeros in holes`() {
        NtfsFileSystem(ImgDev(NtfsFx.image("ntfs"))).use { fs ->
            val n = fs.resolve(FsPath.parse("sparse.bin")); assertEquals(10L * 1024 * 1024, n.size)
            fs.open(n, OpenMode.READ).use { f ->
                val b = ByteArray(4096); assertEquals(4096, f.read(2_000_000, b, 0, 4096)); assertTrue(b.all { it == 0.toByte() })
                assertEquals(4096, f.read(5L * 1024 * 1024, b, 0, 4096)); assertEquals('M'.code.toByte(), b[0])
                assertEquals(-1, f.read(10L * 1024 * 1024, b, 0, 1))
            }
        }
    }

    @Test fun `case-insensitive lookup, unicode and long names`() {
        NtfsFileSystem(ImgDev(NtfsFx.image("ntfs"))).use { fs ->
            assertEquals("mixed\n", String(NtfsFx.readAll(fs, "MIXED CASE NAME.txt")))
            val uni = "ünïcode-ß-日本.txt"
            assertEquals("unicode name\n", String(NtfsFx.readAll(fs, uni.map { Character.toUpperCase(it) }.joinToString(""))))
            assertEquals(1, fs.list(fs.root()).count { it.name.length == 209 })
            assertEquals("deep\n", String(NtfsFx.readAll(fs, "a/b/c/deep.txt")))
        }
    }

    @Test fun `system metafiles and dos short names are hidden`() {
        NtfsFileSystem(ImgDev(NtfsFx.image("ntfs"))).use { fs ->
            val names = fs.list(fs.root()).map { it.name }
            assertTrue(names.none { it.startsWith("$") && it.length > 1 && it[1].isUpperCase() && it in setOf("\$MFT", "\$Bitmap", "\$LogFile", "\$Boot") }, names.toString())
            assertEquals(names.size, names.toSet().size)
            assertTrue(names.none { it.matches(Regex("[A-Z0-9_~]{1,8}~\\d(\\.[A-Z0-9]{1,3})?")) }, "no 8.3 aliases: $names")
        }
    }

    @Test fun `compressed files give a typed error, normal files still read`() {
        NtfsFileSystem(ImgDev(NtfsFx.image("ntfs-comp"))).use { fs ->
            assertEquals("plain file\n", String(NtfsFx.readAll(fs, "plain.txt")))
            val ex = assertThrows(FsException::class.java) { fs.open(fs.resolve(FsPath.parse("cdir/c.txt")), OpenMode.READ) }
            assertTrue(ex.message!!.contains("Compressed"), ex.message)
        }
    }

    @Test fun `torn mft record (fixup mismatch) is detected`() {
        val img = NtfsFx.image("ntfs-small")
        val mftLcn = java.nio.ByteBuffer.wrap(img, 0x30, 8).order(java.nio.ByteOrder.LITTLE_ENDIAN).long
        val off = (mftLcn * 4096 + 5 * 1024 + 510).toInt() // end of first sector of the root directory record
        img[off] = (img[off] + 1).toByte()
        assertThrows(FsCorruptException::class.java) { NtfsFileSystem(ImgDev(img)).use { it.list(it.root()) } }
    }

    @Test fun `bad geometry and foreign filesystems are rejected`() {
        val img = NtfsFx.image("ntfs-small"); img[0x0D] = 3 // sectors per cluster must be a power of two
        assertThrows(FsCorruptException::class.java) { NtfsFileSystem(ImgDev(img)) }
        assertThrows(UnsupportedFilesystemException::class.java) { NtfsFileSystem(ImgDev(ByteArray(512 * 64))) }
        val tooBig = NtfsFx.image("ntfs-small").copyOf(512 * 1024); // truncated device smaller than the filesystem
        assertThrows(FsCorruptException::class.java) { NtfsFileSystem(ImgDev(tooBig)) }
    }

    @Test fun `random garbage after the boot sector never hangs or crashes with anything but FsException`() {
        val rnd = java.util.Random(7)
        repeat(30) {
            val img = NtfsFx.image("ntfs-small")
            repeat(40) { img[(8192 + rnd.nextInt(2_000_000))] = rnd.nextInt().toByte() } // corrupt metadata/data area
            try { NtfsFileSystem(ImgDev(img)).use { fs -> fun walk(n: FsNode) { for (c in fs.list(n)) if (c.isDirectory) walk(c) else NtfsFx.readAll(fs, c.path.toString()) }; walk(fs.root()) } }
            catch (e: FsException) { /* expected */ }
        }
    }
}
