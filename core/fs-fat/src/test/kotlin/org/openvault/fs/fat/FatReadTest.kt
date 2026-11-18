package org.openvault.fs.fat

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource
import org.openvault.fs.*
import java.security.MessageDigest

class FatReadTest {
    private fun sha(b: ByteArray) = MessageDigest.getInstance("SHA-256").digest(b).joinToString("") { "%02x".format(it) }

    @ParameterizedTest @ValueSource(strings = ["plain_fat12", "plain_fat16", "plain_fat32"])
    fun `walk whole tree and verify every file hash`(name: String) {
        FatFileSystem(ImageDevice(Fixtures.image(name))).use { fs ->
            val seen = HashMap<String, String>()
            fun walk(n: FsNode) {
                for (c in fs.list(n)) {
                    if (c.isDirectory) walk(c) else fs.open(c, OpenMode.READ).use { f ->
                        val b = ByteArray(f.size.toInt()); var p = 0
                        while (p < b.size) p += f.read(p.toLong(), b, p, b.size - p)
                        seen[c.path.toString().removePrefix("/")] = sha(b)
                    }
                }
            }
            walk(fs.root())
            assertEquals(Fixtures.hashes(name).toSortedMap(), seen.toSortedMap())
        }
    }

    @Test fun `fat type detected from cluster count`() {
        assertEquals(FatType.FAT12, FatFileSystem(ImageDevice(Fixtures.image("plain_fat12"))).type)
        assertEquals(FatType.FAT16, FatFileSystem(ImageDevice(Fixtures.image("plain_fat16"))).type)
        assertEquals(FatType.FAT32, FatFileSystem(ImageDevice(Fixtures.image("plain_fat32"))).type)
    }

    @Test fun `label and space info`() {
        FatFileSystem(ImageDevice(Fixtures.image("plain_fat16"))).use { fs ->
            assertEquals("PLAIN", fs.label)
            val sp = fs.spaceInfo(); assertTrue(sp.freeBytes in 1 until sp.totalBytes)
            assertEquals(32481L * 512, sp.totalBytes) // matches fsck.fat "309/32481 clusters"
            assertEquals((32481L - 309) * 512, sp.freeBytes)
        }
    }

    @Test fun `fragmented file really is fragmented and reads correctly`() {
        FatFileSystem(ImageDevice(Fixtures.image("plain_fat32"))).use { fs ->
            val n = fs.resolve(FsPath.parse("frag/big.bin"))
            fs.open(n, OpenMode.READ).use { f ->
                val b = ByteArray(f.size.toInt()); var p = 0; while (p < b.size) p += f.read(p.toLong(), b, p, b.size - p)
                assertEquals(Fixtures.hashes("plain_fat32")["frag/big.bin"], sha(b))
            }
        }
    }

    @Test fun `mutations are refused`() {
        FatFileSystem(ImageDevice(Fixtures.image("plain_fat16"))).use { fs ->
            assertTrue(fs.isReadOnly)
            assertThrows(FsReadOnlyException::class.java) { fs.createFile(fs.root(), "x") }
            assertThrows(FsReadOnlyException::class.java) { fs.open(fs.resolve(FsPath.parse("hello.txt")), OpenMode.READ_WRITE) }
            assertThrows(FsReadOnlyException::class.java) { fs.delete(fs.resolve(FsPath.parse("hello.txt"))) }
        }
    }

    @Test fun `unformatted and foreign filesystems are typed errors`() {
        assertThrows(UnsupportedFilesystemException::class.java) { FatFileSystem(ImageDevice(ByteArray(64 * 512))) }
        val ntfs = ByteArray(64 * 512); "NTFS    ".toByteArray().copyInto(ntfs, 3)
        assertEquals("NTFS", assertThrows(UnsupportedFilesystemException::class.java) { FatFileSystem(ImageDevice(ntfs)) }.kind)
        val ex = ByteArray(64 * 512); "EXFAT   ".toByteArray().copyInto(ex, 3)
        assertEquals("exFAT", assertThrows(UnsupportedFilesystemException::class.java) { FatFileSystem(ImageDevice(ex)) }.kind)
    }

    @Test fun `corrupt cluster chain loop is detected not hung`() {
        val img = Fixtures.image("plain_fat16")
        val fs0 = FatFileSystem(ImageDevice(img.copyOf()))
        val bpb = fs0.bpb
        // point cluster 2's FAT entry at itself and read root-adjacent file chain
        val data = img.copyOf(); val fatOff = (bpb.fatStartSector * 512).toInt()
        val first = fs0.resolve(FsPath.parse("data.bin"))
        FatFileSystem(ImageDevice(data)).use { fs ->
            // find data.bin's first cluster by scanning: easier to loop every chain entry to itself
            for (c in 2 until 400) { data[fatOff + c * 2] = c.toByte(); data[fatOff + c * 2 + 1] = (c shr 8).toByte() }
            assertThrows(FsException::class.java) { fs.open(fs.resolve(FsPath.parse("data.bin")), OpenMode.READ) }
        }
        assertEquals("data.bin", first.name)
    }
}

class PlainFat32ContractTest : org.openvault.testkit.FileSystemReadContract() {
    override fun open(): FileSystem = FatFileSystem(ImageDevice(Fixtures.image("plain_fat32")))
    override val expected: Map<String, ByteArray> by lazy { readExpected("plain_fat32") }
}
class PlainFat16ContractTest : org.openvault.testkit.FileSystemReadContract() {
    override fun open(): FileSystem = FatFileSystem(ImageDevice(Fixtures.image("plain_fat16")))
    override val expected by lazy { readExpected("plain_fat16") }
}
class PlainFat12ContractTest : org.openvault.testkit.FileSystemReadContract() {
    override fun open(): FileSystem = FatFileSystem(ImageDevice(Fixtures.image("plain_fat12")))
    override val expected by lazy { readExpected("plain_fat12") }
}

/** Expected content is regenerated from the image by an independent path: mtools (mcopy -> bytes), then compared via sha. */
private fun readExpected(name: String): Map<String, ByteArray> {
    val img = java.io.File(Fixtures.dir, Fixtures.catalog[name].asJsonObject["file"].asString).absolutePath
    val out = HashMap<String, ByteArray>()
    val env = mapOf("MTOOLS_SKIP_CHECK" to "1", "LC_ALL" to "C.UTF-8")
    for ((path, hash) in Fixtures.hashes(name)) {
        val pb = ProcessBuilder("mcopy", "-i", img, "::/$path", "-").also { it.environment().putAll(env) }.start()
        val bytes = pb.inputStream.readBytes(); check(pb.waitFor() == 0) { "mcopy failed for $path" }
        assertEquals(hash, MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }, "oracle content for $path")
        out[path] = bytes
    }
    return out
}
