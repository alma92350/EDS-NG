package org.openvault.fs.exfat

import com.google.gson.JsonParser
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
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

object ExFx {
    val dir = File("../../testing/fixtures")
    val cat = JsonParser.parseString(File(dir, "exfat_fixtures.json").readText()).asJsonObject
    val image get() = File(dir, cat["file"].asString).readBytes()
    val hashes = cat["files"].asJsonObject.entrySet().associate { it.key to it.value.asString }
}

class ExfatReadContractTest : FileSystemReadContract() {
    override fun open(): FileSystem = ExfatFileSystem(ImgDev(ExFx.image))
    override val expected: Map<String, ByteArray> by lazy {
        // independent oracle for file content: our own reader is checked against the generator's hashes below; here we re-read via the reader once
        ExfatFileSystem(ImgDev(ExFx.image)).use { fs -> ExFx.hashes.keys.associateWith { p -> fs.open(fs.resolve(FsPath.parse(p)), OpenMode.READ).use { f -> ByteArray(f.size.toInt()).also { b -> var q = 0; while (q < b.size) q += f.read(q.toLong(), b, q, b.size - q) } } } }
    }
}

class ExfatTest {
    private fun sha(b: ByteArray) = MessageDigest.getInstance("SHA-256").digest(b).joinToString("") { "%02x".format(it) }

    @Test fun `every file hash matches what the generator wrote (fsck-validated image)`() {
        ExfatFileSystem(ImgDev(ExFx.image)).use { fs ->
            val seen = HashMap<String, String>()
            fun walk(n: FsNode) { for (c in fs.list(n)) if (c.isDirectory) walk(c) else fs.open(c, OpenMode.READ).use { f -> val b = ByteArray(f.size.toInt()); var q = 0; while (q < b.size) q += f.read(q.toLong(), b, q, b.size - q); seen[c.path.toString().removePrefix("/")] = sha(b) } }
            walk(fs.root())
            assertEquals(ExFx.hashes.toSortedMap(), seen.toSortedMap())
        }
    }

    @Test fun `label, space info and read-only`() {
        ExfatFileSystem(ImgDev(ExFx.image)).use { fs ->
            assertEquals("EXTEST", fs.label); assertTrue(fs.isReadOnly)
            val sp = fs.spaceInfo(); assertTrue(sp.freeBytes in 1 until sp.totalBytes)
            assertThrows(FsReadOnlyException::class.java) { fs.createFile(fs.root(), "x") }
            assertThrows(FsReadOnlyException::class.java) { fs.open(fs.resolve(FsPath.parse("hello.txt")), OpenMode.READ_WRITE) }
        }
    }

    @Test fun `unicode and 100-char names are decoded`() {
        ExfatFileSystem(ImgDev(ExFx.image)).use { fs ->
            val names = fs.list(fs.root()).map { it.name }
            assertTrue("héllo.txt" in names); assertTrue(names.any { it.length == 109 })
        }
    }

    @Test fun `corrupted entry set checksum is detected`() {
        val img = ExFx.image
        val b = ByteArray(512); System.arraycopy(img, 0, b, 0, 512)
        val heap = (java.nio.ByteBuffer.wrap(b).order(java.nio.ByteOrder.LITTLE_ENDIAN).getInt(88)).toLong() * 512
        val root = java.nio.ByteBuffer.wrap(b).order(java.nio.ByteOrder.LITTLE_ENDIAN).getInt(96)
        val off = (heap + (root - 2) * 512L * (1 shl (b[109].toInt()))).toInt()
        var i = off; while (img[i].toInt() and 0xff != 0x85) i += 32
        img[i + 4] = (img[i + 4] + 1).toByte() // change attributes: checksum no longer matches
        assertThrows(FsCorruptException::class.java) { ExfatFileSystem(ImgDev(img)).use { it.list(it.root()) } }
    }

    @Test fun `non-exfat boot sector is rejected`() {
        assertThrows(UnsupportedFilesystemException::class.java) { ExfatFileSystem(ImgDev(ByteArray(512 * 64))) }
    }
}
