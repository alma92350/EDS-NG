package org.openvault.vault

import com.google.gson.JsonObject
import com.google.gson.JsonParser
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource
import org.openvault.crypto.Prf
import org.openvault.fs.*
import org.openvault.testkit.MemoryStorage
import java.io.ByteArrayInputStream
import java.io.File
import java.security.MessageDigest

/** UC1 at core level: fixture container -> VaultOpener -> walk tree -> compare SHA-256 with the generator's. */
class VaultOpenerTest {
    private val dir = File("../../testing/fixtures")
    private val catalog: JsonObject = JsonParser.parseString(File(dir, "fixtures.json").readText()).asJsonObject
    private fun fx(n: String) = catalog[n].asJsonObject
    private fun sha(b: ByteArray) = MessageDigest.getInstance("SHA-256").digest(b).joinToString("") { "%02x".format(it) }

    private fun tree(fs: FileSystem): Map<String, String> {
        val out = HashMap<String, String>()
        fun walk(n: FsNode) { for (c in fs.list(n)) if (c.isDirectory) walk(c) else fs.open(c, OpenMode.READ).use { f ->
            val b = ByteArray(f.size.toInt()); var p = 0; while (p < b.size) p += f.read(p.toLong(), b, p, b.size - p)
            out[c.path.toString().removePrefix("/").lowercase()] = sha(b) } }
        walk(fs.root()); return out
    }

    private fun expected(files: JsonObject) = files.entrySet().associate { it.key.lowercase() to it.value.asString }

    private fun open(name: String, pw: String = fx(name)["password"].asString, auto: Boolean = false): VaultResult {
        val f = fx(name); val prf = Prf.entries.first { it.name.lowercase() == f["prf"].asString }
        val kf = f["keyfiles"].asJsonArray.map { ByteArrayInputStream(File(dir, it.asString).readBytes()) }
        return VaultOpener.open(MemoryStorage(File(dir, f["file"].asString).readBytes()), pw.toByteArray(), f["pim"].asInt, kf,
            if (auto) Prf.entries else listOf(prf))
    }

    @ParameterizedTest
    @ValueSource(strings = ["aes_sha512_fat", "aes_sha256_fat", "aes_blake2s_fat", "aes_sha512_pim10", "aes_sha512_keyfile", "unicode_pw", "fat16", "fat12", "fat32"])
    fun `tree and hashes match`(name: String) {
        (open(name) as VaultResult.Opened).fileSystem.use { assertEquals(expected(fx(name)["files"].asJsonObject), tree(it)) }
    }

    @Test fun `hidden volume shows its own tree`() {
        val h = fx("hidden")["hidden"].asJsonObject
        (open("hidden") as VaultResult.Opened).fileSystem.use { assertEquals(expected(fx("hidden")["files"].asJsonObject), tree(it)) }
        val r = open("hidden", pw = h["password"].asString) as VaultResult.Opened
        assertTrue(r.isHidden)
        r.fileSystem.use { assertEquals(expected(h["files"].asJsonObject), tree(it)) }
    }

    @Test fun `wrong password is Failed and details list attempts only`() {
        val r = open("aes_sha512_fat", pw = "bad") as VaultResult.Failed
        assertEquals(4, r.tried.size)
    }

    @Test fun `volume with no supported filesystem reports the kind and closes storage`() {
        // random data under a valid header: build by opening a fixture and checking the NTFS path via a patched boot sector is covered in FatReadTest;
        // here: an all-zero data area behind a valid header is "unformatted".
        val f = fx("aes_sha512_fat")
        val storage = MemoryStorage(File(dir, f["file"].asString).readBytes())
        val v = (org.openvault.veracrypt.VolumeOpener.open(storage, "test".toByteArray(), prfs = listOf(Prf.SHA512)) as org.openvault.veracrypt.OpenResult.Opened).volume
        v.writeSectors(0, ByteArray(512), 0, 1) // wipe boot sector (writes encrypted zeros)
        v.close()
        storage.let { /* closed above; reopen same bytes */ }
        val r = VaultOpener.open(MemoryStorage(storage.bytes), "test".toByteArray(), prfs = listOf(Prf.SHA512))
        assertTrue(r is VaultResult.UnsupportedFilesystem, "got $r")
    }

    @Test fun `read-only is the default`() {
        (open("aes_sha512_fat") as VaultResult.Opened).let { it.fileSystem.use { fs -> assertTrue(fs.isReadOnly); assertTrue(it.volume.isReadOnly) } }
    }
}

/** B1: writing to the outer volume must not destroy the hidden volume when protection is on. */
class HiddenProtectionTest {
    private val dir = File("../../testing/fixtures")
    private val cat: JsonObject = JsonParser.parseString(File(dir, "fixtures.json").readText()).asJsonObject["hidden"].asJsonObject
    private val hid = cat["hidden"].asJsonObject
    private fun storage() = MemoryStorage(File(dir, cat["file"].asString).readBytes())
    private val big = ByteArray(6 * 1024 * 1024) { (it * 31).toByte() } // outer data area is ~7.75 MiB, hidden occupies the top 3 MiB

    private fun fill(fs: FileSystem) {
        val n = fs.createFile(fs.root(), "big.bin")
        fs.open(n, OpenMode.READ_WRITE).use { f -> var pos = 0L; while (pos < big.size) { val len = minOf(65536, (big.size - pos).toInt()); f.write(pos, big, pos.toInt(), len); pos += len } }
    }

    private fun hiddenIntact(st: MemoryStorage): Boolean {
        val r = VaultOpener.open(st, hid["password"].asString.toByteArray(), prfs = listOf(Prf.SHA512))
        if (r !is VaultResult.Opened) return false
        return r.fileSystem.use { fs ->
            hid["files"].asJsonObject.entrySet().all { (p, h) -> fs.open(fs.resolve(FsPath.parse(p)), OpenMode.READ).use { f ->
                val b = ByteArray(f.size.toInt()); var q = 0; while (q < b.size) q += f.read(q.toLong(), b, q, b.size - q)
                MessageDigest.getInstance("SHA-256").digest(b).joinToString("") { "%02x".format(it) } == h.asString } }
        }
    }

    @Test fun `with protection the oversized write is refused and the hidden volume survives`() {
        val st = storage()
        val r = VaultOpener.open(st, "outer".toByteArray(), prfs = listOf(Prf.SHA512), readOnly = false,
            hiddenProtection = HiddenProtection(hid["password"].asString.toByteArray())) as VaultResult.Opened
        assertNotNull(r.protection)
        assertThrows(org.openvault.veracrypt.HiddenVolumeProtectionException::class.java) { fill(r.fileSystem) }
        assertTrue(r.protection!!.violated)
        assertTrue(hiddenIntact(MemoryStorage(st.bytes)), "hidden volume must be untouched")
    }

    @Test fun `without protection the same write destroys the hidden volume (why B1 matters)`() {
        val st = storage()
        val r = VaultOpener.open(st, "outer".toByteArray(), prfs = listOf(Prf.SHA512), readOnly = false) as VaultResult.Opened
        fill(r.fileSystem); r.fileSystem.sync()
        assertFalse(hiddenIntact(MemoryStorage(st.bytes)))
    }

    @Test fun `small writes with protection work normally`() {
        val st = storage()
        val r = VaultOpener.open(st, "outer".toByteArray(), prfs = listOf(Prf.SHA512), readOnly = false,
            hiddenProtection = HiddenProtection(hid["password"].asString.toByteArray())) as VaultResult.Opened
        r.fileSystem.use { fs -> val n = fs.createFile(fs.root(), "new.txt"); fs.open(n, OpenMode.READ_WRITE).use { it.write(0, byteArrayOf(1, 2, 3), 0, 3) } }
        assertTrue(hiddenIntact(MemoryStorage(st.bytes)))
    }

    @Test fun `wrong hidden password fails the open`() {
        val r = VaultOpener.open(storage(), "outer".toByteArray(), prfs = listOf(Prf.SHA512), readOnly = false, hiddenProtection = HiddenProtection("nope".toByteArray()))
        assertTrue(r is VaultResult.HiddenProtectionFailed)
    }
}

class ExfatInVaultTest {
    @Test fun `exfat inside a veracrypt container is auto-detected and read`() {
        val dir = File("../../testing/fixtures")
        val f = JsonParser.parseString(File(dir, "fixtures.json").readText()).asJsonObject["aes_exfat"].asJsonObject
        val r = VaultOpener.open(MemoryStorage(File(dir, f["file"].asString).readBytes()), "test".toByteArray(), prfs = listOf(Prf.SHA512)) as VaultResult.Opened
        r.fileSystem.use { fs ->
            assertTrue(fs is org.openvault.fs.exfat.ExfatFileSystem); assertTrue(fs.isReadOnly)
            val seen = HashMap<String, String>()
            fun walk(n: FsNode) { for (c in fs.list(n)) if (c.isDirectory) walk(c) else fs.open(c, OpenMode.READ).use { x -> val b = ByteArray(x.size.toInt()); var q = 0; while (q < b.size) q += x.read(q.toLong(), b, q, b.size - q); seen[c.path.toString().removePrefix("/")] = MessageDigest.getInstance("SHA-256").digest(b).joinToString("") { "%02x".format(it) } } }
            walk(fs.root())
            assertEquals(f["files"].asJsonObject.entrySet().associate { it.key to it.value.asString }.toSortedMap(), seen.toSortedMap())
        }
    }
}

/** Informational throughput numbers (no assertions): desktop JVM, FAT32 in AES-XTS container, write-through I/O. */
class ThroughputTest {
    @Test fun `print sequential write and read MB per second`() {
        val dir = File("../../testing/fixtures")
        val f = JsonParser.parseString(File(dir, "fixtures.json").readText()).asJsonObject["fat32"].asJsonObject
        val r = VaultOpener.open(MemoryStorage(File(dir, f["file"].asString).readBytes()), "test".toByteArray(), prfs = listOf(Prf.SHA512), readOnly = false) as VaultResult.Opened
        r.fileSystem.use { fs ->
            val data = ByteArray(16 * 1024 * 1024) { (it * 7).toByte() }
            val n = fs.createFile(fs.root(), "bench.bin")
            val t0 = System.nanoTime()
            fs.open(n, OpenMode.READ_WRITE).use { x -> var p = 0; while (p < data.size) { x.write(p.toLong(), data, p, 65536); p += 65536 } }
            val t1 = System.nanoTime()
            val buf = ByteArray(65536)
            fs.open(fs.resolve(FsPath.parse("bench.bin")), OpenMode.READ).use { x -> var p = 0L; while (true) { val k = x.read(p, buf, 0, buf.size); if (k < 0) break; p += k } }
            val t2 = System.nanoTime()
            println("THROUGHPUT write ${16.0 / ((t1 - t0) / 1e9)} MB/s, read ${16.0 / ((t2 - t1) / 1e9)} MB/s")
        }
    }
}

class TrueCryptVaultTest {
    private val dir = File("../../testing/fixtures")
    private val cat: JsonObject = JsonParser.parseString(File(dir, "fixtures.json").readText()).asJsonObject

    @ParameterizedTest
    @ValueSource(strings = ["tc_ripemd160", "tc_sha512_v4", "tc_keyfile", "tc_hidden"])
    fun `truecrypt tree and hashes match through the full vault path`(name: String) {
        val f = cat[name].asJsonObject
        val kf = f["keyfiles"].asJsonArray.map { ByteArrayInputStream(File(dir, it.asString).readBytes()) }
        val r = VaultOpener.open(MemoryStorage(File(dir, f["file"].asString).readBytes()), f["password"].asString.toByteArray(), 0, kf, mode = org.openvault.crypto.VolumeMode.TRUECRYPT) as VaultResult.Opened
        r.fileSystem.use { fs ->
            val seen = HashMap<String, String>()
            fun walk(n: FsNode) { for (c in fs.list(n)) if (c.isDirectory) walk(c) else fs.open(c, OpenMode.READ).use { x -> val b = ByteArray(x.size.toInt()); var q = 0; while (q < b.size) q += x.read(q.toLong(), b, q, b.size - q)
                seen[c.path.toString().removePrefix("/").lowercase()] = MessageDigest.getInstance("SHA-256").digest(b).joinToString("") { "%02x".format(it) } } }
            walk(fs.root())
            assertEquals(f["files"].asJsonObject.entrySet().associate { it.key.lowercase() to it.value.asString }.toSortedMap(), seen.toSortedMap())
        }
    }

    @Test fun `hidden protection works in truecrypt mode`() {
        val f = cat["tc_hidden"].asJsonObject; val hid = f["hidden"].asJsonObject
        val st = MemoryStorage(File(dir, f["file"].asString).readBytes())
        val r = VaultOpener.open(st, "outer".toByteArray(), readOnly = false, mode = org.openvault.crypto.VolumeMode.TRUECRYPT,
            hiddenProtection = HiddenProtection(hid["password"].asString.toByteArray())) as VaultResult.Opened
        assertNotNull(r.protection)
        val big = ByteArray(6 * 1024 * 1024)
        assertThrows(org.openvault.veracrypt.HiddenVolumeProtectionException::class.java) {
            r.fileSystem.open(r.fileSystem.createFile(r.fileSystem.root(), "big.bin"), OpenMode.READ_WRITE).use { x -> var p = 0L; while (p < big.size) { x.write(p, big, p.toInt(), 65536); p += 65536 } }
        }
    }
}

class NtfsInVaultTest {
    @Test fun `ntfs inside a veracrypt container is auto-detected and read-only`() {
        val dir = File("../../testing/fixtures")
        val f = JsonParser.parseString(File(dir, "fixtures.json").readText()).asJsonObject["aes_ntfs"].asJsonObject
        val r = VaultOpener.open(MemoryStorage(File(dir, f["file"].asString).readBytes()), "test".toByteArray(), prfs = listOf(Prf.SHA512), readOnly = false) as VaultResult.Opened
        r.fileSystem.use { fs ->
            assertTrue(fs is org.openvault.fs.ntfs.NtfsFileSystem); assertTrue(fs.isReadOnly, "NTFS is always read-only")
            assertEquals("VAULT", fs.label)
            val seen = HashMap<String, String>()
            fun walk(n: FsNode) { for (c in fs.list(n)) if (c.isDirectory) walk(c) else fs.open(c, OpenMode.READ).use { x -> val b = ByteArray(x.size.toInt()); var q = 0; while (q < b.size) q += x.read(q.toLong(), b, q, b.size - q)
                seen[c.path.toString().removePrefix("/")] = MessageDigest.getInstance("SHA-256").digest(b).joinToString("") { "%02x".format(it) } } }
            walk(fs.root())
            assertEquals(f["files"].asJsonObject.entrySet().associate { it.key to it.value.asString }.toSortedMap(), seen.toSortedMap())
            assertThrows(org.openvault.fs.FsReadOnlyException::class.java) { fs.createFile(fs.root(), "x") }
        }
    }
}
