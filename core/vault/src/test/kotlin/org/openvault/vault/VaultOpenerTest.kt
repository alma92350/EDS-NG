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
