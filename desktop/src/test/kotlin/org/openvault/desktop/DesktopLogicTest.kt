package org.openvault.desktop

import com.google.gson.JsonObject
import com.google.gson.JsonParser
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import org.openvault.fs.FsPath
import java.io.File
import java.nio.file.Path
import java.security.MessageDigest

class DesktopLogicTest {
    private val dir = File("../testing/fixtures")
    private val cat: JsonObject = JsonParser.parseString(File(dir, "fixtures.json").readText()).asJsonObject
    private fun sha(b: ByteArray) = MessageDigest.getInstance("SHA-256").digest(b).joinToString("") { "%02x".format(it) }

    /** Copies a fixture so tests can write to it. */
    private fun copy(name: String, tmp: Path): File = File(tmp.toFile(), "c${System.nanoTime()}.hc").also { File(dir, cat[name].asJsonObject["file"].asString).copyTo(it) }

    private fun req(name: String, file: File, pw: String = cat[name].asJsonObject["password"].asString, readOnly: Boolean = true) = UnlockRequest(
        file, pw.toCharArray(), cat[name].asJsonObject["pim"].asInt, cat[name].asJsonObject["keyfiles"].asJsonArray.map { File(dir, it.asString) }, readOnly,
        truecrypt = cat[name].asJsonObject["mode"].asString == "truecrypt")

    @Test fun `unlock veracrypt truecrypt and keyfile fixtures and wipe the password array`(@TempDir t: Path) {
        for (n in listOf("aes_sha512_fat", "aes_sha512_keyfile", "tc_ripemd160", "aes_exfat")) {
            val r = req(n, copy(n, t)); val pw = r.password
            val o = Unlocker.open(r) as UnlockOutcome.Opened
            assertTrue(pw.all { it == '\u0000' }, "password wiped for $n")
            assertTrue(o.session.readOnly)
            assertTrue(o.session.sync { fs -> fs.list(fs.root()).isNotEmpty() }, n)
            o.session.lock()
        }
    }

    @Test fun `wrong password gives the generic message and cancel works`(@TempDir t: Path) {
        val f = copy("aes_sha512_fat", t)
        val bad = Unlocker.open(req("aes_sha512_fat", f, pw = "nope")) as UnlockOutcome.Failed
        assertTrue(bad.message.startsWith(Unlocker.GENERIC_FAILURE))
        assertTrue(Unlocker.open(req("aes_sha512_fat", f), cancelled = { true }) is UnlockOutcome.Cancelled)
    }

    @Test fun `import export round trip with keep-both, folders, and persistence`(@TempDir t: Path) {
        val f = copy("aes_sha512_fat", t)
        val src = File(t.toFile(), "src").also { it.mkdirs() }
        File(src, "a.txt").writeText("hello a"); File(src, "big.bin").writeBytes(ByteArray(300_000) { (it * 3).toByte() })
        File(src, "sub").mkdir(); File(src, "sub/x.txt").writeText("nested")
        val o = Unlocker.open(req("aes_sha512_fat", f, readOnly = false)) as UnlockOutcome.Opened
        val s = o.session; assertFalse(s.readOnly)
        assertEquals(2, s.sync { fs -> Transfer.importPath(fs, FsPath.ROOT, File(src, "a.txt")) + Transfer.importPath(fs, FsPath.ROOT, File(src, "big.bin")) })
        assertEquals(1, s.sync { fs -> Transfer.importPath(fs, FsPath.ROOT, File(src, "a.txt")) }) // conflict -> "a (1).txt"
        assertEquals(1, s.sync { fs -> Transfer.importPath(fs, FsPath.ROOT, File(src, "sub")) }) // folder with one file
        s.lock()
        // reopen from disk and export everything
        val s2 = (Unlocker.open(req("aes_sha512_fat", f)) as UnlockOutcome.Opened).session
        val out = File(t.toFile(), "out").also { it.mkdirs() }
        val names = s2.sync { fs -> fs.list(fs.root()).map { it.name } }
        assertTrue("a.txt" in names && "a (1).txt" in names && "sub" in names, names.toString())
        s2.sync { fs -> Transfer.exportTo(fs, fs.resolve(FsPath.parse("big.bin")), out); Transfer.exportTo(fs, fs.resolve(FsPath.parse("sub")), out); Transfer.exportTo(fs, fs.resolve(FsPath.parse("big.bin")), out) }
        assertEquals(sha(File(src, "big.bin").readBytes()), sha(File(out, "big.bin").readBytes()))
        assertEquals("nested", File(out, "sub/x.txt").readText()); assertTrue(File(out, "big (1).bin").exists(), "export never overwrites")
        s2.lock()
    }

    @Test fun `cancelled import leaves no partial file`(@TempDir t: Path) {
        val f = copy("aes_sha512_fat", t); val big = File(t.toFile(), "b.bin").also { it.writeBytes(ByteArray(2_000_000)) }
        val s = (Unlocker.open(req("aes_sha512_fat", f, readOnly = false)) as UnlockOutcome.Opened).session
        var calls = 0
        s.sync { fs -> assertNull(big.inputStream().use { Transfer.importStream(fs, FsPath.ROOT, "b.bin", it, cancelled = { calls++ > 2 }) }) }
        assertFalse(s.sync { fs -> fs.list(fs.root()).any { it.name == "b.bin" } })
        s.lock()
    }

    @Test fun `viewer read limit and locked session refuses work`(@TempDir t: Path) {
        val s = (Unlocker.open(req("aes_sha512_fat", copy("aes_sha512_fat", t))) as UnlockOutcome.Opened).session
        assertEquals("hello a\n", String(s.sync { fs -> Transfer.readBytes(fs, FsPath.parse("hello.txt"), 1000) }))
        assertThrows(java.io.IOException::class.java) { s.sync { fs -> Transfer.readBytes(fs, FsPath.parse("data.bin"), 10) } }
        s.lock(); assertTrue(s.locked)
        assertThrows(java.io.IOException::class.java) { s.sync { it.root() } }
    }

    @Test fun `ntfs container opened read-write is forced read-only with a notice`(@TempDir t: Path) {
        val f = copy("aes_ntfs", t)
        val o = Unlocker.open(req("aes_ntfs", f, readOnly = false)) as UnlockOutcome.Opened
        assertTrue(o.session.readOnly, "NTFS sessions must report read-only so the UI hides write actions")
        assertNotNull(o.warning); assertTrue(o.warning!!.contains("read-only"))
        assertEquals("VAULT", o.session.sync { it.label }); o.session.lock()
    }
}
