package org.openvault.cli

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.PrintStream
import java.security.MessageDigest

class CliTest {
    private val dir = File("../../testing/fixtures")
    private fun c(n: String) = File(dir, n).path
    private class R(val code: Int, val out: ByteArray, val err: String) { val text get() = String(out, Charsets.UTF_8) }
    private fun cli(vararg a: String, stdin: String = "test\n"): R {
        val o = ByteArrayOutputStream(); val e = ByteArrayOutputStream()
        val code = run(a.toList(), ByteArrayInputStream(stdin.toByteArray()), o, PrintStream(e, true))
        return R(code, o.toByteArray(), e.toString())
    }

    @Test fun `info prints details and never the password or key`() {
        val r = cli("info", c("aes_sha512_fat.hc"), "--password-stdin", "--prf", "sha512")
        assertEquals(0, r.code, r.err)
        assertTrue("volume:     normal\n" in r.text && "prf:        SHA-512" in r.text && "filesystem: FAT16" in r.text && "mode:       read-only" in r.text, r.text)
        assertFalse("test" in r.text.replace("filesystem", ""))
    }

    @Test fun `ls lists folders first with sizes`() {
        val r = cli("ls", c("aes_sha512_fat.hc"), "--password-stdin", "--prf", "sha512")
        assertEquals(0, r.code, r.err)
        val lines = r.text.trim().lines()
        assertTrue(lines[0].startsWith("d ") && lines[0].endsWith("docs/"), r.text)
        assertTrue(lines.any { it.startsWith("-") && it.endsWith("hello.txt") })
    }

    @Test fun `cat streams file bytes exactly`() {
        val r = cli("cat", c("aes_sha512_fat.hc"), "hello.txt", "--password-stdin", "--prf", "sha512")
        assertEquals("hello a\n", r.text)
    }

    @Test fun `get copies a large file with matching hash`() {
        val dst = File.createTempFile("ovt", ".bin")
        try {
            assertEquals(0, cli("get", c("aes_sha512_fat.hc"), "data.bin", dst.path, "--password-stdin", "--prf", "sha512").code)
            val h = MessageDigest.getInstance("SHA-256").digest(dst.readBytes()).joinToString("") { "%02x".format(it) }
            assertTrue(File(dir, "fixtures.json").readText().contains(h))
        } finally { dst.delete() }
    }

    @Test fun `wrong password gives the single generic message`() {
        val r = cli("ls", c("aes_sha512_fat.hc"), "--password-stdin", "--prf", "sha512", stdin = "wrong\n")
        assertEquals(1, r.code); assertEquals("error: Incorrect password, PIM, keyfiles or unsupported settings\n", r.err)
    }

    @Test fun `pim and keyfile options work`() {
        assertEquals(0, cli("ls", c("aes_sha512_pim10.hc"), "--password-stdin", "--prf", "sha512", "--pim", "10").code)
        assertEquals(0, cli("ls", c("aes_sha512_keyfile.hc"), "--password-stdin", "--prf", "sha512", "-k", c("keyfile1.bin"), "-k", c("keyfile2.bin")).code)
    }

    @Test fun `missing path and usage errors`() {
        assertEquals(1, cli("cat", c("aes_sha512_fat.hc"), "nope.txt", "--password-stdin", "--prf", "sha512").code)
        assertEquals(2, cli("ls").code)
        assertEquals(1, cli("frobnicate", c("aes_sha512_fat.hc")).code)
        assertEquals(1, cli("ls", c("aes_sha512_fat.hc")).code) // no password given
    }
}
