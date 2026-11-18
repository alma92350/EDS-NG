package org.openvault.testkit

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.openvault.fs.*
import kotlin.random.Random

/**
 * Write-side contract. [fresh] returns an empty, writable filesystem; [remount] syncs it and returns a NEW
 * instance over the same bytes (proves persistence). Capacity must be well under 8 MiB for the no-space test.
 */
abstract class FileSystemWriteContract {
    protected abstract fun fresh(): FileSystem
    protected abstract fun remount(fs: FileSystem): FileSystem

    private fun p(s: String) = FsPath.parse(s)
    private fun FileSystem.write(path: String, data: ByteArray): FsNode {
        val parent = resolve(p(path).parent); val n = createFile(parent, p(path).name)
        open(n, OpenMode.READ_WRITE).use { f -> f.write(0, data, 0, data.size); f.flush() }
        return n
    }
    private fun FileSystem.read(path: String): ByteArray = open(resolve(p(path)), OpenMode.READ).use { f ->
        val b = ByteArray(f.size.toInt()); var q = 0; while (q < b.size) q += f.read(q.toLong(), b, q, b.size - q); b }

    @Test fun `create write read back`() {
        fresh().use { fs -> val d = Random(1).nextBytes(1500); fs.write("a.bin", d); assertArrayEquals(d, fs.read("a.bin")); assertEquals(1500, fs.resolve(p("a.bin")).size) }
    }

    @Test fun `data persists across remount`() {
        val fs = fresh(); val d = Random(2).nextBytes(70_000)
        fs.createDirectory(fs.root(), "docs"); fs.write("docs/big.bin", d); fs.write("empty.txt", ByteArray(0))
        val fs2 = remount(fs)
        assertArrayEquals(d, fs2.read("docs/big.bin")); assertEquals(0, fs2.resolve(p("empty.txt")).size)
        assertTrue(fs2.resolve(p("docs")).isDirectory)
    }

    @Test fun `overwrite in the middle and append`() {
        fresh().use { fs ->
            val d = Random(3).nextBytes(5000); fs.write("f", d)
            val patch = ByteArray(700) { 7 }
            fs.open(fs.resolve(p("f")), OpenMode.READ_WRITE).use { it.write(1000, patch, 0, 700); it.write(5000, patch, 0, 700) }
            val e = d.copyOf(5700); patch.copyInto(e, 1000); patch.copyInto(e, 5000)
            assertArrayEquals(e, fs.read("f"))
        }
    }

    @Test fun `sparse write zero fills the gap`() {
        fresh().use { fs ->
            fs.write("s", ByteArray(100) { 9 })
            fs.open(fs.resolve(p("s")), OpenMode.READ_WRITE).use { it.write(3000, byteArrayOf(1, 2, 3), 0, 3) }
            val r = fs.read("s"); assertEquals(3003, r.size)
            assertTrue((100 until 3000).all { r[it] == 0.toByte() }); assertEquals(9, r[99].toInt()); assertEquals(3, r[3002].toInt())
        }
    }

    @Test fun `truncate shrink then grow never exposes old bytes`() {
        fresh().use { fs ->
            fs.write("t", ByteArray(4000) { 0x55 })
            fs.open(fs.resolve(p("t")), OpenMode.READ_WRITE).use { it.truncate(1000); it.truncate(3000) }
            val r = fs.read("t"); assertEquals(3000, r.size)
            assertTrue((0 until 1000).all { r[it] == 0x55.toByte() }); assertTrue((1000 until 3000).all { r[it] == 0.toByte() })
            fs.open(fs.resolve(p("t")), OpenMode.READ_WRITE).use { it.truncate(0) }
            assertEquals(0, fs.resolve(p("t")).size)
        }
    }

    @Test fun `directories nested list and delete`() {
        fresh().use { fs ->
            val a = fs.createDirectory(fs.root(), "a"); val b = fs.createDirectory(a, "b"); fs.write("a/b/x.txt", byteArrayOf(1))
            assertEquals(listOf("b"), fs.list(a).map { it.name }); assertEquals(listOf("x.txt"), fs.list(b).map { it.name })
            assertThrows(FsException::class.java) { fs.delete(b) } // not empty
            fs.delete(fs.resolve(p("a/b/x.txt"))); fs.delete(b); fs.delete(a)
            assertTrue(fs.list(fs.root()).isEmpty())
        }
    }

    @Test fun `rename including case-only and conflicts`() {
        fresh().use { fs ->
            fs.write("one.txt", byteArrayOf(1)); fs.write("two.txt", byteArrayOf(2))
            val r = fs.rename(fs.resolve(p("one.txt")), "Uno Largo.TXT")
            assertEquals("Uno Largo.TXT", r.name); assertArrayEquals(byteArrayOf(1), fs.read("uno largo.txt"))
            fs.rename(fs.resolve(p("two.txt")), "TWO.TXT"); assertEquals("TWO.TXT", fs.list(fs.root()).first { it.name.equals("two.txt", true) }.name)
            assertThrows(FsExistsException::class.java) { fs.rename(fs.resolve(p("TWO.TXT")), "uno largo.txt") }
        }
    }

    @Test fun `invalid names are rejected`() {
        fresh().use { fs ->
            for (bad in listOf("", "a/b", "a:b", "a*b", "a?b", "a<b", "a>b", "a|b", "a\"b", "a\\b", "x\u0001y", "trail.", "trail ", ".", "..", "a".repeat(256)))
                assertThrows(FsInvalidNameException::class.java, { fs.createFile(fs.root(), bad) }, "name '$bad'")
        }
    }

    @Test fun `duplicate names are case-insensitive`() {
        fresh().use { fs -> fs.createFile(fs.root(), "Dup.txt"); assertThrows(FsExistsException::class.java) { fs.createFile(fs.root(), "dup.TXT") }
            assertThrows(FsExistsException::class.java) { fs.createDirectory(fs.root(), "DUP.txt") } }
    }

    @Test fun `move file and directory, cycle refused`() {
        fresh().use { fs ->
            val a = fs.createDirectory(fs.root(), "a"); val b = fs.createDirectory(fs.root(), "b"); fs.write("a/f.txt", byteArrayOf(5)); fs.createDirectory(a, "sub")
            fs.move(fs.resolve(p("a/f.txt")), b); assertArrayEquals(byteArrayOf(5), fs.read("b/f.txt")); assertThrows(FsNotFoundException::class.java) { fs.resolve(p("a/f.txt")) }
            fs.move(fs.resolve(p("a")), b); assertTrue(fs.resolve(p("b/a/sub")).isDirectory)
            assertThrows(FsException::class.java) { fs.move(fs.resolve(p("b")), fs.resolve(p("b/a/sub"))) }
            assertTrue(fs.resolve(p("b/a/sub")).isDirectory)
            val back = remount(fs); assertTrue(back.resolve(p("b/a/sub")).isDirectory)
        }
    }

    @Test fun `unicode and long names round trip`() {
        fresh().use { fs ->
            val names = listOf("ünïcode ✓ — long file name.txt", "日本語のファイル.txt", "Mixed Case.Txt", "a.b.c.d.txt", "x".repeat(200) + ".dat")
            names.forEachIndexed { i, n -> fs.write(n, byteArrayOf(i.toByte())) }
            val fs2 = remount(fs)
            names.forEachIndexed { i, n -> assertEquals(i.toByte(), fs2.read(n)[0]); assertTrue(fs2.list(fs2.root()).any { it.name == n }, n) }
        }
    }

    @Test fun `many entries spanning directory clusters, delete half, reuse`() {
        fresh().use { fs ->
            val d = fs.createDirectory(fs.root(), "many")
            for (i in 0 until 200) fs.createFile(d, "file-number-$i.txt")
            for (i in 0 until 200 step 2) fs.delete(fs.resolve(p("many/file-number-$i.txt")))
            for (i in 0 until 100) fs.createFile(d, "again-$i.txt")
            val names = remount(fs).let { r -> r.list(r.resolve(p("many"))).map { it.name } }
            assertEquals(200, names.size); assertEquals(200, names.toSet().size)
        }
    }

    @Test fun `delete frees space and no space is a typed error without leaks`() {
        fresh().use { fs ->
            val free0 = fs.spaceInfo().freeBytes
            fs.write("one", ByteArray(100_000)); assertTrue(fs.spaceInfo().freeBytes < free0)
            fs.delete(fs.resolve(p("one"))); assertEquals(free0, fs.spaceInfo().freeBytes)
            val n = fs.createFile(fs.root(), "huge")
            assertThrows(FsNoSpaceException::class.java) {
                fs.open(n, OpenMode.READ_WRITE).use { f -> val chunk = ByteArray(65536); var pos = 0L; while (true) { f.write(pos, chunk, 0, chunk.size); pos += chunk.size } }
            }
            fs.delete(fs.resolve(p("huge"))); assertEquals(free0, fs.spaceInfo().freeBytes)
        }
    }
}
