package org.openvault.testkit

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.openvault.fs.*

/**
 * Read-side contract every [FileSystem] must satisfy. Subclasses supply a filesystem holding exactly [expected]
 * (path without leading slash -> content). Case-insensitive lookup is required (FAT/exFAT semantics).
 */
abstract class FileSystemReadContract {
    protected abstract fun open(): FileSystem
    protected abstract val expected: Map<String, ByteArray>

    private fun readAll(fs: FileSystem, path: String): ByteArray {
        val n = fs.resolve(FsPath.parse(path))
        fs.open(n, OpenMode.READ).use { f ->
            val out = ByteArray(f.size.toInt()); var p = 0
            while (p < out.size) { val r = f.read(p.toLong(), out, p, out.size - p); if (r < 0) break; p += r }
            assertEquals(out.size, p); return out
        }
    }

    @Test fun `every expected file reads back byte for byte`() {
        open().use { fs -> for ((p, d) in expected) assertArrayEquals(d, readAll(fs, p), p) }
    }

    @Test fun `node metadata matches`() {
        open().use { fs ->
            for ((p, d) in expected) {
                val n = fs.resolve(FsPath.parse(p))
                assertFalse(n.isDirectory); assertEquals(d.size.toLong(), n.size); assertEquals(FsPath.parse(p).name.lowercase(), n.name.lowercase())
            }
        }
    }

    @Test fun `root listing contains top-level names exactly`() {
        open().use { fs ->
            val want = expected.keys.map { it.substringBefore('/').lowercase() }.toSet()
            val got = fs.list(fs.root()).map { it.name.lowercase() }
            assertEquals(want, got.toSet()); assertEquals(got.size, got.toSet().size, "no duplicate entries")
        }
    }

    @Test fun `every directory lists its children`() {
        open().use { fs ->
            val dirs = expected.keys.flatMap { p -> FsPath.parse(p).let { fp -> (1 until fp.segments.size).map { fp.segments.take(it).joinToString("/") } } }.toSet()
            for (d in dirs) {
                val node = fs.resolve(FsPath.parse(d)); assertTrue(node.isDirectory, d)
                val want = expected.keys.filter { it.startsWith("$d/") }.map { it.removePrefix("$d/").substringBefore('/').lowercase() }.toSet()
                assertEquals(want, fs.list(node).map { it.name.lowercase() }.toSet(), d)
            }
        }
    }

    @Test fun `lookup is case insensitive`() {
        open().use { fs ->
            val p = expected.keys.first { '/' !in it }
            assertEquals(fs.resolve(FsPath.parse(p.uppercase())).size, fs.resolve(FsPath.parse(p.lowercase())).size)
        }
    }

    @Test fun `random access reads including across clusters`() {
        open().use { fs ->
            val (p, d) = expected.entries.maxByOrNull { it.value.size }!!
            fs.open(fs.resolve(FsPath.parse(p)), OpenMode.READ).use { f ->
                for ((pos, len) in listOf(0 to 1, 1 to 511, 511 to 3, 510 to 1030, d.size - 7 to 7, d.size / 2 to d.size / 3)) {
                    if (pos + len > d.size) continue
                    val b = ByteArray(len); var got = 0
                    while (got < len) { val r = f.read((pos + got).toLong(), b, got, len - got); assertTrue(r > 0); got += r }
                    assertArrayEquals(d.copyOfRange(pos, pos + len), b, "pos=$pos len=$len")
                }
            }
        }
    }

    @Test fun `eof semantics`() {
        open().use { fs ->
            val (p, d) = expected.entries.first { it.value.isNotEmpty() }
            fs.open(fs.resolve(FsPath.parse(p)), OpenMode.READ).use { f ->
                assertEquals(-1, f.read(d.size.toLong(), ByteArray(4), 0, 4))
                assertEquals(-1, f.read(d.size + 100L, ByteArray(4), 0, 4))
                val pos = maxOf(0, d.size - 3); val b = ByteArray(10)
                val r = f.read(pos.toLong(), b, 0, 10)
                assertTrue(r in 1..(d.size - pos), "partial read at tail returned $r")
            }
        }
    }

    @Test fun `missing path and wrong kinds`() {
        open().use { fs ->
            assertThrows(FsNotFoundException::class.java) { fs.resolve(FsPath.parse("/definitely/not/here")) }
            val file = fs.resolve(FsPath.parse(expected.keys.first { '/' !in it }))
            assertThrows(FsNotDirectoryException::class.java) { fs.list(file) }
            val dir = fs.root()
            assertThrows(FsIsDirectoryException::class.java) { fs.open(dir, OpenMode.READ) }
        }
    }

    @Test fun `empty file is readable`() {
        open().use { fs ->
            val e = expected.entries.firstOrNull { it.value.isEmpty() } ?: return
            fs.open(fs.resolve(FsPath.parse(e.key)), OpenMode.READ).use { assertEquals(0, it.size); assertEquals(-1, it.read(0, ByteArray(1), 0, 1)) }
        }
    }
}
