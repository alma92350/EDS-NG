package org.openvault.fs.fat

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.time.ZoneOffset

class DirParserTest {
    private fun short(name: String, ext: String, attr: Int = 0x20, cluster: Int = 5, size: Int = 100, nt: Int = 0, date: Int = (30 shl 9) or (6 shl 5) or 15, time: Int = (13 shl 11) or (45 shl 5) or 10): ByteArray {
        val e = ByteArray(32)
        (name.padEnd(8) + ext.padEnd(3)).toByteArray(Charsets.ISO_8859_1).copyInto(e)
        e[11] = attr.toByte(); e[12] = nt.toByte()
        e[22] = time.toByte(); e[23] = (time shr 8).toByte(); e[24] = date.toByte(); e[25] = (date shr 8).toByte()
        e[26] = cluster.toByte(); e[27] = (cluster shr 8).toByte()
        e[28] = size.toByte(); e[29] = (size shr 8).toByte()
        return e
    }

    private fun lfn(name: String, shortEntry: ByteArray): List<ByteArray> {
        val sum = DirParser.lfnChecksum(shortEntry.copyOf(11))
        val chars = name.map { it.code } + (if (name.length % 13 != 0) listOf(0) else emptyList())
        val padded = chars + List((13 - chars.size % 13) % 13) { 0xFFFF }
        val parts = padded.chunked(13)
        return parts.indices.reversed().map { i ->
            ByteArray(32).also { e ->
                e[0] = ((i + 1) or (if (i == parts.size - 1) 0x40 else 0)).toByte(); e[11] = 0x0F; e[13] = sum.toByte()
                val offs = intArrayOf(1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30)
                parts[i].forEachIndexed { k, c -> e[offs[k]] = c.toByte(); e[offs[k] + 1] = (c shr 8).toByte() }
            }
        }
    }

    private fun dir(vararg e: ByteArray) = (e.toList().fold(ByteArray(0)) { a, b -> a + b } + ByteArray(32)) // 0x00 terminator

    @Test fun `short name with nt lowercase flags and timestamps`() {
        val l = DirParser.parse(dir(short("README", "TXT", nt = 0x18)), ZoneOffset.UTC)
        assertEquals(1, l.size); assertEquals("readme.txt", l[0].name); assertEquals(100, l[0].size)
        assertEquals("2010-06-15T13:45:20Z", l[0].modified.toString()) // 1980+30, seconds field 10*2
    }

    @Test fun `unicode long file name across multiple entries`() {
        val s = short("UNICOD~1", "TXT"); val name = "ünïcode ✓ — very long name.txt"
        val l = DirParser.parse(dir(*lfn(name, s).toTypedArray(), s), ZoneOffset.UTC)
        assertEquals(name, l.single().name); assertEquals("UNICOD~1.TXT", l.single().shortName)
    }

    @Test fun `exact multiple of 13 chars has no terminator`() {
        val s = short("EXACT13", "TXT"); val name = "0123456789abc"
        assertEquals(name, DirParser.parse(dir(*lfn(name, s).toTypedArray(), s), ZoneOffset.UTC).single().name)
    }

    @Test fun `checksum mismatch falls back to short name`() {
        val s = short("REAL", "TXT"); val other = short("OTHER", "TXT")
        val l = DirParser.parse(dir(*lfn("Wrong Owner.txt", other).toTypedArray(), s), ZoneOffset.UTC)
        assertEquals("REAL.TXT", l.single().name)
    }

    @Test fun `orphaned lfn before deleted entry is ignored`() {
        val s = short("KEEP", "TXT"); val del = short("GONE", "TXT").also { it[0] = 0xE5.toByte() }
        val l = DirParser.parse(dir(*lfn("Stale Long Name.txt", del).toTypedArray(), del, s), ZoneOffset.UTC)
        assertEquals(listOf("KEEP.TXT"), l.map { it.name })
    }

    @Test fun `dot entries volume labels and deleted entries skipped, parsing stops at 0x00`() {
        val l = DirParser.parse(dir(short(".", ""), short("..", ""), short("VOL", "", attr = 0x08), short("A", "TXT").also { it[0] = 0xE5.toByte() }, short("B", "TXT", attr = 0x10)) + short("AFTER", "TXT"), ZoneOffset.UTC)
        assertEquals(listOf("B.TXT"), l.map { it.name }); assertTrue(l[0].isDirectory); assertEquals(0, l[0].size)
    }

    @Test fun `0x05 first byte means 0xE5`() {
        val e = short("XNAME", "TXT"); e[0] = 0x05
        assertEquals(0xE5, DirParser.parse(dir(e), ZoneOffset.UTC).single().name[0].code and 0xff)
    }

    @Test fun `zero date gives null timestamp`() {
        assertNull(DirParser.parse(dir(short("A", "TXT", date = 0)), ZoneOffset.UTC).single().modified)
    }
}
