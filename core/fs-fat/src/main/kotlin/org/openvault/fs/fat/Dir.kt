package org.openvault.fs.fat

import java.time.Instant
import java.time.LocalDateTime
import java.time.ZoneId

/** A decoded directory entry (short entry + its long name, if any). */
class DirEntry(
    val name: String, val shortName: String, val isDirectory: Boolean, val size: Long, val firstCluster: Long,
    val modified: Instant?, val created: Instant?,
    /** Byte offset in the parent directory stream of the first (LFN) entry and of the short entry. */
    val startOffset: Int = 0, val shortOffset: Int = 0, val attr: Int = 0,
) {
    /** Directory stream this entry lives in: 0 = fixed FAT12/16 root, else first cluster. Set by the driver. */
    var parentFirst: Long = -1
}

object DirParser {
    private fun u16(b: ByteArray, o: Int) = (b[o].toInt() and 0xff) or ((b[o + 1].toInt() and 0xff) shl 8)
    private fun u32(b: ByteArray, o: Int) = u16(b, o).toLong() or (u16(b, o + 2).toLong() shl 16)

    fun lfnChecksum(name11: ByteArray): Int {
        var sum = 0
        for (i in 0 until 11) sum = (((sum and 1) shl 7) + (sum shr 1) + (name11[i].toInt() and 0xff)) and 0xff
        return sum
    }

    fun fatTime(date: Int, time: Int, zone: ZoneId): Instant? {
        if (date == 0) return null
        return try {
            LocalDateTime.of(1980 + (date shr 9), (date shr 5) and 0xf, date and 0x1f, (time shr 11) and 0x1f, (time shr 5) and 0x3f, (time and 0x1f) * 2)
                .atZone(zone).toInstant()
        } catch (e: java.time.DateTimeException) { null }
    }

    /** Parses a raw directory byte stream. Stops at the first 0x00 entry. Orphan/invalid LFN sets fall back to the short name. */
    fun parse(raw: ByteArray, zone: ZoneId = ZoneId.systemDefault()): List<DirEntry> {
        val out = ArrayList<DirEntry>()
        var lfn = StringBuilder(); var lfnSum = -1; var expectedSeq = 0; var lfnValid = false; var lfnStart = -1
        var o = 0
        while (o + 32 <= raw.size) {
            val first = raw[o].toInt() and 0xff
            if (first == 0x00) break
            val attr = raw[o + 11].toInt() and 0xff
            if (first == 0xE5) { lfnValid = false; o += 32; continue }
            if (attr == 0x0F) {
                val seq = first and 0x3f
                if (first and 0x40 != 0) { lfn = StringBuilder(); expectedSeq = seq; lfnSum = raw[o + 13].toInt() and 0xff; lfnValid = true; lfnStart = o }
                else if (!lfnValid || seq != expectedSeq - 1 || (raw[o + 13].toInt() and 0xff) != lfnSum) { lfnValid = false }
                if (lfnValid) {
                    expectedSeq = seq
                    val part = StringBuilder()
                    for (r in intArrayOf(1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30)) part.append(u16(raw, o + r).toChar())
                    lfn.insert(0, part)
                }
                o += 32; continue
            }
            if (attr and 0x08 != 0) { lfnValid = false; o += 32; continue } // volume label
            val nameBytes = raw.copyOfRange(o, o + 11)
            if (nameBytes[0] == 0x05.toByte()) nameBytes[0] = 0xE5.toByte()
            val ntFlags = raw[o + 12].toInt()
            val base = String(nameBytes, 0, 8, Charsets.ISO_8859_1).trimEnd().let { if (ntFlags and 0x08 != 0) it.lowercase() else it }
            val ext = String(nameBytes, 8, 3, Charsets.ISO_8859_1).trimEnd().let { if (ntFlags and 0x10 != 0) it.lowercase() else it }
            val short = if (ext.isEmpty()) base else "$base.$ext"
            var name = short; var usedLfn = false
            if (lfnValid && expectedSeq == 1 && lfnChecksum(raw.copyOfRange(o, o + 11)) == lfnSum) {
                val s = lfn.toString(); val end = s.indexOf('\u0000')
                name = (if (end >= 0) s.substring(0, end) else s).takeIf { it.isNotEmpty() } ?: short
                usedLfn = name != short
            }
            lfnValid = false
            o.let {
                if (short != "." && short != "..") {
                    val cluster = u16(raw, it + 26).toLong() or (u16(raw, it + 20).toLong() shl 16)
                    out += DirEntry(name, short, attr and 0x10 != 0, if (attr and 0x10 != 0) 0 else u32(raw, it + 28), cluster,
                        fatTime(u16(raw, it + 24), u16(raw, it + 22), zone), fatTime(u16(raw, it + 16), u16(raw, it + 14), zone),
                        if (name != short && lfnStart >= 0 && usedLfn) lfnStart else it, it, attr)
                }
            }
            o += 32
        }
        return out
    }
}
