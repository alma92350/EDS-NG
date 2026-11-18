package org.openvault.fs.fat

import org.openvault.fs.FsInvalidNameException

/** Name rules and 8.3 short-name generation (PRD §7.1). */
object ShortName {
    private const val INVALID = "\"*/:<>?\\|"
    private const val SHORT_OK = "!#$%&'()-@^_`{}~"

    fun validate(name: String) {
        if (name.isEmpty() || name.length > 255 || name == "." || name == ".." || name.endsWith(".") || name.endsWith(" ") || name.startsWith(" ")
            || name.any { it.code < 0x20 || it in INVALID || it.code == 0x7f }) throw FsInvalidNameException(name)
    }

    private fun okChar(c: Char) = c in 'A'..'Z' || c in '0'..'9' || c in SHORT_OK

    /** Result: the 11-byte on-disk name, NT case flags, and whether LFN entries are required. */
    class Packed(val name11: ByteArray, val ntFlags: Int, val needsLfn: Boolean)

    /** If [name] fits 8.3 exactly (modulo uniform case per part), returns it without LFN. */
    private fun exact(name: String): Packed? {
        val dot = name.lastIndexOf('.')
        val base = if (dot < 0) name else name.substring(0, dot); val ext = if (dot < 0) "" else name.substring(dot + 1)
        if (base.isEmpty() || base.length > 8 || ext.length > 3 || base.contains('.') ) return null
        fun uniform(s: String) = s == s.uppercase() || s == s.lowercase()
        if (!uniform(base) || !uniform(ext)) return null
        if (!(base + ext).uppercase().all { okChar(it) }) return null
        val flags = (if (base.isNotEmpty() && base == base.lowercase() && base != base.uppercase()) 0x08 else 0) or (if (ext.isNotEmpty() && ext == ext.lowercase() && ext != ext.uppercase()) 0x10 else 0)
        return Packed((base.uppercase().padEnd(8) + ext.uppercase().padEnd(3)).toByteArray(Charsets.ISO_8859_1), flags, false)
    }

    /** [taken] holds the 11-byte short names (as 11-char strings) already used in the directory. */
    fun pack(name: String, taken: Set<String>): Packed {
        exact(name)?.let { if (String(it.name11, Charsets.ISO_8859_1) !in taken) return it }
        val up = name.uppercase().trimStart('.')
        val dot = up.lastIndexOf('.')
        val rawBase = if (dot < 0) up else up.substring(0, dot); val rawExt = if (dot < 0) "" else up.substring(dot + 1)
        fun clean(s: String) = s.filter { it != ' ' && it != '.' }.map { if (okChar(it)) it else '_' }.joinToString("")
        val base = clean(rawBase).ifEmpty { "_" }; val ext = clean(rawExt).take(3)
        for (n in 1..999999) {
            val tail = "~$n"
            val b = base.take(8 - tail.length) + tail
            val key = b.padEnd(8) + ext.padEnd(3)
            if (key !in taken) return Packed(key.toByteArray(Charsets.ISO_8859_1), 0, true)
        }
        throw FsInvalidNameException(name)
    }

    fun lfnEntries(name: String, name11: ByteArray): List<ByteArray> {
        val sum = DirParser.lfnChecksum(name11)
        val chars = name.map { it.code } + (if (name.length % 13 != 0) listOf(0) else emptyList())
        val parts = (chars + List((13 - chars.size % 13) % 13) { 0xFFFF }).chunked(13)
        val offs = intArrayOf(1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30)
        return parts.indices.reversed().map { i ->
            ByteArray(32).also { e ->
                e[0] = ((i + 1) or (if (i == parts.size - 1) 0x40 else 0)).toByte(); e[11] = 0x0F; e[13] = sum.toByte()
                parts[i].forEachIndexed { k, c -> e[offs[k]] = c.toByte(); e[offs[k] + 1] = (c shr 8).toByte() }
            }
        }
    }
}
