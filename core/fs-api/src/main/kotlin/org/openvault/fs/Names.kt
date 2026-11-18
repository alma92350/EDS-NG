package org.openvault.fs

object Names {
    /** "keep both" conflict resolution: "a.txt" -> "a (1).txt", "a (2).txt"... case-insensitive against [existing]. */
    fun keepBoth(name: String, existing: Collection<String>): String {
        val taken = existing.map { it.lowercase() }.toSet()
        if (name.lowercase() !in taken) return name
        val dot = name.lastIndexOf('.').let { if (it <= 0) name.length else it }
        val base = name.substring(0, dot); val ext = name.substring(dot)
        var i = 1
        while (true) { val c = "$base ($i)$ext"; if (c.lowercase() !in taken) return c; i++ }
    }

    /** Human readable size, e.g. 1536 -> "1.5 KB". */
    fun size(bytes: Long): String {
        if (bytes < 1024) return "$bytes B"
        val units = arrayOf("KB", "MB", "GB", "TB"); var v = bytes.toDouble(); var i = -1
        while (v >= 1024 && i < units.size - 1) { v /= 1024; i++ }
        return String.format(java.util.Locale.ROOT, "%.1f %s", v, units[i])
    }
}
