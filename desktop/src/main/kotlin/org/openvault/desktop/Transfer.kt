package org.openvault.desktop

import org.openvault.fs.*
import java.io.File
import java.io.InputStream
import java.io.OutputStream

/** Copy logic between the host filesystem and a vault. Runs on the vault thread. */
object Transfer {
    /** Copies [input] into [dir]/[name] ("keep both" on conflicts). A cancelled or failed copy leaves no partial file. Returns the created node or null if cancelled. */
    fun importStream(fs: FileSystem, dir: FsPath, name: String, input: InputStream, cancelled: () -> Boolean = { false }, progress: (Long) -> Unit = {}): FsNode? {
        val parent = fs.resolve(dir)
        val finalName = Names.keepBoth(name, fs.list(parent).map { it.name })
        val node = fs.createFile(parent, finalName)
        var ok = false
        try {
            fs.open(node, OpenMode.READ_WRITE).use { f ->
                val buf = ByteArray(256 * 1024); var pos = 0L
                while (!cancelled()) { val n = input.read(buf); if (n < 0) { ok = true; break }; f.write(pos, buf, 0, n); pos += n; progress(pos) }
            }
        } finally { if (!ok) runCatching { fs.delete(fs.resolve(dir.child(finalName))) } else fs.sync() }
        return if (ok) fs.resolve(dir.child(finalName)) else null
    }

    /** Imports a file or (recursively) a directory. Returns the number of files copied. */
    fun importPath(fs: FileSystem, dir: FsPath, source: File, cancelled: () -> Boolean = { false }, progress: (String) -> Unit = {}): Int {
        if (cancelled()) return 0
        if (source.isDirectory) {
            val parent = fs.resolve(dir)
            val name = Names.keepBoth(source.name, fs.list(parent).map { it.name })
            val made = fs.createDirectory(parent, name)
            var n = 0
            source.listFiles()?.sortedBy { it.name.lowercase() }?.forEach { n += importPath(fs, made.path, it, cancelled, progress) }
            return n
        }
        progress(source.name)
        return source.inputStream().use { if (importStream(fs, dir, source.name, it, cancelled) != null) 1 else 0 }
    }

    fun exportStream(fs: FileSystem, node: FsNode, out: OutputStream, cancelled: () -> Boolean = { false }, progress: (Long) -> Unit = {}): Boolean {
        fs.open(fs.resolve(node.path), OpenMode.READ).use { f ->
            val buf = ByteArray(256 * 1024); var pos = 0L
            while (!cancelled()) { val k = f.read(pos, buf, 0, buf.size); if (k < 0) return true; out.write(buf, 0, k); pos += k; progress(pos) }
        }
        return false
    }

    /** Exports a file or directory tree into [destDir]; existing host files are never overwritten (keep both). Returns files written. */
    fun exportTo(fs: FileSystem, node: FsNode, destDir: File, cancelled: () -> Boolean = { false }, progress: (String) -> Unit = {}): Int {
        if (cancelled()) return 0
        val target = File(destDir, Names.keepBoth(node.name, destDir.list()?.toList() ?: emptyList()))
        if (node.isDirectory) {
            check(target.mkdir() || target.isDirectory) { "cannot create ${target.name}" }
            var n = 0
            fs.list(fs.resolve(node.path)).forEach { n += exportTo(fs, it, target, cancelled, progress) }
            return n
        }
        progress(node.name)
        var done = false
        try { target.outputStream().use { done = exportStream(fs, node, it, cancelled) } } finally { if (!done) target.delete() }
        return if (done) 1 else 0
    }

    /** Reads a whole file for the built-in viewers (bounded). */
    fun readBytes(fs: FileSystem, path: FsPath, limit: Long): ByteArray = fs.open(fs.resolve(path), OpenMode.READ).use { f ->
        if (f.size > limit) throw java.io.IOException("File too large for the built-in viewer (${Names.size(f.size)}). Use Export instead.")
        ByteArray(f.size.toInt()).also { b -> var q = 0; while (q < b.size) { val n = f.read(q.toLong(), b, q, b.size - q); if (n < 0) break; q += n } }
    }
}
