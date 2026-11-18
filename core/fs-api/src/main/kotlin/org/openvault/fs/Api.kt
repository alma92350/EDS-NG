package org.openvault.fs

import java.io.Closeable
import java.time.Instant

/** Absolute, normalised path inside a filesystem. Segments never contain '/' and are never "." or "..". */
class FsPath private constructor(val segments: List<String>) {
    val isRoot get() = segments.isEmpty()
    val name: String get() = segments.lastOrNull() ?: ""
    val parent: FsPath get() = if (isRoot) this else FsPath(segments.dropLast(1))
    fun child(name: String): FsPath {
        require(name.isNotEmpty() && '/' !in name && name != "." && name != "..") { "invalid segment '$name'" }
        return FsPath(segments + name)
    }
    override fun toString() = "/" + segments.joinToString("/")
    override fun equals(other: Any?) = other is FsPath && other.segments == segments
    override fun hashCode() = segments.hashCode()

    companion object {
        val ROOT = FsPath(emptyList())
        /** Parses "/a/b", "a//b/./c", "a/../b"; ".." above root is an error. */
        fun parse(p: String): FsPath {
            val out = ArrayList<String>()
            for (s in p.split('/')) when (s) {
                "", "." -> {}
                ".." -> { if (out.isEmpty()) throw IllegalArgumentException("path escapes root: $p"); out.removeAt(out.size - 1) }
                else -> out += s
            }
            return FsPath(out)
        }
    }
}

data class FsNode(
    val path: FsPath, val name: String, val isDirectory: Boolean, val size: Long,
    val modified: Instant?, val created: Instant?,
)

enum class OpenMode { READ, READ_WRITE }

data class SpaceInfo(val totalBytes: Long, val freeBytes: Long)

interface FsFile : Closeable {
    val size: Long
    /** Reads up to [len] bytes at [position]; returns bytes read, or -1 at/after EOF. */
    fun read(position: Long, dst: ByteArray, off: Int, len: Int): Int
    fun write(position: Long, src: ByteArray, off: Int, len: Int)
    fun truncate(newSize: Long)
    fun flush()
}

interface FileSystem : Closeable {
    val label: String?
    val isReadOnly: Boolean
    fun root(): FsNode
    fun resolve(path: FsPath): FsNode
    fun list(dir: FsNode): List<FsNode>
    fun createFile(dir: FsNode, name: String): FsNode
    fun createDirectory(dir: FsNode, name: String): FsNode
    fun rename(node: FsNode, newName: String): FsNode
    fun move(node: FsNode, newParent: FsNode): FsNode
    fun delete(node: FsNode)
    fun open(node: FsNode, mode: OpenMode): FsFile
    fun spaceInfo(): SpaceInfo
    fun sync()
}

open class FsException(message: String, cause: Throwable? = null) : java.io.IOException(message, cause)
class FsNotFoundException(path: Any) : FsException("not found: $path")
class FsNotDirectoryException(path: Any) : FsException("not a directory: $path")
class FsIsDirectoryException(path: Any) : FsException("is a directory: $path")
class FsExistsException(path: Any) : FsException("already exists: $path")
class FsReadOnlyException : FsException("filesystem is read-only")
class FsNoSpaceException : FsException("no space left on volume")
class FsInvalidNameException(name: String) : FsException("invalid name: $name")
class FsCorruptException(msg: String) : FsException("filesystem corrupt: $msg")
class UnsupportedFilesystemException(val kind: String) : FsException("unsupported filesystem: $kind")
