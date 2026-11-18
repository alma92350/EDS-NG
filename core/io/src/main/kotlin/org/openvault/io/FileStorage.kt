package org.openvault.io

import java.io.File
import java.io.IOException
import java.io.RandomAccessFile

/** A container stored in a normal file (desktop / CLI). Read-only unless [writable]. Calls are synchronised (seek + read). */
class FileStorage(file: File, writable: Boolean = false) : RandomAccessStorage {
    private val raf = RandomAccessFile(file, if (writable) "rw" else "r")
    override val isReadOnly = !writable
    override val size: Long get() = synchronized(raf) { raf.length() }

    override fun read(position: Long, dst: ByteArray, off: Int, len: Int) {
        checkRange(position, off, len, dst.size, size)
        synchronized(raf) { raf.seek(position); raf.readFully(dst, off, len) }
    }

    override fun write(position: Long, src: ByteArray, off: Int, len: Int) {
        if (isReadOnly) throw IOException("read-only")
        checkRange(position, off, len, src.size, size)
        synchronized(raf) { raf.seek(position); raf.write(src, off, len) }
    }

    override fun flush() { if (!isReadOnly) synchronized(raf) { raf.fd.sync() } }
    override fun close() = raf.close()
}
