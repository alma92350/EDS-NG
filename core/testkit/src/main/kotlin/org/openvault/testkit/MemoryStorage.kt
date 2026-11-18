package org.openvault.testkit

import org.openvault.io.RandomAccessStorage
import org.openvault.io.checkRange

class MemoryStorage(val bytes: ByteArray, override val isReadOnly: Boolean = false) : RandomAccessStorage {
    constructor(size: Int) : this(ByteArray(size))

    var closed = false
        private set
    override val size: Long get() = bytes.size.toLong()

    override fun read(position: Long, dst: ByteArray, off: Int, len: Int) {
        check(!closed) { "closed" }
        checkRange(position, off, len, dst.size, size)
        System.arraycopy(bytes, position.toInt(), dst, off, len)
    }

    override fun write(position: Long, src: ByteArray, off: Int, len: Int) {
        check(!closed) { "closed" }
        if (isReadOnly) throw java.io.IOException("read-only")
        checkRange(position, off, len, src.size, size)
        System.arraycopy(src, off, bytes, position.toInt(), len)
    }

    override fun flush() {}
    override fun close() { closed = true }
}
