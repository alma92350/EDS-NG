package org.openvault.crypto

import java.io.Closeable

/** Owns a byte array of key material; [close] zeroes it. Use with `use {}` so wiping happens on every path. */
class SecretBytes(private val data: ByteArray) : Closeable {
    var isClosed = false
        private set

    val size: Int get() = data.size

    /** Direct access to the backing array (no copy, so nothing extra to wipe). Do not retain it. */
    val bytes: ByteArray get() { check(!isClosed) { "secret already wiped" }; return data }

    override fun close() {
        data.fill(0)
        isClosed = true
    }

    companion object {
        fun ofUtf8(password: CharArray): SecretBytes {
            val buf = java.nio.CharBuffer.wrap(password)
            val bb = Charsets.UTF_8.encode(buf)
            val out = ByteArray(bb.remaining())
            bb.get(out)
            if (bb.hasArray()) bb.array().fill(0)
            return SecretBytes(out)
        }
    }
}
