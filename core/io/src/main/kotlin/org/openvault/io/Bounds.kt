package org.openvault.io

import java.io.EOFException

/** Validates a byte range request against a storage of [size] bytes and a buffer of [bufSize] bytes. */
fun checkRange(position: Long, off: Int, len: Int, bufSize: Int, size: Long) {
    require(off >= 0 && len >= 0 && off.toLong() + len <= bufSize) { "buffer range out of bounds" }
    require(position >= 0) { "negative position" }
    if (position + len > size) throw EOFException("range $position+$len exceeds size $size")
}
