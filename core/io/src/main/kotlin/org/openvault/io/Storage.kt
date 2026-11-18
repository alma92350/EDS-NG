package org.openvault.io

import java.io.Closeable
import java.io.EOFException

/** Random-access byte storage (the encrypted container file). Reads/writes are all-or-nothing. */
interface RandomAccessStorage : Closeable {
    val size: Long
    val isReadOnly: Boolean

    /** Reads exactly [len] bytes; throws [EOFException] if the range is not fully inside the storage. */
    fun read(position: Long, dst: ByteArray, off: Int = 0, len: Int = dst.size - off)

    /** Writes exactly [len] bytes inside the storage (no growth); throws on read-only storage. */
    fun write(position: Long, src: ByteArray, off: Int = 0, len: Int = src.size - off)

    fun flush()
}

/** A decrypted block device (e.g. the data area of a VeraCrypt volume). */
interface BlockDevice : Closeable {
    val sectorSize: Int
    val sectorCount: Long
    val isReadOnly: Boolean
    fun readSectors(firstSector: Long, dst: ByteArray, off: Int, count: Int)
    fun writeSectors(firstSector: Long, src: ByteArray, off: Int, count: Int)
    fun flush()
}
