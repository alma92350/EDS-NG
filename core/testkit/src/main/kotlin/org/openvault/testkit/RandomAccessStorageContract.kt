package org.openvault.testkit

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.openvault.io.RandomAccessStorage
import java.io.EOFException

/** Every [RandomAccessStorage] implementation must pass this suite (subclass and supply [create]). */
abstract class RandomAccessStorageContract {
    /** A writable storage of exactly [size] zero bytes. */
    protected abstract fun create(size: Int): RandomAccessStorage

    @Test fun `write then read round trips`() {
        create(1024).use { s ->
            val data = ByteArray(100) { it.toByte() }
            s.write(10, data)
            val out = ByteArray(100)
            s.read(10, out)
            assertArrayEquals(data, out)
        }
    }

    @Test fun `read past end throws EOF`() {
        create(64).use { s -> assertThrows(EOFException::class.java) { s.read(60, ByteArray(8)) } }
    }

    @Test fun `exact end read is allowed`() {
        create(64).use { s -> s.read(56, ByteArray(8)) }
    }

    @Test fun `negative position rejected`() {
        create(64).use { s -> assertThrows(IllegalArgumentException::class.java) { s.read(-1, ByteArray(1)) } }
    }

    @Test fun `bad buffer range rejected`() {
        create(64).use { s -> assertThrows(IllegalArgumentException::class.java) { s.read(0, ByteArray(4), 2, 4) } }
    }

    @Test fun `offset buffer is honoured`() {
        create(64).use { s ->
            s.write(0, byteArrayOf(1, 2, 3, 4), 1, 2)
            val out = ByteArray(2)
            s.read(0, out)
            assertArrayEquals(byteArrayOf(2, 3), out)
        }
    }
}
