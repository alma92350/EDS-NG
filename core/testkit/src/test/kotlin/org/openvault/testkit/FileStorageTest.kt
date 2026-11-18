package org.openvault.testkit

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.openvault.io.FileStorage
import org.openvault.io.RandomAccessStorage
import java.io.File
import java.io.IOException

class FileStorageTest : RandomAccessStorageContract() {
    override fun create(size: Int): RandomAccessStorage {
        val f = File.createTempFile("ovfs", ".bin"); f.deleteOnExit(); f.writeBytes(ByteArray(size))
        return FileStorage(f, writable = true)
    }

    @Test fun `read-only mode refuses writes and reports size`() {
        val f = File.createTempFile("ovfs", ".bin"); f.deleteOnExit(); f.writeBytes(ByteArray(100) { it.toByte() })
        FileStorage(f).use { s -> assertEquals(100, s.size); assertTrue(s.isReadOnly); assertThrows(IOException::class.java) { s.write(0, byteArrayOf(1)) }
            val b = ByteArray(3); s.read(10, b); assertArrayEquals(byteArrayOf(10, 11, 12), b) }
    }
}
