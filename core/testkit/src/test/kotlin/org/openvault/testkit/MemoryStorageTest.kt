package org.openvault.testkit

import org.openvault.io.RandomAccessStorage

class MemoryStorageTest : RandomAccessStorageContract() {
    override fun create(size: Int): RandomAccessStorage = MemoryStorage(size)
}
