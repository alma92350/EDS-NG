package org.openvault.veracrypt

import org.openvault.io.BlockDevice
import org.openvault.io.RandomAccessStorage

/** Thrown when a write would touch the protected hidden-volume area; the device is read-only afterwards (like desktop VeraCrypt). */
class HiddenVolumeProtectionException : java.io.IOException("write refused: it would overwrite the hidden volume; volume is now read-only")

/**
 * B1: decorator that refuses every write overlapping sectors [protectedFirst, protectedFirst+protectedCount).
 * After the first violation all further writes are refused.
 */
class ProtectedRangeBlockDevice(
    private val inner: BlockDevice, private val protectedFirst: Long, private val protectedCount: Long,
) : BlockDevice by inner {
    var violated = false
        private set
    override val isReadOnly: Boolean get() = inner.isReadOnly || violated

    override fun writeSectors(firstSector: Long, src: ByteArray, off: Int, count: Int) {
        if (violated) throw HiddenVolumeProtectionException()
        if (count > 0 && firstSector < protectedFirst + protectedCount && firstSector + count > protectedFirst) {
            violated = true; throw HiddenVolumeProtectionException()
        }
        inner.writeSectors(firstSector, src, off, count)
    }
}

/** Lets a second reader inspect the container without closing the real storage. */
class NonClosingStorage(private val s: RandomAccessStorage) : RandomAccessStorage by s {
    override fun close() {}
}
