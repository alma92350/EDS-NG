package org.openvault.veracrypt

import org.openvault.crypto.XtsAes
import org.openvault.io.BlockDevice
import org.openvault.io.RandomAccessStorage

/**
 * The decrypted data area of a VeraCrypt volume as a block device (AES-256-XTS, 512-byte data units;
 * data unit number = absolute container byte offset / 512, PRD §6.5). NOT thread-safe.
 * Header areas are unreachable through this API: sector 0 is the first data-area sector.
 */
class VeraCryptVolume internal constructor(
    private val storage: RandomAccessStorage,
    val header: VolumeHeader,
    val location: HeaderLocation,
    readOnly: Boolean,
) : BlockDevice {
    private val xts = XtsAes(header.keyMaterial.copyOfRange(0, 32), header.keyMaterial.copyOfRange(32, 64))
    private var closed = false

    override val sectorSize: Int get() = header.sectorSize
    override val sectorCount: Long get() = header.volumeSize / header.sectorSize
    override val isReadOnly: Boolean = readOnly || storage.isReadOnly
    val usedBackupHeader: Boolean get() = location.isBackup
    val isHidden: Boolean get() = location.isHidden

    private fun check(first: Long, count: Int, bufSize: Int, off: Int) {
        check(!closed) { "volume closed" }
        require(count >= 0 && off >= 0 && off.toLong() + count.toLong() * sectorSize <= bufSize) { "buffer too small" }
        require(first >= 0 && first + count <= sectorCount) { "sector range outside volume" }
    }

    override fun readSectors(firstSector: Long, dst: ByteArray, off: Int, count: Int) {
        check(firstSector, count, dst.size, off)
        if (count == 0) return
        val pos = header.dataOffset + firstSector * sectorSize
        val len = count * sectorSize
        storage.read(pos, dst, off, len)
        xts.decrypt(dst, off, len, pos / XtsAes.UNIT)
    }

    override fun writeSectors(firstSector: Long, src: ByteArray, off: Int, count: Int) {
        check(firstSector, count, src.size, off)
        if (isReadOnly) throw java.io.IOException("volume is read-only")
        if (count == 0) return
        val pos = header.dataOffset + firstSector * sectorSize
        val len = count * sectorSize
        val tmp = src.copyOfRange(off, off + len)
        xts.encrypt(tmp, 0, len, pos / XtsAes.UNIT)
        storage.write(pos, tmp, 0, len)
        tmp.fill(0)
    }

    override fun flush() = storage.flush()

    override fun close() {
        if (closed) return
        closed = true
        xts.wipe(); header.wipe()
        storage.close()
    }
}
