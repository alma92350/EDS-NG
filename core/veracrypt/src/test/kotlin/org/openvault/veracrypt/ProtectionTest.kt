package org.openvault.veracrypt

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.openvault.io.BlockDevice

class ProtectionTest {
    private class Mem(val w: MutableList<Long> = ArrayList()) : BlockDevice {
        override val sectorSize = 512; override val sectorCount = 100L; override val isReadOnly = false
        override fun readSectors(firstSector: Long, dst: ByteArray, off: Int, count: Int) {}
        override fun writeSectors(firstSector: Long, src: ByteArray, off: Int, count: Int) { w += firstSector }
        override fun flush() {}; override fun close() {}
    }

    @Test fun `writes outside the range pass, overlapping writes are refused and lock the device`() {
        val m = Mem(); val d = ProtectedRangeBlockDevice(m, 50, 10)
        d.writeSectors(0, ByteArray(512 * 50), 0, 50)        // sectors 0..49 end exactly at the range start
        d.writeSectors(60, ByteArray(512), 0, 1)              // first sector after the range
        assertEquals(listOf(0L, 60L), m.w); assertFalse(d.violated)
        assertThrows(HiddenVolumeProtectionException::class.java) { d.writeSectors(49, ByteArray(1024), 0, 2) } // overlaps sector 50
        assertTrue(d.violated); assertTrue(d.isReadOnly)
        assertThrows(HiddenVolumeProtectionException::class.java) { d.writeSectors(0, ByteArray(512), 0, 1) } // now everything refused
        assertEquals(listOf(0L, 60L), m.w)
    }

    @Test fun `last sector of the range is protected and reads always work`() {
        val d = ProtectedRangeBlockDevice(Mem(), 50, 10)
        assertThrows(HiddenVolumeProtectionException::class.java) { d.writeSectors(59, ByteArray(512), 0, 1) }
        d.readSectors(55, ByteArray(512), 0, 1)
    }
}
