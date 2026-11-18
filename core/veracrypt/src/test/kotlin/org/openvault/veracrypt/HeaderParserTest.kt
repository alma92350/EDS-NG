package org.openvault.veracrypt

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.nio.ByteBuffer
import java.util.zip.CRC32

class HeaderParserTest {
    private val storage = 10L * 1024 * 1024

    /** Builds a valid decrypted header region (448 bytes) from the PRD §6.2 layout. */
    private fun build(
        magic: String = "VERA", version: Int = 5, hidden: Long = 0, vol: Long = storage - 262144, off: Long = 131072,
        sector: Int = 512, key: ByteArray = ByteArray(64) { (it + 1).toByte() },
    ): ByteArray {
        val b = ByteBuffer.allocate(448)
        b.put(0, magic.toByteArray()); b.putShort(4, version.toShort()); b.putShort(6, 0x010b)
        b.putLong(28, hidden); b.putLong(36, vol); b.putLong(44, off); b.putLong(52, vol); b.putInt(64, sector)
        System.arraycopy(key, 0, b.array(), 192, key.size)
        refresh(b.array())
        return b.array()
    }

    private fun refresh(a: ByteArray) {
        val bb = ByteBuffer.wrap(a)
        bb.putInt(8, CRC32().apply { update(a, 192, 256) }.value.toInt())
        bb.putInt(188, CRC32().apply { update(a, 0, 188) }.value.toInt())
    }

    @Test fun `valid header parses`() {
        val h = HeaderParser.parse(build(), storage)!!
        assertEquals(5, h.version); assertEquals(131072, h.dataOffset); assertEquals(storage - 262144, h.volumeSize)
        assertEquals(512, h.sectorSize); assertEquals(1, h.keyMaterial[0].toInt()); assertEquals(256, h.keyMaterial.size)
    }

    @Test fun `bad magic rejected`() = assertNull(HeaderParser.parse(build(magic = "TRUE"), storage))
    @Test fun `old version rejected`() = assertNull(HeaderParser.parse(build(version = 4), storage))
    @Test fun `newer version accepted`() = assertNotNull(HeaderParser.parse(build(version = 6), storage))
    @Test fun `bad sector size rejected`() = assertNull(HeaderParser.parse(build(sector = 500), storage))
    @Test fun `data area outside storage rejected`() = assertNull(HeaderParser.parse(build(vol = storage), storage))
    @Test fun `zero volume size rejected`() = assertNull(HeaderParser.parse(build(vol = 0), storage))
    @Test fun `unaligned offset rejected`() = assertNull(HeaderParser.parse(build(off = 131073), storage))
    @Test fun `wrong length rejected`() = assertNull(HeaderParser.parse(ByteArray(447), storage))

    @Test fun `corrupt header-field CRC rejected`() {
        val a = build(); a[100] = (a[100] + 1).toByte() // reserved area covered by CRC at 188
        assertNull(HeaderParser.parse(a, storage))
    }

    @Test fun `corrupt key-material CRC rejected`() {
        val a = build(); a[300] = (a[300] + 1).toByte()
        assertNull(HeaderParser.parse(a, storage))
    }

    @Test fun `random data is always rejected`() {
        val r = java.util.Random(42)
        repeat(10_000) {
            val a = ByteArray(448); r.nextBytes(a)
            assertNull(HeaderParser.parse(a, storage))
        }
    }
}

class HeaderSearchPlanTest {
    @Test fun `order is normal, hidden, backup normal, backup hidden`() {
        val plan = HeaderSearchPlan.build(org.openvault.crypto.Prf.entries)
        assertEquals(20, plan.size)
        assertEquals(HeaderLocation.NORMAL, plan.first().location)
        assertEquals(listOf(HeaderLocation.NORMAL, HeaderLocation.HIDDEN, HeaderLocation.BACKUP_NORMAL, HeaderLocation.BACKUP_HIDDEN),
            plan.map { it.location }.distinct())
        assertEquals(org.openvault.crypto.Prf.SHA512, plan.first().prf)
    }

    @Test fun `single prf restricts the plan`() {
        val plan = HeaderSearchPlan.build(listOf(org.openvault.crypto.Prf.SHA256))
        assertEquals(4, plan.size); assertTrue(plan.all { it.prf == org.openvault.crypto.Prf.SHA256 })
    }

    @Test fun `header offsets`() {
        val s = 5L * 1024 * 1024
        assertEquals(0, HeaderLocation.NORMAL.offset(s)); assertEquals(65536, HeaderLocation.HIDDEN.offset(s))
        assertEquals(s - 131072, HeaderLocation.BACKUP_NORMAL.offset(s)); assertEquals(s - 65536, HeaderLocation.BACKUP_HIDDEN.offset(s))
    }
}
