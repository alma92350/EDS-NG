package org.openvault.fs.fat

import org.openvault.fs.FsCorruptException
import org.openvault.fs.UnsupportedFilesystemException

enum class FatType { FAT12, FAT16, FAT32 }

/** BIOS Parameter Block; the FAT type comes from the cluster count (Microsoft FAT spec), never from the label string. */
class Bpb private constructor(
    val bytesPerSector: Int, val sectorsPerCluster: Int, val reservedSectors: Int, val numFats: Int,
    val rootEntries: Int, val totalSectors: Long, val fatSectors: Long, val rootCluster: Long, val fsInfoSector: Int,
    val type: FatType, val label: String?,
) {
    val clusterBytes get() = bytesPerSector * sectorsPerCluster
    val fatStartSector get() = reservedSectors.toLong()
    val rootDirSectors get() = ((rootEntries * 32) + bytesPerSector - 1) / bytesPerSector
    val rootDirStartSector get() = fatStartSector + numFats * fatSectors
    val dataStartSector get() = rootDirStartSector + rootDirSectors
    val clusterCount get() = (totalSectors - dataStartSector) / sectorsPerCluster
    fun clusterFirstSector(c: Long) = dataStartSector + (c - 2) * sectorsPerCluster

    companion object {
        private fun u16(b: ByteArray, o: Int) = (b[o].toInt() and 0xff) or ((b[o + 1].toInt() and 0xff) shl 8)
        private fun u32(b: ByteArray, o: Int) = (u16(b, o).toLong()) or (u16(b, o + 2).toLong() shl 16)

        fun parse(s: ByteArray): Bpb {
            if (s.size < 512) throw FsCorruptException("boot sector too short")
            val oem = String(s, 3, 8, Charsets.ISO_8859_1)
            if (oem == "EXFAT   ") throw UnsupportedFilesystemException("exFAT")
            if (oem == "NTFS    ") throw UnsupportedFilesystemException("NTFS")
            if ((s[510].toInt() and 0xff) != 0x55 || (s[511].toInt() and 0xff) != 0xAA) throw UnsupportedFilesystemException("unformatted or unknown")
            val bps = u16(s, 11); val spc = s[13].toInt() and 0xff; val rsv = u16(s, 14); val nf = s[16].toInt() and 0xff
            val rootEnt = u16(s, 17)
            val ts = u16(s, 19).let { if (it != 0) it.toLong() else u32(s, 32) }
            val fs = u16(s, 22).let { if (it != 0) it.toLong() else u32(s, 36) }
            if (bps !in intArrayOf(512, 1024, 2048, 4096) || spc == 0 || (spc and (spc - 1)) != 0 || rsv == 0 || nf == 0 || fs == 0L || ts == 0L)
                throw UnsupportedFilesystemException("unformatted or unknown")
            val rootSectors = ((rootEnt * 32) + bps - 1) / bps
            val data = ts - (rsv + nf * fs + rootSectors)
            if (data <= 0) throw FsCorruptException("no data area")
            val clusters = data / spc
            val type = when { clusters < 4085 -> FatType.FAT12; clusters < 65525 -> FatType.FAT16; else -> FatType.FAT32 }
            val labelOff = if (type == FatType.FAT32) 71 else 43
            val label = String(s, labelOff, 11, Charsets.ISO_8859_1).trim().ifEmpty { null }.takeIf { it != "NO NAME" }
            return Bpb(bps, spc, rsv, nf, rootEnt, ts, fs, if (type == FatType.FAT32) u32(s, 44) else 0, if (type == FatType.FAT32) u16(s, 48) else 0, type, label)
        }
    }
}
