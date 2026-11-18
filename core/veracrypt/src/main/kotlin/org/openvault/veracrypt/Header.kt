package org.openvault.veracrypt

import java.nio.ByteBuffer
import java.security.MessageDigest
import java.util.zip.CRC32

/** Decrypted VeraCrypt header fields (PRD §6.2). Offsets below are relative to the decrypted region (= header byte 64). */
class VolumeHeader(
    val version: Int,
    val minProgramVersion: Int,
    val hiddenVolumeSize: Long,
    val volumeSize: Long,
    val dataOffset: Long,
    val encryptedAreaSize: Long,
    val flags: Int,
    val sectorSize: Int,
    /** 256 bytes of key material; the first 64 are the AES-256 XTS key pair. Wipe when done. */
    val keyMaterial: ByteArray,
) {
    fun wipe() = keyMaterial.fill(0)
}

object HeaderParser {
    const val ENCRYPTED_SIZE = 448
    private val MAGIC = "VERA".toByteArray(Charsets.US_ASCII)

    private fun crc(b: ByteArray, off: Int, len: Int): ByteArray {
        val c = CRC32().apply { update(b, off, len) }.value
        return ByteBuffer.allocate(4).putInt(c.toInt()).array()
    }

    private fun ctEq(a: ByteArray, b: ByteArray) = MessageDigest.isEqual(a, b)

    /**
     * Validates a trial-decrypted header. Returns null for anything that is not a valid header (wrong password
     * and malformed input are deliberately indistinguishable). [storageSize] bounds the data area.
     */
    fun parse(plain: ByteArray, storageSize: Long): VolumeHeader? {
        if (plain.size != ENCRYPTED_SIZE) return null
        val bb = ByteBuffer.wrap(plain) // big-endian
        if (!ctEq(plain.copyOfRange(0, 4), MAGIC)) return null
        if (!ctEq(crc(plain, 0, 188), plain.copyOfRange(188, 192))) return null
        if (!ctEq(crc(plain, 192, 256), plain.copyOfRange(8, 12))) return null
        val version = bb.getShort(4).toInt() and 0xffff
        if (version < 5) return null
        val hidden = bb.getLong(28)
        val volSize = bb.getLong(36)
        val dataOff = bb.getLong(44)
        val encSize = bb.getLong(52)
        val sector = bb.getInt(64)
        if (sector !in intArrayOf(512, 1024, 2048, 4096)) return null
        if (volSize <= 0 || dataOff < 0 || volSize < 0 || hidden < 0) return null
        if (dataOff % 512 != 0L || volSize % sector != 0L) return null
        if (dataOff > storageSize || volSize > storageSize - dataOff) return null
        return VolumeHeader(
            version, bb.getShort(6).toInt() and 0xffff, hidden, volSize, dataOff, encSize,
            bb.getInt(60), sector, plain.copyOfRange(192, 448),
        )
    }
}
