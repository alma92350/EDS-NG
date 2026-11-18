package org.openvault.veracrypt

import org.openvault.crypto.VolumeMode
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
    private val MAGIC_VERA = "VERA".toByteArray(Charsets.US_ASCII)
    private val MAGIC_TRUE = "TRUE".toByteArray(Charsets.US_ASCII)

    private fun crc(b: ByteArray, off: Int, len: Int): ByteArray {
        val c = CRC32().apply { update(b, off, len) }.value
        return ByteBuffer.allocate(4).putInt(c.toInt()).array()
    }

    private fun ctEq(a: ByteArray, b: ByteArray) = MessageDigest.isEqual(a, b)

    /**
     * Validates a trial-decrypted header. Returns null for anything that is not a valid header (wrong password
     * and malformed input are deliberately indistinguishable). [storageSize] bounds the data area.
     */
    fun parse(plain: ByteArray, storageSize: Long, mode: VolumeMode = VolumeMode.VERACRYPT): VolumeHeader? {
        if (plain.size != ENCRYPTED_SIZE) return null
        val bb = ByteBuffer.wrap(plain) // big-endian
        val tc = mode == VolumeMode.TRUECRYPT
        if (!ctEq(plain.copyOfRange(0, 4), if (tc) MAGIC_TRUE else MAGIC_VERA)) return null
        if (!ctEq(crc(plain, 0, 188), plain.copyOfRange(188, 192))) return null
        if (!ctEq(crc(plain, 192, 256), plain.copyOfRange(8, 12))) return null
        val version = bb.getShort(4).toInt() and 0xffff
        // VeraCrypt: header version >= 5. TrueCrypt 6.x/7.x: versions 4 and 5 (older layouts are not supported).
        if (version < (if (tc) 4 else 5)) return null
        val hidden = bb.getLong(28)
        val volSize = bb.getLong(36)
        val dataOff = bb.getLong(44)
        val encSize = bb.getLong(52)
        // TrueCrypt headers before v5 have no sector size field: 0 means 512.
        val sector = bb.getInt(64).let { if (tc && it == 0) 512 else it }
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
