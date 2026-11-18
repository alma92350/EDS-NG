package org.openvault.crypto

import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec

/**
 * AES-XTS (IEEE 1619) over 512-byte data units. Not thread-safe: use one instance per thread.
 * [dataUnitNumber] is the number of the FIRST unit in the buffer; following units increment it.
 */
class XtsAes(key1: ByteArray, key2: ByteArray) {
    private val data = Cipher.getInstance("AES/ECB/NoPadding")
    private val tweakCipher = Cipher.getInstance("AES/ECB/NoPadding")
    private var key1Copy = key1.copyOf()
    private var key2Copy = key2.copyOf()
    private var mode = -1
    private val keySpec1 = SecretKeySpec(key1Copy, "AES")
    private val keySpec2 = SecretKeySpec(key2Copy, "AES")
    private var tweaks = ByteArray(0)

    init {
        require(key1.size == 32 && key2.size == 32) { "AES-256 keys required" }
        tweakCipher.init(Cipher.ENCRYPT_MODE, keySpec2)
    }

    fun encrypt(buf: ByteArray, off: Int, len: Int, dataUnitNumber: Long, unitSize: Int = UNIT) =
        process(Cipher.ENCRYPT_MODE, buf, off, len, dataUnitNumber, unitSize)

    fun decrypt(buf: ByteArray, off: Int, len: Int, dataUnitNumber: Long, unitSize: Int = UNIT) =
        process(Cipher.DECRYPT_MODE, buf, off, len, dataUnitNumber, unitSize)

    private fun process(m: Int, buf: ByteArray, off: Int, len: Int, firstUnit: Long, unitSize: Int) {
        require(unitSize % 16 == 0 && unitSize > 0) { "unit size must be a multiple of 16" }
        require(len % 16 == 0 && off >= 0 && off + len <= buf.size) { "length must be a multiple of 16 within buffer" }
        if (len == 0) return
        if (tweaks.size < len) tweaks = ByteArray(len)
        // 1. all tweaks (one per 16-byte block)
        val unitCount = (len + unitSize - 1) / unitSize
        val iv = ByteArray(16)
        val t = ByteArray(16)
        for (u in 0 until unitCount) {
            var n = firstUnit + u
            for (i in 0 until 8) { iv[i] = n.toByte(); n = n ushr 8 }
            tweakCipher.update(iv, 0, 16, t, 0)
            var lo = le64(t, 0); var hi = le64(t, 8)
            val start = u * unitSize
            val end = minOf(len, start + unitSize)
            var p = start
            while (p < end) {
                putLe64(tweaks, p, lo); putLe64(tweaks, p + 8, hi)
                val carry = hi ushr 63
                hi = (hi shl 1) or (lo ushr 63)
                lo = (lo shl 1) xor (carry * 0x87L)
                p += 16
            }
        }
        // 2. one ECB call over the whole batch
        xor(buf, off, tweaks, len)
        if (m != mode) { data.init(m, keySpec1); mode = m }
        data.doFinal(buf, off, len, buf, off)
        xor(buf, off, tweaks, len)
    }

    /** Best-effort wipe of the copies we hold (JCA internal key schedules cannot be wiped). */
    fun wipe() {
        key1Copy.fill(0); key2Copy.fill(0); tweaks.fill(0)
    }

    private fun xor(b: ByteArray, off: Int, t: ByteArray, len: Int) {
        var i = 0
        while (i < len) { putLe64(b, off + i, le64(b, off + i) xor le64(t, i)); i += 8 }
    }

    private fun le64(b: ByteArray, o: Int): Long {
        var v = 0L
        for (i in 7 downTo 0) v = (v shl 8) or (b[o + i].toLong() and 0xff)
        return v
    }

    private fun putLe64(b: ByteArray, o: Int, v: Long) {
        var x = v
        for (i in 0 until 8) { b[o + i] = x.toByte(); x = x ushr 8 }
    }

    companion object { const val UNIT = 512 }
}
