package org.openvault.crypto

import java.io.InputStream

/**
 * VeraCrypt keyfile mixing (PRD §6.6, ⚠ VERIFY against fixtures: pool size 64 vs 128; default 64).
 * Per keyfile: running CRC-32 register over the first 1 MiB; after every byte the 4 register bytes
 * (big-endian) are added (mod 256) into the pool at a wrapping write position.
 */
object KeyfilePool {
    const val MAX_BYTES = 1024 * 1024
    private val TABLE = IntArray(256).also { t ->
        for (n in 0 until 256) {
            var c = n
            repeat(8) { c = if (c and 1 != 0) (c ushr 1) xor 0xEDB88320.toInt() else c ushr 1 }
            t[n] = c
        }
    }

    fun mix(password: ByteArray, keyfiles: List<InputStream>, poolSize: Int = 64): ByteArray {
        require(poolSize > 0)
        require(password.size <= poolSize) { "password longer than pool" }
        val pool = ByteArray(poolSize)
        for (kf in keyfiles) {
            var crc = -1 // 0xFFFFFFFF
            var pos = 0
            var total = 0
            val buf = ByteArray(8192)
            while (total < MAX_BYTES) {
                val n = kf.read(buf, 0, minOf(buf.size, MAX_BYTES - total))
                if (n < 0) break
                for (i in 0 until n) {
                    crc = TABLE[(crc xor buf[i].toInt()) and 0xff] xor (crc ushr 8)
                    pool[pos] = (pool[pos] + (crc ushr 24)).toByte(); pos = (pos + 1) % poolSize
                    pool[pos] = (pool[pos] + (crc ushr 16)).toByte(); pos = (pos + 1) % poolSize
                    pool[pos] = (pool[pos] + (crc ushr 8)).toByte(); pos = (pos + 1) % poolSize
                    pool[pos] = (pool[pos] + crc).toByte(); pos = (pos + 1) % poolSize
                }
                total += n
            }
            buf.fill(0)
        }
        for (i in password.indices) pool[i] = (pool[i] + password[i]).toByte()
        return pool
    }
}
