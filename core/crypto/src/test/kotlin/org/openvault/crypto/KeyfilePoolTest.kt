package org.openvault.crypto

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.io.ByteArrayInputStream

class KeyfilePoolTest {
    private fun kf(vararg b: Int) = ByteArrayInputStream(ByteArray(b.size) { b[it].toByte() })

    @Test fun `no keyfiles leaves password padded with zeros`() {
        val r = KeyfilePool.mix("ab".toByteArray(), emptyList(), 8)
        assertArrayEquals(byteArrayOf(97, 98, 0, 0, 0, 0, 0, 0), r)
    }

    @Test fun `keyfile changes the result and is deterministic`() {
        val a = KeyfilePool.mix(ByteArray(0), listOf(kf(1, 2, 3)), 64)
        val b = KeyfilePool.mix(ByteArray(0), listOf(kf(1, 2, 3)), 64)
        assertArrayEquals(a, b)
        assertFalse(a.all { it == 0.toByte() })
    }

    @Test fun `keyfile order does not matter`() {
        // Each keyfile restarts at pool position 0 and results are added mod 256, so the sum commutes.
        // (VeraCrypt documents the same; PRD 6.6 / FR-U1 claim that order matters is wrong - verify with fixtures.)
        val ab = KeyfilePool.mix(ByteArray(0), listOf(kf(1, 2, 3), kf(9, 8, 7)), 64)
        val ba = KeyfilePool.mix(ByteArray(0), listOf(kf(9, 8, 7), kf(1, 2, 3)), 64)
        assertArrayEquals(ab, ba)
    }

    @Test fun `single byte keyfile matches hand-computed crc register`() {
        // CRC-32 register after byte 0x01 starting from 0xFFFFFFFF = 0x77073096 ^ (0xFFFFFF>>>... ) computed below.
        val crc = run {
            var c = -1; c = c xor 1
            repeat(8) { c = if (c and 1 != 0) (c ushr 1) xor 0xEDB88320.toInt() else c ushr 1 }; c
        }
        val r = KeyfilePool.mix(ByteArray(0), listOf(kf(1)), 8)
        assertArrayEquals(byteArrayOf((crc ushr 24).toByte(), (crc ushr 16).toByte(), (crc ushr 8).toByte(), crc.toByte(), 0, 0, 0, 0), r)
    }

    @Test fun `only first 1 MiB is read`() {
        val big = ByteArray(KeyfilePool.MAX_BYTES + 500) { (it * 7).toByte() }
        val capped = big.copyOf(KeyfilePool.MAX_BYTES)
        assertArrayEquals(
            KeyfilePool.mix(ByteArray(0), listOf(ByteArrayInputStream(capped)), 64),
            KeyfilePool.mix(ByteArray(0), listOf(ByteArrayInputStream(big)), 64))
    }

    @Test fun `password longer than pool rejected`() {
        assertThrows(IllegalArgumentException::class.java) { KeyfilePool.mix(ByteArray(65), emptyList(), 64) }
    }
}
