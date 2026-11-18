package org.openvault.crypto

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class SecretBytesTest {
    @Test fun `close zeroes backing array`() {
        val arr = byteArrayOf(1, 2, 3)
        SecretBytes(arr).close()
        assertArrayEquals(byteArrayOf(0, 0, 0), arr)
    }

    @Test fun `zeroed even when block throws`() {
        val arr = byteArrayOf(9, 9)
        assertThrows(IllegalStateException::class.java) { SecretBytes(arr).use { error("boom") } }
        assertArrayEquals(byteArrayOf(0, 0), arr)
    }

    @Test fun `access after close is rejected`() {
        val s = SecretBytes(byteArrayOf(1)); s.close()
        assertThrows(IllegalStateException::class.java) { s.bytes }
    }

    @Test fun `utf8 encoding of non-ascii password and source wipe`() {
        val pw = "pässwörd✓".toCharArray()
        SecretBytes.ofUtf8(pw).use { assertArrayEquals("pässwörd✓".toByteArray(Charsets.UTF_8), it.bytes) }
    }
}
