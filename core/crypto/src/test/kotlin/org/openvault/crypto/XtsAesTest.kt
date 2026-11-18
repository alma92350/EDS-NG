package org.openvault.crypto

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.openvault.testkit.hex
import org.openvault.testkit.toHex
import java.security.MessageDigest
import kotlin.random.Random

class XtsAesTest {
    private val k1 = "2718281828459045235360287471352662497757247093699959574966967627".hex()
    private val k2 = "3141592653589793238462643383279502884197169399375105820974944592".hex()
    private val plain = ByteArray(512) { it.toByte() }
    private fun sha(b: ByteArray) = MessageDigest.getInstance("SHA-256").digest(b).toHex()

    @Test fun `IEEE 1619 vector 15 XTS-AES-256 unit 0xff`() {
        val b = plain.copyOf()
        XtsAes(k1, k2).encrypt(b, 0, 512, 0xff)
        assertEquals("1c3b3a102f770386e4836c99e370cf9b", b.copyOfRange(0, 16).toHex())
        assertEquals("e97e974fa393af794f7a4684395814cf820de60a01eaec677d87b452e316b364", sha(b))
    }

    @Test fun `unit number 256 matches independent implementation`() {
        val b = plain.copyOf()
        XtsAes(k1, k2).encrypt(b, 0, 512, 256)
        assertEquals("d2681225948d7b026a19c3d8ec02e68673081979b776bcfe55a7f79a2a502f6c", b.copyOfRange(0, 32).toHex())
        assertEquals("2cc699eae61144e70c2a11618a4cd64b015430e76fdda36a4d941210a733e1e2", sha(b))
    }

    @Test fun `decrypt inverts encrypt`() {
        val x = XtsAes(k1, k2)
        val orig = Random(1).nextBytes(4096)
        val b = orig.copyOf()
        x.encrypt(b, 0, b.size, 7); assertFalse(orig.contentEquals(b))
        x.decrypt(b, 0, b.size, 7)
        assertArrayEquals(orig, b)
    }

    @Test fun `batch equals per-unit processing`() {
        val x = XtsAes(k1, k2)
        val orig = Random(2).nextBytes(512 * 9)
        val batch = orig.copyOf(); x.encrypt(batch, 0, batch.size, 1000)
        val single = orig.copyOf()
        for (u in 0 until 9) x.encrypt(single, u * 512, 512, 1000L + u)
        assertArrayEquals(batch, single)
    }

    @Test fun `different unit numbers give different ciphertext`() {
        val x = XtsAes(k1, k2)
        val a = plain.copyOf(); val b = plain.copyOf()
        x.encrypt(a, 0, 512, 1); x.encrypt(b, 0, 512, 2)
        assertFalse(a.contentEquals(b))
    }

    @Test fun `offset into buffer is honoured`() {
        val x = XtsAes(k1, k2)
        val ref = plain.copyOf(); x.encrypt(ref, 0, 512, 5)
        val big = ByteArray(1024); plain.copyInto(big, 100)
        x.encrypt(big, 100, 512, 5)
        assertArrayEquals(ref, big.copyOfRange(100, 612))
    }

    @Test fun `rejects bad lengths and keys`() {
        assertThrows(IllegalArgumentException::class.java) { XtsAes(ByteArray(16), ByteArray(16)) }
        assertThrows(IllegalArgumentException::class.java) { XtsAes(k1, k2).encrypt(ByteArray(20), 0, 20, 0) }
    }
}
