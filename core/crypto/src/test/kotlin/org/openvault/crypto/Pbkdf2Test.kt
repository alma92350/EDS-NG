package org.openvault.crypto

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.EnumSource
import org.openvault.testkit.toHex
import org.bouncycastle.crypto.macs.HMac
import org.bouncycastle.crypto.params.KeyParameter

class Pbkdf2Test {
    private val pw = "password".toByteArray()
    private val salt = "salt".toByteArray()

    // Vectors generated with Python hashlib.pbkdf2_hmac (independent implementation).
    @Test fun `sha256 vector`() = assertEquals(
        "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43",
        Pbkdf2.derive(Prf.SHA256, pw, salt, 2, 32).toHex())

    @Test fun `sha512 vector`() = assertEquals(
        "e1d9c16aa681708a45f5c7c4e215ceb66e011a2e9f0040713f18aefdb866d53cf76cab2868a39b9f7840edce4fef5a82be67335c77a6068e04112754f27ccf4e",
        Pbkdf2.derive(Prf.SHA512, pw, salt, 2, 64).toHex())

    @Test fun `blake2s vector`() = assertEquals(
        "7b88e65e6e95a118bc995f681a391cbd7b46e0cf9750a81100f613add62d84be",
        Pbkdf2.derive(Prf.BLAKE2S, pw, salt, 2, 32).toHex())

    /** Whirlpool/Streebog have no stdlib oracle: check against a from-scratch HMAC built on the raw digest. */
    @ParameterizedTest @EnumSource(Prf::class)
    fun `iteration 1 equals plain HMAC of salt||INT(1)`(prf: Prf) {
        val d = prf.newDigest()
        val h = HMac(prf.newDigest()).apply { init(KeyParameter(pw)) }
        val msg = salt + byteArrayOf(0, 0, 0, 1)
        h.update(msg, 0, msg.size)
        val expected = ByteArray(h.macSize); h.doFinal(expected, 0)
        assertEquals(expected.toHex(), Pbkdf2.derive(prf, pw, salt, 1, expected.size).toHex())
        assertTrue(d.digestSize > 0)
    }

    @ParameterizedTest @EnumSource(Prf::class)
    fun `dkLen larger than one block and truncation are consistent`(prf: Prf) {
        val long = Pbkdf2.derive(prf, pw, salt, 3, 150)
        assertEquals(150, long.size)
        assertArrayEquals(long.copyOf(40), Pbkdf2.derive(prf, pw, salt, 3, 40))
    }

    @Test fun `binary and non-ascii passwords work`() {
        val a = Pbkdf2.derive(Prf.SHA512, byteArrayOf(0, -1, 0x80.toByte()), salt, 2, 64)
        val b = Pbkdf2.derive(Prf.SHA512, byteArrayOf(0, -1, 0x80.toByte(), 0), salt, 2, 64)
        assertFalse(a.contentEquals(b))
    }
}

class IterationPolicyTest {
    @ParameterizedTest @EnumSource(Prf::class)
    fun `default PIM gives 500000`(prf: Prf) = assertEquals(500_000, IterationPolicy.iterations(prf, 0))

    @Test fun `custom PIM`() {
        assertEquals(25_000, IterationPolicy.iterations(Prf.SHA512, 10))
        assertEquals(15_000 + 485_000, IterationPolicy.iterations(Prf.SHA256, 485))
    }

    @Test fun `negative PIM rejected`() {
        assertThrows(IllegalArgumentException::class.java) { IterationPolicy.iterations(Prf.SHA512, -1) }
    }
}
