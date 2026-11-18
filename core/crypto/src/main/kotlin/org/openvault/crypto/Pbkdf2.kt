package org.openvault.crypto

import org.bouncycastle.crypto.Digest
import org.bouncycastle.crypto.digests.Blake2sDigest
import org.bouncycastle.crypto.digests.GOST3411_2012_512Digest
import org.bouncycastle.crypto.digests.RIPEMD160Digest
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.digests.SHA512Digest
import org.bouncycastle.crypto.digests.WhirlpoolDigest
import org.bouncycastle.crypto.macs.HMac
import org.bouncycastle.crypto.params.KeyParameter

/** VeraCrypt header-derivation PRFs, in auto-detect order (PRD §6.3). */
enum class Prf(val displayName: String, internal val newDigest: () -> Digest) {
    SHA512("SHA-512", ::SHA512Digest),
    SHA256("SHA-256", ::SHA256Digest),
    BLAKE2S("BLAKE2s-256", { Blake2sDigest(256) }),
    WHIRLPOOL("Whirlpool", ::WhirlpoolDigest),
    STREEBOG("Streebog", ::GOST3411_2012_512Digest),
    /** TrueCrypt's default PRF; in VeraCrypt it is deprecated but still readable (655331 iterations). */
    RIPEMD160("RIPEMD-160", ::RIPEMD160Digest);

    companion object {
        /** PRFs to try, in order, for each on-disk format. */
        fun defaultFor(mode: VolumeMode): List<Prf> = when (mode) {
            VolumeMode.VERACRYPT -> listOf(SHA512, SHA256, BLAKE2S, WHIRLPOOL, STREEBOG)
            VolumeMode.TRUECRYPT -> listOf(RIPEMD160, SHA512, WHIRLPOOL)
        }

        /** Fast PRFs (<= ~1.3 s each on a desktop JVM) for the default auto-detect; Whirlpool/Streebog cost 3.5-5.6 s each. */
        val COMMON = listOf(SHA512, SHA256, BLAKE2S)
    }
}

/** On-disk format family: header magic, iteration rules and header-version rules differ (PRD open question 4 resolved: supported on request). */
enum class VolumeMode { VERACRYPT, TRUECRYPT }

/** PBKDF2-HMAC with byte-array passwords (no char[] APIs, so binary/non-ASCII input is safe). */
object Pbkdf2 {
    fun derive(prf: Prf, password: ByteArray, salt: ByteArray, iterations: Int, dkLen: Int): ByteArray {
        require(iterations >= 1 && dkLen >= 1)
        val mac = HMac(prf.newDigest())
        mac.init(KeyParameter(password))
        val hLen = mac.macSize
        val out = ByteArray(dkLen)
        val u = ByteArray(hLen)
        val t = ByteArray(hLen)
        val blocks = (dkLen + hLen - 1) / hLen
        for (i in 1..blocks) {
            mac.update(salt, 0, salt.size)
            mac.update(byteArrayOf((i ushr 24).toByte(), (i ushr 16).toByte(), (i ushr 8).toByte(), i.toByte()), 0, 4)
            mac.doFinal(u, 0)
            System.arraycopy(u, 0, t, 0, hLen)
            for (n in 2..iterations) {
                mac.update(u, 0, hLen)
                mac.doFinal(u, 0)
                for (j in 0 until hLen) t[j] = (t[j].toInt() xor u[j].toInt()).toByte()
            }
            System.arraycopy(t, 0, out, (i - 1) * hLen, minOf(hLen, dkLen - (i - 1) * hLen))
        }
        u.fill(0); t.fill(0)
        return out
    }
}

/** Iteration counts for non-system volumes (PRD §6.3; BLAKE2s value ⚠ VERIFY against desktop-VeraCrypt fixtures). */
object IterationPolicy {
    const val DEFAULT_ITERATIONS = 500_000
    private const val RIPEMD160_DEFAULT = 655_331

    /**
     * VeraCrypt: PIM 0 -> 500 000 (655 331 for RIPEMD-160), else 15 000 + PIM x 1 000.
     * TrueCrypt: fixed counts, no PIM: RIPEMD-160 2000, SHA-512 1000, Whirlpool 1000 (other PRFs do not exist in TrueCrypt).
     */
    fun iterations(prf: Prf, pim: Int, mode: VolumeMode = VolumeMode.VERACRYPT): Int {
        require(pim >= 0) { "PIM must not be negative" }
        if (mode == VolumeMode.TRUECRYPT) {
            require(pim == 0) { "PIM is not supported in TrueCrypt mode" }
            return when (prf) {
                Prf.RIPEMD160 -> 2000
                Prf.SHA512, Prf.WHIRLPOOL -> 1000
                else -> throw IllegalArgumentException("${prf.displayName} is not a TrueCrypt hash")
            }
        }
        return if (pim == 0) (if (prf == Prf.RIPEMD160) RIPEMD160_DEFAULT else DEFAULT_ITERATIONS) else 15_000 + pim * 1_000
    }
}
