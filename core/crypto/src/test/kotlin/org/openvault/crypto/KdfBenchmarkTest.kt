package org.openvault.crypto

import org.junit.jupiter.api.Test

/** Informational only (no assertions): prints single-thread time of one default-iteration derivation per PRF. */
class KdfBenchmarkTest {
    @Test fun `print per-PRF derivation time`() {
        val pw = "benchmark".toByteArray(); val salt = ByteArray(64) { it.toByte() }
        Pbkdf2.derive(Prf.SHA512, pw, salt, 20_000, 64) // warm-up
        for (p in Prf.entries) {
            val t0 = System.nanoTime(); Pbkdf2.derive(p, pw, salt, IterationPolicy.iterations(p, 0), 64)
            println("KDF-BENCH ${p.displayName}: ${(System.nanoTime() - t0) / 1_000_000} ms (500k iterations, this JVM)")
        }
    }
}
