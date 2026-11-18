package org.openvault.veracrypt

import org.openvault.crypto.IterationPolicy
import org.openvault.crypto.KeyfilePool
import org.openvault.crypto.Pbkdf2
import org.openvault.crypto.Prf
import org.openvault.crypto.XtsAes
import org.openvault.io.RandomAccessStorage
import java.io.InputStream

sealed interface OpenResult {
    class Opened(val volume: VeraCryptVolume, val prf: Prf) : OpenResult
    /** Deliberately says WHAT was tried, never which step failed (FR-U5). */
    class Failed(val tried: List<Attempt>) : OpenResult
    object Cancelled : OpenResult
}

object VolumeOpener {
    /**
     * Tries each (location, PRF) attempt in [HeaderSearchPlan] order; the first header that validates wins.
     * [password] is not modified or wiped (caller owns it). Keyfile streams are consumed.
     * Runs sequentially; parallel PRF execution is a later optimisation (ADR-05).
     */
    fun open(
        storage: RandomAccessStorage,
        password: ByteArray,
        pim: Int = 0,
        keyfiles: List<InputStream> = emptyList(),
        prfs: List<Prf> = Prf.entries,
        readOnly: Boolean = false,
        cancelled: () -> Boolean = { false },
        progress: (done: Int, total: Int) -> Unit = { _, _ -> },
    ): OpenResult {
        val size = storage.size
        val effective = KeyfilePool.mix(password, keyfiles)
            .let { if (keyfiles.isEmpty()) password else it }
        val plan = HeaderSearchPlan.build(prfs).filter { it.location.offset(size) >= 0 && it.location.offset(size) + 512 <= size }
        val raw = ByteArray(512)
        val tried = ArrayList<Attempt>()
        try {
            for ((i, a) in plan.withIndex()) {
                if (cancelled()) return OpenResult.Cancelled
                progress(i, plan.size)
                tried += a
                storage.read(a.location.offset(size), raw)
                val salt = raw.copyOfRange(0, 64)
                val key = Pbkdf2.derive(a.prf, effective, salt, IterationPolicy.iterations(a.prf, pim), 64)
                val plain = raw.copyOfRange(64, 512)
                try {
                    XtsAes(key.copyOfRange(0, 32), key.copyOfRange(32, 64)).decrypt(plain, 0, plain.size, 0)
                    val h = HeaderParser.parse(plain, size)
                    if (h != null) return OpenResult.Opened(VeraCryptVolume(storage, h, a.location, readOnly), a.prf)
                } finally {
                    key.fill(0); plain.fill(0)
                }
            }
            return OpenResult.Failed(tried)
        } finally {
            if (keyfiles.isNotEmpty()) effective.fill(0)
        }
    }
}
