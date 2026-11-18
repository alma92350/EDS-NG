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
     * Tries each (location, PRF) attempt of [HeaderSearchPlan]; the EARLIEST attempt in plan order that validates wins,
     * even though attempts run in parallel ([parallelism] threads, default = CPU count). The 4 header sectors are read once
     * up front, so storage is never accessed concurrently. [password] is not wiped (caller owns it). Keyfile streams are consumed.
     * [cancelled] is polled before each attempt starts and while waiting.
     */
    fun open(
        storage: RandomAccessStorage,
        password: ByteArray,
        pim: Int = 0,
        keyfiles: List<InputStream> = emptyList(),
        prfs: List<Prf> = Prf.entries,
        readOnly: Boolean = false,
        locations: Set<HeaderLocation> = HeaderLocation.entries.toSet(),
        cancelled: () -> Boolean = { false },
        progress: (done: Int, total: Int) -> Unit = { _, _ -> },
        parallelism: Int = Runtime.getRuntime().availableProcessors(),
    ): OpenResult {
        val size = storage.size
        val mixed = if (keyfiles.isEmpty()) null else KeyfilePool.mix(password, keyfiles)
        val effective = mixed ?: password
        val plan = HeaderSearchPlan.build(prfs).filter { it.location in locations }.filter { it.location.offset(size) >= 0 && it.location.offset(size) + 512 <= size }
        val raws = HeaderLocation.entries.filter { l -> plan.any { it.location == l } }.associateWith { l -> ByteArray(512).also { storage.read(l.offset(size), it) } }
        val stop = java.util.concurrent.atomic.AtomicBoolean(false)
        val pool = java.util.concurrent.Executors.newFixedThreadPool(maxOf(1, minOf(parallelism, plan.size.coerceAtLeast(1)))) { r -> Thread(r, "vc-kdf").apply { isDaemon = true } }
        try {
            val futures = plan.map { a ->
                pool.submit<VolumeHeader?> {
                    if (stop.get() || cancelled()) return@submit null
                    val raw = raws.getValue(a.location)
                    val key = Pbkdf2.derive(a.prf, effective, raw.copyOfRange(0, 64), IterationPolicy.iterations(a.prf, pim), 64)
                    val plain = raw.copyOfRange(64, 512)
                    try {
                        XtsAes(key.copyOfRange(0, 32), key.copyOfRange(32, 64)).decrypt(plain, 0, plain.size, 0)
                        HeaderParser.parse(plain, size)
                    } finally { key.fill(0); plain.fill(0) }
                }
            }
            val tried = ArrayList<Attempt>()
            for ((i, f) in futures.withIndex()) {
                while (true) {
                    if (cancelled()) { stop.set(true); futures.forEach { it.cancel(true) }; return OpenResult.Cancelled }
                    try { f.get(50, java.util.concurrent.TimeUnit.MILLISECONDS); break } catch (e: java.util.concurrent.TimeoutException) { continue }
                }
                tried += plan[i]
                progress(i + 1, plan.size)
                val h = f.get()
                if (h != null) {
                    stop.set(true); futures.drop(i + 1).forEach { it.cancel(true) }
                    // wipe headers produced by later, now-unneeded successes
                    futures.drop(i + 1).forEach { g -> if (g.isDone && !g.isCancelled) runCatching { g.get()?.wipe() } }
                    return OpenResult.Opened(VeraCryptVolume(storage, h, plan[i].location, readOnly), plan[i].prf)
                }
            }
            return OpenResult.Failed(tried)
        } finally {
            pool.shutdownNow()
            mixed?.fill(0); raws.values.forEach { it.fill(0) }
        }
    }
}
