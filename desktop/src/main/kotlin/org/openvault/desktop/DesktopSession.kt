package org.openvault.desktop

import org.openvault.fs.FileSystem
import org.openvault.veracrypt.ProtectedRangeBlockDevice
import java.util.concurrent.Executors
import javax.swing.SwingUtilities

/** One unlocked vault. All filesystem access is serialised on a single thread (filesystem drivers are not thread-safe). */
class DesktopSession(val name: String, private val fileSystem: FileSystem, val readOnly: Boolean, val protection: ProtectedRangeBlockDevice?, val isHidden: Boolean = false) {
    private val exec = Executors.newSingleThreadExecutor { r -> Thread(r, "vault-io").apply { isDaemon = true } }
    @Volatile var locked = false
        private set

    /** Runs [block] on the vault thread and waits (used by tests and by short operations). */
    fun <T> sync(block: (FileSystem) -> T): T {
        if (locked) throw java.io.IOException("vault is locked")
        return try { exec.submit<T> { block(fileSystem) }.get() } catch (e: java.util.concurrent.ExecutionException) { throw e.cause ?: e }
    }

    /** Runs [block] on the vault thread, delivers the result on the Swing event thread. */
    fun <T> async(block: (FileSystem) -> T, done: (Result<T>) -> Unit) {
        if (locked) { SwingUtilities.invokeLater { done(Result.failure(java.io.IOException("vault is locked"))) }; return }
        exec.submit { val r = runCatching { block(fileSystem) }; SwingUtilities.invokeLater { done(r) } }
    }

    /** Syncs and closes the filesystem (zeroing keys and caches). Idempotent. */
    fun lock() {
        if (locked) return
        locked = true
        exec.submit { runCatching { fileSystem.sync() }; runCatching { fileSystem.close() } }
        exec.shutdown()
    }
}
