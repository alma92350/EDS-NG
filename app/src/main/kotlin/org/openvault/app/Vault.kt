package org.openvault.app

import android.app.Application
import android.app.Activity
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.Uri
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import org.openvault.fs.FileSystem
import org.openvault.io.RandomAccessStorage
import org.openvault.io.checkRange
import org.openvault.vault.LockPolicy
import org.openvault.veracrypt.ProtectedRangeBlockDevice
import java.io.EOFException
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.util.concurrent.Callable
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

/** Container bytes behind a SAF document, via positional I/O on the file descriptor (no copies). */
class SafStorage(private val pfd: ParcelFileDescriptor, writable: Boolean) : RandomAccessStorage {
    private val rd: FileChannel = FileInputStream(pfd.fileDescriptor).channel
    private val wr: FileChannel? = if (writable) FileOutputStream(pfd.fileDescriptor).channel else null
    override val size: Long
    override val isReadOnly = !writable

    init {
        try { size = rd.size(); rd.position() } // pipes / non-seekable providers throw here (FR-C6)
        catch (e: IOException) { runCatching { pfd.close() }; throw IOException("This location does not support random access. Copy the container to local storage first.", e) }
    }

    override fun read(position: Long, dst: ByteArray, off: Int, len: Int) {
        checkRange(position, off, len, dst.size, size)
        val bb = ByteBuffer.wrap(dst, off, len); var p = position
        while (bb.hasRemaining()) { val n = rd.read(bb, p); if (n < 0) throw EOFException("unexpected end of container"); p += n }
    }

    override fun write(position: Long, src: ByteArray, off: Int, len: Int) {
        val w = wr ?: throw IOException("container opened read-only")
        checkRange(position, off, len, src.size, size)
        val bb = ByteBuffer.wrap(src, off, len); var p = position
        while (bb.hasRemaining()) p += w.write(bb, p)
    }

    override fun flush() { wr?.force(false) }
    override fun close() { runCatching { rd.close() }; runCatching { wr?.close() }; runCatching { pfd.close() } }
}

/** The single unlocked vault of this process. All filesystem calls run on one thread ([io]); locking wipes keys. */
object Vault {
    class Session(val containerName: String, val fs: FileSystem, val readOnly: Boolean, val protection: ProtectedRangeBlockDevice?, val exec: ExecutorService)

    private val ui = Handler(Looper.getMainLooper())
    @Volatile var session: Session? = null
        private set
    val lockListeners = ArrayList<() -> Unit>()
    var policy = LockPolicy(5 * 60_000L) { System.currentTimeMillis() }
    private val timer = Runnable { checkTimer() }

    fun start(name: String, fs: FileSystem, readOnly: Boolean, protection: ProtectedRangeBlockDevice?) {
        lock()
        session = Session(name, fs, readOnly, protection, Executors.newSingleThreadExecutor { r -> Thread(r, "vault-io") })
        activity(); schedule()
    }

    fun activity() { policy.activity(); schedule() }

    private fun schedule() {
        ui.removeCallbacks(timer)
        if (session == null) return
        policy.msUntilLock()?.let { ui.postDelayed(timer, it + 50) }
    }

    private fun checkTimer() { if (policy.shouldLockNow()) lock() else schedule() }

    /** Runs [block] on the vault thread and delivers the result on the UI thread. */
    fun <T> io(block: () -> T, done: (Result<T>) -> Unit) {
        val s = session ?: return done(Result.failure(IOException("vault is locked")))
        activity()
        s.exec.submit { val r = runCatching(block); ui.post { done(r) } }
    }

    /** Locks: finishes pending work, syncs, closes (zeroing keys and caches), notifies listeners. Safe to call repeatedly. */
    fun lock() {
        val s = session ?: return
        session = null
        ui.removeCallbacks(timer)
        s.exec.submit { runCatching { s.fs.sync() }; runCatching { s.fs.close() } }
        s.exec.shutdown()
        lockListeners.toList().forEach { it() }
    }
}

class App : Application() {
    private var started = 0

    override fun attachBaseContext(base: Context) { super.attachBaseContext(base); CrashReporter.install(this) }

    override fun onCreate() {
        super.onCreate()
        val screenOff = object : BroadcastReceiver() {
            override fun onReceive(c: Context, i: Intent) { if (Vault.policy.shouldLockOnScreenOff()) Vault.lock() }
        }
        // 4 = RECEIVER_NOT_EXPORTED (API 33); older versions have no such flag
        if (android.os.Build.VERSION.SDK_INT >= 33) registerReceiver(screenOff, IntentFilter(Intent.ACTION_SCREEN_OFF), 4)
        else registerReceiver(screenOff, IntentFilter(Intent.ACTION_SCREEN_OFF))
        registerActivityLifecycleCallbacks(object : ActivityLifecycleCallbacks {
            override fun onActivityStarted(a: Activity) { started++ }
            override fun onActivityStopped(a: Activity) { started-- }
            override fun onActivityCreated(a: Activity, b: Bundle?) {}
            override fun onActivityResumed(a: Activity) {}
            override fun onActivityPaused(a: Activity) {}
            override fun onActivitySaveInstanceState(a: Activity, b: Bundle) {}
            override fun onActivityDestroyed(a: Activity) {}
        })
    }
}

fun Context.prefs() = getSharedPreferences("openvault", Context.MODE_PRIVATE)
fun Uri.displayName(ctx: Context): String = ctx.contentResolver.query(this, arrayOf(android.provider.OpenableColumns.DISPLAY_NAME), null, null, null)?.use { if (it.moveToFirst()) it.getString(0) else null } ?: (lastPathSegment ?: "file")
