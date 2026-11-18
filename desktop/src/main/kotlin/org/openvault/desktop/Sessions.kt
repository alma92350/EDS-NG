package org.openvault.desktop

import org.openvault.vault.LockPolicy
import java.awt.AWTEvent
import java.awt.Toolkit
import java.awt.event.AWTEventListener
import java.util.prefs.Preferences
import javax.swing.JFrame
import javax.swing.SwingUtilities
import javax.swing.Timer

/** Registry of unlocked vaults + inactivity auto-lock (pure policy in [LockPolicy]; this is the Swing glue). */
object Sessions {
    private class Entry(val session: DesktopSession, val frame: JFrame)
    private val entries = ArrayList<Entry>()
    val listeners = ArrayList<() -> Unit>()
    private val prefs = Preferences.userRoot().node("org/openvault/desktop")
    val policy = LockPolicy(prefs.getLong("timeout_ms", 5 * 60_000L)) { System.currentTimeMillis() }
    private var timer: Timer? = null

    val count get() = entries.size

    fun add(session: DesktopSession, frame: JFrame) {
        entries += Entry(session, frame); policy.activity(); ensureTimer(); notifyChanged()
    }

    fun remove(session: DesktopSession) { entries.removeAll { it.session === session }; notifyChanged() }

    fun lockAll() {
        entries.toList().forEach { it.session.lock(); it.frame.dispose() }
        entries.clear(); notifyChanged()
    }

    fun setTimeout(ms: Long) { policy.timeoutMs = ms; prefs.putLong("timeout_ms", ms); policy.activity() }

    private fun notifyChanged() = listeners.toList().forEach { it() }

    private fun ensureTimer() {
        if (timer != null) return
        Toolkit.getDefaultToolkit().addAWTEventListener(AWTEventListener { policy.activity() }, AWTEvent.MOUSE_EVENT_MASK or AWTEvent.KEY_EVENT_MASK or AWTEvent.MOUSE_MOTION_EVENT_MASK)
        timer = Timer(1000) { if (entries.isNotEmpty() && policy.shouldLockNow()) lockAll() }.also { it.start() }
    }

    fun recent(): List<String> = prefs.get("recent", "").split('\n').filter { it.isNotBlank() }
    fun addRecent(path: String) { prefs.put("recent", (listOf(path) + recent().filter { it != path }).take(10).joinToString("\n")) }
    fun removeRecent(path: String) { prefs.put("recent", recent().filter { it != path }.joinToString("\n")) }
}
