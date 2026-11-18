package org.openvault.vault

/**
 * Pure inactivity policy (FR-L2/L3): the vault locks [timeoutMs] after the last activity (UI interaction or I/O),
 * immediately on screen-off when enabled. [timeoutMs] <= 0 means "never" for the inactivity rule. The Android layer
 * only asks [msUntilLock] and schedules a timer, so this logic is tested on the JVM (ADR-08).
 */
class LockPolicy(var timeoutMs: Long, var lockOnScreenOff: Boolean = true, private val clock: () -> Long) {
    private var last = clock()
    fun activity() { last = clock() }
    /** Milliseconds until the inactivity lock is due (0 = due now), or null if the timeout is "never". */
    fun msUntilLock(): Long? = if (timeoutMs <= 0) null else maxOf(0L, timeoutMs - (clock() - last))
    fun shouldLockNow(): Boolean = msUntilLock() == 0L
    fun shouldLockOnScreenOff(): Boolean = lockOnScreenOff
}
