package org.openvault.vault

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class LockPolicyTest {
    private var now = 1_000L
    private fun p(timeout: Long = 300_000) = LockPolicy(timeout, clock = { now })

    @Test fun `counts down from last activity`() { val p = p(); now += 100_000; assertEquals(200_000L, p.msUntilLock()); assertFalse(p.shouldLockNow()) }
    @Test fun `activity resets the timer`() { val p = p(); now += 250_000; p.activity(); now += 250_000; assertFalse(p.shouldLockNow()); assertEquals(50_000L, p.msUntilLock()) }
    @Test fun `locks exactly at the timeout and stays due`() { val p = p(); now += 300_000; assertTrue(p.shouldLockNow()); now += 1; assertEquals(0L, p.msUntilLock()) }
    @Test fun `never means no timer`() { val p = p(0); now += 10_000_000; assertNull(p.msUntilLock()); assertFalse(p.shouldLockNow()) }
    @Test fun `timeout can change at runtime`() { val p = p(); now += 100_000; p.timeoutMs = 60_000; assertTrue(p.shouldLockNow()) }
    @Test fun `screen off setting`() { val p = p(); assertTrue(p.shouldLockOnScreenOff()); p.lockOnScreenOff = false; assertFalse(p.shouldLockOnScreenOff()) }
}
