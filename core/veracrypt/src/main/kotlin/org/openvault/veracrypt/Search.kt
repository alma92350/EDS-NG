package org.openvault.veracrypt

import org.openvault.crypto.Prf

/** Where a header may live in a file container (PRD §6.1). */
enum class HeaderLocation(val isBackup: Boolean, val isHidden: Boolean) {
    NORMAL(false, false), HIDDEN(false, true), BACKUP_NORMAL(true, false), BACKUP_HIDDEN(true, true);

    fun offset(storageSize: Long): Long = when (this) {
        NORMAL -> 0L
        HIDDEN -> 65_536L
        BACKUP_NORMAL -> storageSize - 131_072L
        BACKUP_HIDDEN -> storageSize - 65_536L
    }
}

data class Attempt(val location: HeaderLocation, val prf: Prf)

/** ADR-05: the ordered list of (location, PRF) attempts. Pure data, so it can be tested without any KDF. */
object HeaderSearchPlan {
    fun build(prfs: List<Prf>): List<Attempt> =
        HeaderLocation.entries.flatMap { loc -> prfs.map { Attempt(loc, it) } }
}
