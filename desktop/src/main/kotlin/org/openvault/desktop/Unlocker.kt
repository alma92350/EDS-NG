package org.openvault.desktop

import org.openvault.crypto.Prf
import org.openvault.crypto.SecretBytes
import org.openvault.crypto.VolumeMode
import org.openvault.io.FileStorage
import org.openvault.vault.HiddenProtection
import org.openvault.vault.VaultOpener
import org.openvault.vault.VaultResult
import java.io.ByteArrayInputStream
import java.io.File

class UnlockRequest(
    val file: File, val password: CharArray, val pim: Int = 0, val keyfiles: List<File> = emptyList(),
    val readOnly: Boolean = true, val truecrypt: Boolean = false, val tryAllHashes: Boolean = false,
    val hiddenProtectionPassword: CharArray? = null,
)

sealed interface UnlockOutcome {
    class Opened(val session: DesktopSession, val warning: String?) : UnlockOutcome
    /** [message] is the single generic text for wrong password / unsupported settings (FR-U5). */
    class Failed(val message: String) : UnlockOutcome
    object Cancelled : UnlockOutcome
}

object Unlocker {
    const val GENERIC_FAILURE = "Incorrect password, PIM, keyfiles or unsupported settings"
    private fun secret(c: CharArray) = SecretBytes.ofUtf8(c)

    /** Wipes the password arrays in [req] when done. Never throws for expected failures. */
    fun open(req: UnlockRequest, cancelled: () -> Boolean = { false }, progress: (Int, Int) -> Unit = { _, _ -> }): UnlockOutcome {
        val pw = secret(req.password); val hp = req.hiddenProtectionPassword?.let { secret(it) }
        req.password.fill('\u0000'); req.hiddenProtectionPassword?.fill('\u0000')
        var storage: FileStorage? = null
        try {
            if (pw.size > 128 || (hp?.size ?: 0) > 128) return UnlockOutcome.Failed("Passwords longer than 128 bytes are not supported")
            val kfs = req.keyfiles.map { f -> f.inputStream().use { it.readNBytes(1024 * 1024) } }
            var readOnly = req.readOnly; var warning: String? = null
            storage = try { FileStorage(req.file, !readOnly) } catch (e: java.io.IOException) {
                if (readOnly) throw e
                readOnly = true; warning = "The file could not be opened for writing: opened read-only"; FileStorage(req.file, false)
            }
            val mode = if (req.truecrypt) VolumeMode.TRUECRYPT else VolumeMode.VERACRYPT
            val prfs = when { req.truecrypt -> Prf.defaultFor(mode); req.tryAllHashes -> Prf.defaultFor(mode); else -> Prf.COMMON }
            val r = VaultOpener.open(storage, pw.bytes, if (req.truecrypt) 0 else req.pim, kfs.map { ByteArrayInputStream(it) }, prfs, readOnly,
                hp?.let { HiddenProtection(it.bytes) }, cancelled, progress, mode)
            kfs.forEach { it.fill(0) }
            return when (r) {
                is VaultResult.Opened -> {
                    val note = listOfNotNull(warning, if (!readOnly && r.fileSystem.isReadOnly) "This filesystem is read-only in this version (NTFS/exFAT): write actions are disabled." else null, if (r.usedBackupHeader) "Primary header damaged, opened with backup header" else null).joinToString("\n").ifEmpty { null }
                    UnlockOutcome.Opened(DesktopSession(req.file.name, r.fileSystem, readOnly || r.fileSystem.isReadOnly, r.protection, r.isHidden), note).also { storage = null }
                }
                is VaultResult.Failed -> UnlockOutcome.Failed(GENERIC_FAILURE + when {
                    req.truecrypt -> "\n\nTrueCrypt mode: RIPEMD-160, SHA-512 and Whirlpool were tried (AES only, no PIM)."
                    !req.tryAllHashes -> "\n\nOnly SHA-512, SHA-256 and BLAKE2s were tried; enable \"try all hash algorithms\" for Whirlpool/Streebog, or TrueCrypt mode for old containers."
                    else -> "" })
                is VaultResult.HiddenProtectionFailed -> UnlockOutcome.Failed("The hidden volume password did not match, so protection could not be enabled.")
                is VaultResult.UnsupportedFilesystem -> UnlockOutcome.Failed("Unsupported filesystem (${r.kind}). This version reads FAT12/16/32, exFAT and NTFS.")
                is VaultResult.Cancelled -> UnlockOutcome.Cancelled
            }
        } catch (e: Exception) {
            return UnlockOutcome.Failed(e.message ?: e.javaClass.simpleName)
        } finally { pw.close(); hp?.close(); storage?.close() }
    }
}
