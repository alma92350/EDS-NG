package org.openvault.vault

import org.openvault.crypto.Prf
import org.openvault.fs.FileSystem
import org.openvault.fs.UnsupportedFilesystemException
import org.openvault.fs.fat.FatFileSystem
import org.openvault.io.RandomAccessStorage
import org.openvault.veracrypt.Attempt
import org.openvault.veracrypt.OpenResult
import org.openvault.veracrypt.VolumeOpener
import org.openvault.veracrypt.VeraCryptVolume
import java.io.InputStream

sealed interface VaultResult {
    /** [volume] owns the storage; closing [fileSystem] closes the volume and storage. */
    class Opened(val fileSystem: FileSystem, val volume: VeraCryptVolume, val prf: Prf, val usedBackupHeader: Boolean, val isHidden: Boolean) : VaultResult
    /** Opened the volume but no supported filesystem was found (FR-U8). [kind] e.g. "NTFS", "exFAT", "unformatted or unknown". */
    class UnsupportedFilesystem(val kind: String) : VaultResult
    class Failed(val tried: List<Attempt>) : VaultResult
    object Cancelled : VaultResult
}

/** storage -> VeraCrypt volume -> filesystem auto-detect (PRD §4.1 `:core:vault`). */
object VaultOpener {
    fun open(
        storage: RandomAccessStorage, password: ByteArray, pim: Int = 0, keyfiles: List<InputStream> = emptyList(),
        prfs: List<Prf> = Prf.entries, readOnly: Boolean = true,
        cancelled: () -> Boolean = { false }, progress: (Int, Int) -> Unit = { _, _ -> },
    ): VaultResult = when (val r = VolumeOpener.open(storage, password, pim, keyfiles, prfs, readOnly, cancelled, progress)) {
        is OpenResult.Cancelled -> VaultResult.Cancelled
        is OpenResult.Failed -> VaultResult.Failed(r.tried)
        is OpenResult.Opened -> try {
            VaultResult.Opened(FatFileSystem(r.volume), r.volume, r.prf, r.volume.usedBackupHeader, r.volume.isHidden)
        } catch (e: UnsupportedFilesystemException) {
            r.volume.close(); VaultResult.UnsupportedFilesystem(e.kind)
        } catch (e: Throwable) { r.volume.close(); throw e }
    }
}
