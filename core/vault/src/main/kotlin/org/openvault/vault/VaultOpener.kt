package org.openvault.vault

import org.openvault.crypto.Prf
import org.openvault.crypto.VolumeMode
import org.openvault.fs.FileSystem
import org.openvault.fs.UnsupportedFilesystemException
import org.openvault.fs.exfat.ExfatFileSystem
import org.openvault.fs.fat.FatFileSystem
import org.openvault.io.RandomAccessStorage
import org.openvault.io.BlockDevice
import org.openvault.veracrypt.Attempt
import org.openvault.veracrypt.HeaderLocation
import org.openvault.veracrypt.NonClosingStorage
import org.openvault.veracrypt.ProtectedRangeBlockDevice
import org.openvault.veracrypt.OpenResult
import org.openvault.veracrypt.VolumeOpener
import org.openvault.veracrypt.VeraCryptVolume
import java.io.InputStream

/** Credentials of the hidden volume to protect while writing to the outer volume (FR-U11). */
class HiddenProtection(val password: ByteArray, val pim: Int = 0, val keyfiles: List<InputStream> = emptyList())

sealed interface VaultResult {
    /** [volume] owns the storage; closing [fileSystem] closes the volume and storage. */
    class Opened(val fileSystem: FileSystem, val volume: VeraCryptVolume, val prf: Prf, val usedBackupHeader: Boolean, val isHidden: Boolean, val protection: ProtectedRangeBlockDevice? = null) : VaultResult
    /** Opened the volume but no supported filesystem was found (FR-U8). [kind] e.g. "NTFS", "exFAT", "unformatted or unknown". */
    class UnsupportedFilesystem(val kind: String) : VaultResult
    class Failed(val tried: List<Attempt>) : VaultResult
    /** The outer volume opened but the supplied hidden-volume credentials did not match a hidden header. */
    object HiddenProtectionFailed : VaultResult
    object Cancelled : VaultResult
}

/** Filesystem auto-detect (FR-U8): exFAT by OEM name, otherwise FAT; NTFS/unknown surface as [UnsupportedFilesystemException]. */
internal fun detect(device: BlockDevice, readOnly: Boolean): FileSystem {
    val boot = ByteArray(device.sectorSize); device.readSectors(0, boot, 0, 1)
    return if (ExfatFileSystem.matches(boot)) ExfatFileSystem(device) else FatFileSystem(device, readOnly = readOnly)
}

/** storage -> VeraCrypt volume -> filesystem auto-detect (PRD §4.1 `:core:vault`). */
object VaultOpener {
    fun open(
        storage: RandomAccessStorage, password: ByteArray, pim: Int = 0, keyfiles: List<InputStream> = emptyList(),
        prfs: List<Prf>? = null, readOnly: Boolean = true, hiddenProtection: HiddenProtection? = null,
        cancelled: () -> Boolean = { false }, progress: (Int, Int) -> Unit = { _, _ -> },
        mode: VolumeMode = VolumeMode.VERACRYPT,
    ): VaultResult {
        val locations = if (hiddenProtection != null) setOf(HeaderLocation.NORMAL, HeaderLocation.BACKUP_NORMAL) else HeaderLocation.entries.toSet()
        val r = VolumeOpener.open(storage, password, pim, keyfiles, prfs, readOnly, locations, cancelled, progress, mode = mode)
        return when (r) {
            is OpenResult.Cancelled -> VaultResult.Cancelled
            is OpenResult.Failed -> VaultResult.Failed(r.tried)
            is OpenResult.Opened -> try {
                var device: BlockDevice = r.volume; var protection: ProtectedRangeBlockDevice? = null
                if (hiddenProtection != null && !readOnly) {
                    val h = VolumeOpener.open(NonClosingStorage(storage), hiddenProtection.password, hiddenProtection.pim, hiddenProtection.keyfiles, prfs, true,
                        setOf(HeaderLocation.HIDDEN, HeaderLocation.BACKUP_HIDDEN), cancelled, progress, mode = mode)
                    if (h !is OpenResult.Opened) { r.volume.close(); return VaultResult.HiddenProtectionFailed }
                    val hh = h.volume.header; h.volume.close()
                    val first = (hh.dataOffset - r.volume.header.dataOffset) / r.volume.sectorSize
                    protection = ProtectedRangeBlockDevice(r.volume, first, hh.volumeSize / r.volume.sectorSize)
                    device = protection
                }
                VaultResult.Opened(detect(device, r.volume.isReadOnly), r.volume, r.prf, r.volume.usedBackupHeader, r.volume.isHidden, protection)
            } catch (e: UnsupportedFilesystemException) {
                r.volume.close(); VaultResult.UnsupportedFilesystem(e.kind)
            } catch (e: Throwable) { r.volume.close(); throw e }
        }
    }
}
