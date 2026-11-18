# EDS NG — Reference Analysis (for a clean-room rewrite)

Source: `apk-origin/` XAPKs, versions 1.16.75 and 1.19.110, analysed with stdlib-only tools
(`work/tools/apkinfo.py`, `work/tools/elfsyms.py`). No decompiled source was used. Everything
below is from the manifest, class/method names, JNI exports, strings and bundled docs.
**Use this as a feature and architecture reference only. Do not copy code from the APK.**

## 1. Core architecture: stacked filesystems

The central idea is a single filesystem interface that every layer implements, so layers can be
stacked arbitrarily (for example: a VeraCrypt volume, inside a file, on Dropbox).

```
                ┌────────────────────────────────────────────┐
  UI            │ File manager · viewers · widgets · SAF      │
                └───────────────▲────────────────────────────┘
                                │ BlockingFileSystem (list/stat/open/rename/delete…)
        ┌───────────────────────┼─────────────────────────────────┐
        │                       │                                 │
  (A) Block-device containers   │              (B) Overlay containers
  VeraCrypt · LUKS · BitLocker · VHD           gocryptfs · CryFS · EncFS
        │                                                  │
  Volume: read/write/getSize of the                 a "FUSE session" that translates
  *decrypted* block device                          paths/contents over an UNDERLYING
        │                                           PathnameFileSystemProvider (Java callback)
  Userspace FS driver on that device:                      │
  FAT · exFAT · NTFS · ext4 (native, FUSE-style ops)       │
        │                                                  │
        └──────────────► underlying storage ◄──────────────┘
                 local · SAF · USB OTG (libusb) · SMB · SFTP · FTP(S) · WebDAV
                 S3 · Google Drive · Dropbox · OneDrive · Box · pCloud · MEGA · Yandex
```

Evidence (JNI exports):
- `VeraCryptImpl.openVolume / createVcVolume`, `VeraCryptVolume.read / write / getSize / changeVcPassword / close`
- `LuksCryptSetup.open / create / add / change / removeKeySlot / read / write`, `BitLockerCryptSetup.open / read / write`
- `GoCryptFsImpl.open/createGoCryptFsFuseSession`, `CryFsImpl.openCryFsFuseSession`, `EncFsImpl.open/createEncFsFuseSession`
- `BlockingFuseFileSystem.setPathnameFileSystemProvider / listMembers / openFile / newFile / newGroup / renameObject / delete / getSpaceInfo …`
- `BlockingFatFuseFileSystem.formatFatFileSystem`: it can create new FAT-formatted containers.

Note: "FUSE session" here means libfuse-style operations called **in process**. No kernel mount
is needed. Kernel mounting is optional and needs root (see §4).

## 2. Container crypto

| Format | Native lib | Upstream (license) | Operations |
|---|---|---|---|
| VeraCrypt | libveracrypt | VeraCrypt (Apache-2.0 + TrueCrypt 3.0 parts) | open, create, change password; Argon2 added in 1.19 |
| LUKS1/2 | libcryptsetup | cryptsetup (GPL-2.0) | open, create, add/change password, remove keyslot |
| BitLocker | libcryptsetup | cryptsetup/libbde-style | open existing containers only |
| gocryptfs | libgocryptfs (Go) | gocryptfs (MIT) | open, create, change password |
| CryFS | libcryfs-jni | CryFS (LGPL-3.0) | open, set config |
| EncFS | libencfs-jni | EncFS (LGPL-3.0/GPL) | open, create, change password, filename-encryption choices |

- **Ciphers and modes:** AES, Serpent, Twofish, Camellia and Kuznyechik in XTS mode, plus cascades.
- **Key derivation:** PBKDF2-HMAC with SHA-512, Whirlpool or Streebog; Argon2id; scrypt (gocryptfs).
- **Unlock factors:** password, keyfiles (`KeyFilesMode`), fingerprint or pattern unlocking a stored
  password, YubiKey (OTP and challenge-response), NFC.
- **Master password:** protects the app's own stored settings and credentials (`MasterPasswordInputActivity`).
- **Crypto libraries:** OpenSSL 3 natively, BouncyCastle on the JVM side.

## 3. Filesystem drivers inside volumes
`libfat` (FAT12/16/32, can format), `libexfat`, `libntfs` (ntfs-3g, GPL), `libext4` (lwext4-like).
All of them expose the same in-process FUSE-style operations as above.

## 4. Exposure to other apps
- `DocumentsContentProvider` is a SAF `DocumentsProvider` (exported, `MANAGE_DOCUMENTS`). Open containers
  appear in the system file picker. **No root needed. This is the primary integration path.**
- `FileContentProvider` gives temporary `content://` grants for opening single files in external apps.
- Local FTP server: exposes an open container on localhost.
- Root mode: `assets/main.jar` holds libsu's `RootServerMain`. `libmounter` mounts the FUSE session through
  `/dev/fuse`, and there are bind-mount workarounds for per-app mount namespaces
  (`MountBindNamespaceWorkaround`). An "app data isolation" feature redirects other apps' paths.

## 5. Feature inventory (UI)
- **File manager:** two panels, search, sorting, gallery and grid view, checksum shown in file properties,
  hidden dot-files option, fast scroll, shortcuts.
- **Viewers:** images (including animated WebP), video and audio (Media3, with subtitles, audio tracks and
  playlists), PDF (libpdfsdk, with bookmarks), text editor (multiple encodings).
- **"Forms" folder:** structured records (password-manager-like), with a creation widget and a
  password generator.
- **Automatic folder encryption** (sync a plain folder into a container), and capturing photos or videos
  straight into a container.
- **Widgets:** app shortcut, storage reset (emergency wipe, which can delete container files), form creation.
- **Calculator masking:** a working calculator acts as the launcher (`CalcActivityAlias`), and a secret
  code opens the vault. Reset codes trigger a wipe.
- **Hardening and convenience:** auto-close timeout, hide from recents, auto-open on launch,
  close-all notification action, custom script on mount.

## 6. Candidates for removal ("slim down")

| Component | Weight | Notes |
|---|---|---|
| Microsoft identity + OneDrive SDK | ~39 000 classes, about half the app | Biggest single win |
| Box, MEGA (`libmega` 11 MB), pCloud, Yandex SDKs | large | Keep only what you need |
| AWS S3 SDK (Kotlin) | large | Could use plain HTTP signing instead |
| AI assistant (`lc.sovworks.com/v1/ask_ai`) | small | Sends data to a vendor server |
| Virus scan (`api.cloudmersive.com`) | small | Uploads files to a third party |
| Google Play Billing, Firebase transport | medium | Not needed for a personal app |
| junit/hamcrest/androidx.test shipped in release | — | Build hygiene |
| `usesCleartextTraffic=true` | — | Tighten |

## 7. Licensing implications for a new app
Reusing **cryptsetup, ntfs-3g or exfat** (GPL-2.0) makes the whole app GPL. VeraCrypt's code carries
the TrueCrypt License 3.0, which is not OSI-approved and is awkward to redistribute. gocryptfs (MIT)
and the published format specs (VeraCrypt volume format, LUKS2 on-disk format, gocryptfs format)
can be implemented independently without that baggage.
