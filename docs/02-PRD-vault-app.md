# PRD: Encrypted Container Vault for Android (working title: **OpenVault**)

| | |
|---|---|
| **Status** | Draft v1.0, 2026-11-18 |
| **Scope of this PRD** | MVP (v1.0) in full detail; Phase 2+ as roadmap |
| **Reference** | `docs/01-eds-ng-reference-analysis.md` (EDS NG analysis, for features and architecture only) |
| **License of the new app** | GPL-3.0-or-later |
| **Platform** | Android 8.0+ (minSdk 26), targetSdk = latest stable (35/36) |
| **Language** | Kotlin only for the MVP (no NDK) |

> **Clean-room rule.** EDS NG is a closed-source commercial app. It is a *behavioural* reference
> only. Never copy code, resources, strings or assets from the APK. Implement the VeraCrypt format
> from its public documentation and test it against containers created with desktop VeraCrypt.
> Do **not** copy VeraCrypt source code either: parts of it are under the TrueCrypt License 3.0,
> which is not GPL-compatible. Reading its documentation and format description is fine.

---

## 1. Summary

OpenVault is a small, auditable Android app that opens **VeraCrypt file containers**. Users can
browse, view, add and export files inside them, and other apps can open those files through the
**Android system file picker (Storage Access Framework, SAF)**. It needs no root, no
`MANAGE_EXTERNAL_STORAGE` and **no Internet permission**.

It keeps the strongest idea from EDS NG: **layered filesystems behind one common interface**. A
block device is decrypted into a virtual disk, a filesystem driver reads that disk, and the result is
shown in the UI and the file picker. It drops EDS NG's bloat (cloud SDKs, AI assistant, virus scan
upload, billing).

## 2. Goals and non-goals

### 2.1 Goals (MVP)
- G1. Open existing VeraCrypt file containers (normal **and hidden** volumes) created by desktop VeraCrypt 1.2x with default settings.
- G2. Read and write files in **FAT12/16/32** volumes (with long file names), and read **exFAT** volumes.
- G3. Expose unlocked containers through a SAF `DocumentsProvider` with random-access file descriptors.
- G4. Provide a usable built-in file manager: browse, view images and text, import, export, rename, delete, create folders.
- G5. Strong local security: no network, auto-lock, wipe keys from memory on lock, block screenshots.
- G6. The crypto and filesystem core are **pure Kotlin/JVM modules** with unit tests that run on a desktop JVM. A desktop CLI makes debugging possible without a phone.

### 2.2 Non-goals (MVP)
- Creating new containers, changing passwords (Phase 2).
- LUKS, gocryptfs, CryFS, EncFS, BitLocker, VHD (Phase 3+).
- Cascade ciphers (Serpent, Twofish, Camellia, Kuznyechik) and Argon2: they are **detected and reported as unsupported**, not silently failed.
- NTFS and ext4 inside volumes (Phase 3, would use GPL native libraries).
- Cloud or network storage, USB OTG raw access, root FUSE mounting.
- Calculator disguise, widgets, forms, auto-encryption of folders (later phases).
- System encryption or partition-level (device) volumes.

## 3. Users and use cases

| ID | Persona | Use case |
|---|---|---|
| UC1 | Privacy-conscious user with a desktop VeraCrypt container synced to the phone (USB copy, Syncthing, etc.) | Opens the container on the phone, reads a PDF, closes it. |
| UC2 | Same | Takes a document from the Downloads folder and **imports** it into the container. |
| UC3 | Same | Opens a photo inside the container **with another app** (gallery or editor) through the file picker, without leaving a plaintext copy. |
| UC4 | Same | Phone locked or app backgrounded too long: the vault locks automatically and keys are wiped. |
| UC5 | User under coercion | Opens the outer volume with the decoy password. Nothing reveals that a hidden volume exists. |

## 4. Architecture

### 4.1 Layering

```
┌──────────────────────────── :app (Android) ─────────────────────────────┐
│  Compose UI  ·  VaultSessionService (foreground)  ·  VaultDocumentsProvider│
│                 └────────── VaultManager (unlocked sessions) ──────────┘  │
└───────────────────────────────▲──────────────────────────────────────────┘
                                │ FileSystem  (:core:fs-api)
             ┌──────────────────┴──────────────────┐
             │ :core:fs-fat  (FAT12/16/32 + LFN)    │   :core:fs-exfat (read-only MVP)
             └──────────────────▲──────────────────┘
                                │ BlockDevice (decrypted, 512-B sectors)
             ┌──────────────────┴──────────────────┐
             │ :core:veracrypt  (header, volume)    │
             └──────────────────▲──────────────────┘
                                │ uses :core:crypto (XTS, AES, PBKDF2, PRFs, keyfiles)
                                │ RandomAccessStorage (encrypted container bytes)
             ┌──────────────────┴──────────────────┐
             │ :app  SafRandomAccessStorage         │  (ParcelFileDescriptor + FileChannel)
             │ :tools:cli  FileRandomAccessStorage  │  (java.io.RandomAccessFile)
             └─────────────────────────────────────┘
```

### 4.2 Gradle modules

| Module | Type | Depends on | Contents |
|---|---|---|---|
| `:core:io` | Kotlin/JVM | none | `RandomAccessStorage`, `BlockDevice`, helpers (bounds checks, sector caching) |
| `:core:crypto` | Kotlin/JVM | `:core:io`, BouncyCastle | AES-XTS, PBKDF2 for each PRF, keyfile mixing, CRC32, secure wipe utilities |
| `:core:veracrypt` | Kotlin/JVM | `:core:crypto` | Header parsing/validation, try-all-combinations open, `VeraCryptVolume : BlockDevice` |
| `:core:fs-api` | Kotlin/JVM | `:core:io` | `FileSystem`, `FsNode`, `FsFile`, errors, path utilities |
| `:core:fs-fat` | Kotlin/JVM | `:core:fs-api` | FAT driver (read/write). Possibly an adapter over vendored libaums FAT32 code (§15.3) |
| `:core:fs-exfat` | Kotlin/JVM | `:core:fs-api` | exFAT driver (read-only in MVP) |
| `:core:vault` | Kotlin/JVM | all core | `VaultOpener`: storage → volume → auto-detect filesystem → `FileSystem` |
| `:tools:cli` | Kotlin/JVM app | `:core:vault` | Desktop CLI: `info`, `ls`, `cat`, `get`, `put`, `fsck` |
| `:app` | Android app | `:core:vault` | UI, SAF provider, service, settings |
| `:testing:fixtures` | test resources | none | Small VeraCrypt test containers + `fixtures.json` (passwords, expected tree) |

**Rule:** no `android.*` imports in any `:core:*` module. CI enforces this (`./gradlew :core:...:test` runs without the Android SDK).

### 4.3 Core interfaces (normative sketch)

```kotlin
// :core:io
interface RandomAccessStorage : Closeable {
    val size: Long
    val isReadOnly: Boolean
    fun read(position: Long, dst: ByteArray, off: Int = 0, len: Int = dst.size - off) // fully, or throws EOFException
    fun write(position: Long, src: ByteArray, off: Int = 0, len: Int = src.size - off)
    fun flush()
}

interface BlockDevice : Closeable {
    val sectorSize: Int          // 512 for VeraCrypt file containers
    val sectorCount: Long
    val isReadOnly: Boolean
    fun readSectors(firstSector: Long, dst: ByteArray, off: Int, count: Int)
    fun writeSectors(firstSector: Long, src: ByteArray, off: Int, count: Int)
    fun flush()
}

// :core:fs-api
interface FileSystem : Closeable {
    val label: String?
    val isReadOnly: Boolean
    fun root(): FsNode
    fun resolve(path: FsPath): FsNode                 // throws FsNotFoundException
    fun list(dir: FsNode): List<FsNode>
    fun createFile(dir: FsNode, name: String): FsNode
    fun createDirectory(dir: FsNode, name: String): FsNode
    fun rename(node: FsNode, newName: String): FsNode
    fun move(node: FsNode, newParent: FsNode): FsNode
    fun delete(node: FsNode)                            // directories must be empty
    fun open(node: FsNode, mode: OpenMode): FsFile
    fun spaceInfo(): SpaceInfo
    fun sync()
}

data class FsNode(val path: FsPath, val name: String, val isDirectory: Boolean,
                  val size: Long, val modified: Instant?, val created: Instant?)

interface FsFile : Closeable {
    val size: Long
    fun read(position: Long, dst: ByteArray, off: Int, len: Int): Int   // -1 at EOF
    fun write(position: Long, src: ByteArray, off: Int, len: Int)
    fun truncate(newSize: Long)
    fun flush()
}
```

**Threading model:** filesystem drivers are **not** thread-safe. Each unlocked vault owns a
`VaultSession` that serialises all `FileSystem` calls through a single-thread coroutine dispatcher
(`newSingleThreadContext` or `limitedParallelism(1)`). The SAF provider and the UI both go through
that session. This mirrors EDS NG's `CoroutineContextBlockingFileSystemWrapper`.

## 5. Functional requirements

Priority: **P0** = MVP blocker, **P1** = MVP, should have, **P2** = later.

### 5.1 Container management
| ID | Pri | Requirement |
|---|---|---|
| FR-C1 | P0 | The user adds an existing container through `ACTION_OPEN_DOCUMENT` (any MIME type). The app takes a persistable URI permission (read and write; fall back to read-only if write is refused). |
| FR-C2 | P0 | Container list shows display name, size, location (provider authority) and state (locked/unlocked). It is stored in app-private storage (Room or DataStore). Only the URI, name, user label and options are stored, **never passwords or keys**. |
| FR-C3 | P0 | Remove a container from the list. This never deletes the file. Release the persisted URI permission. |
| FR-C4 | P1 | Rename the label shown in the list. Per-container defaults: read-only, PRF hint, PIM-required flag. |
| FR-C5 | P1 | Detect that the URI became inaccessible (file moved or permission revoked) and show a re-link action. |
| FR-C6 | P0 | Reject URIs whose provider does not support seeking. Check this by opening a `ParcelFileDescriptor` and testing `FileChannel.position()`, then show a clear error. |

### 5.2 Unlock
| ID | Pri | Requirement |
|---|---|---|
| FR-U1 | P0 | Unlock dialog fields: password (masked, show/hide toggle), PIM (optional, numeric), keyfiles (0..n, picked through SAF), **read-only** toggle, PRF selector ("Auto-detect" by default). |
| FR-U2 | P0 | Password handling: `CharArray` (not `String`), encoded to UTF-8 into a `ByteArray`. Both are wiped after key derivation. Max length 128 bytes. Reject longer input with a message. |
| FR-U3 | P0 | Open algorithm (see §6.4): try the **normal header (offset 0)**, then the **hidden header (offset 65536)**, with every supported PRF unless the user chose one. The first header that passes validation wins. |
| FR-U4 | P0 | Run key derivation on `Dispatchers.Default` with a progress indicator and a **Cancel** button. Cancelling stops further PRF attempts. |
| FR-U5 | P0 | A wrong password, an unsupported cipher or an unsupported PRF all produce the **same** message: "Incorrect password, PIM, keyfiles or unsupported settings". There is also a "Details" link that lists what was tried, but never which step failed. This protects hidden volumes. |
| FR-U6 | P1 | If the header decrypts but the cipher is a cascade or non-AES (detectable only for supported PRFs, via a valid magic under a different cipher; see §6.4), the details say "Cipher X is not supported in this version". |
| FR-U7 | P0 | If the primary header fails, try the backup header (`size - 131072`, and hidden backup at `size - 65536`) and show a warning: "Primary header damaged, opened with backup header". |
| FR-U8 | P1 | Auto-detect the filesystem in the decrypted volume: FAT12/16/32 or exFAT. Otherwise show "Unsupported filesystem (NTFS/ext4/unformatted)". |
| FR-U9 | P1 | Remember the PRF that worked for each container (non-secret hint) to speed up the next unlock. The user can turn this off. |
| FR-U10 | P2 | Biometric-protected saved password (Android Keystore AES key, `setUserAuthenticationRequired(true)`). |

### 5.3 File manager
| ID | Pri | Requirement |
|---|---|---|
| FR-F1 | P0 | Browse directories: breadcrumb path, list view with icon, name, size and modified date. Sort by name (natural order), size or date, folders first. |
| FR-F2 | P0 | Create folder, rename, delete (with a confirmation that names the count), multi-select. |
| FR-F3 | P0 | **Import**: pick one or more files (`ACTION_OPEN_DOCUMENT`, multiple) or a folder (`ACTION_OPEN_DOCUMENT_TREE`) and copy it into the current directory. Ask on name conflicts: skip, replace, keep both. |
| FR-F4 | P0 | **Export**: copy selected items to a user-picked folder (`ACTION_OPEN_DOCUMENT_TREE`). Show a warning that exported files are no longer encrypted. |
| FR-F5 | P0 | Long copies run in the foreground service with a progress notification and a Cancel action. On cancel, the partial target file is deleted. |
| FR-F6 | P0 | **Open with an external app**: `ACTION_VIEW` with a `content://` URI from the app's own `VaultDocumentsProvider`, plus `FLAG_GRANT_READ_URI_PERMISSION`. **No plaintext temp files.** |
| FR-F7 | P1 | Built-in viewers: images (`ImageDecoder` reading from `FsFile`, with zoom and pan, swipe to the next image) and plain text (UTF-8 and Latin-1, read-only, up to 5 MB). |
| FR-F8 | P1 | Properties dialog: size, dates, path, SHA-256 checksum computed on demand. |
| FR-F9 | P1 | Search within the current directory by name (substring, case-insensitive). P2: recursive search. |
| FR-F10 | P2 | Grid/gallery view, thumbnails (cached in memory only, never on disk). |
| FR-F11 | P0 | Free and used space of the volume shown in the toolbar or overflow menu. |

### 5.4 SAF DocumentsProvider
| ID | Pri | Requirement |
|---|---|---|
| FR-S1 | P0 | `VaultDocumentsProvider` (exported, `android.permission.MANAGE_DOCUMENTS`) publishes **one root per unlocked container**. Roots disappear on lock: call `notifyChange` on the roots URI. |
| FR-S2 | P0 | Document ID format: `<containerId>:<absolute path>` (for example `3f9a…:/Photos/a.jpg`). Validate it on every call. An unknown or locked container causes a `FileNotFoundException`. |
| FR-S3 | P0 | Implement `queryRoots`, `queryDocument`, `queryChildDocuments`, `openDocument` (r, w, rw, wt), `createDocument`, `deleteDocument`, `renameDocument`, `moveDocument` (within the same root), `isChildDocument`, `getDocumentType` (MIME type from the file extension through `MimeTypeMap`). |
| FR-S4 | P0 | `openDocument` returns `StorageManager.openProxyFileDescriptor(mode, ProxyFileDescriptorCallback, handler)`. The callback calls `FsFile` through the session dispatcher, so it supports random access with no temp copies. The handler runs on a dedicated `HandlerThread` per open file, or on a shared pool. |
| FR-S5 | P0 | Root flags: `FLAG_SUPPORTS_CREATE`, `FLAG_SUPPORTS_IS_CHILD`, plus `FLAG_LOCAL_ONLY`. No `FLAG_SUPPORTS_RECENTS` or `FLAG_SUPPORTS_SEARCH` in the MVP. **Read-only sessions** report no create flags, and documents in them have no write, delete or rename flags. |
| FR-S6 | P1 | When a vault locks while a proxy FD is open, later reads and writes return `EIO` (throw `ErrnoException(EIO)`), and the FD is released cleanly. |
| FR-S7 | P0 | Setting "Show unlocked vaults in the system file picker" (default **on**). When off, the provider returns no roots. |

### 5.5 Session, locking and service
| ID | Pri | Requirement |
|---|---|---|
| FR-L1 | P0 | While at least one vault is unlocked, a foreground service (`VaultSessionService`) shows an ongoing notification: "N vault(s) unlocked" with a **Lock all** action. |
| FR-L2 | P0 | Auto-lock after an **inactivity timeout** (default 5 min; options 1, 5, 15, 60 min, or never). Activity means any UI interaction or provider I/O. |
| FR-L3 | P0 | Lock on **screen off** (setting, default on). Lock when the app is **removed from recents** (`onTaskRemoved`). |
| FR-L4 | P0 | Locking order: block new operations, cancel or finish running copies (the user is asked if a copy is in progress, except for timeout or screen-off locks, which force a cancel), `fs.sync()`, `volume.flush()`, close the storage, **wipe all key material**, `notifyChange` the provider roots, update the UI. |
| FR-L5 | P0 | If the process dies, nothing persistent remains unlocked. There is no automatic re-unlock. |
| FR-L6 | P1 | "Lock all" quick settings tile. |

### 5.6 Settings
| ID | Pri | Setting | Default |
|---|---|---|---|
| FR-ST1 | P0 | Auto-lock timeout | 5 min |
| FR-ST2 | P0 | Lock on screen off | On |
| FR-ST3 | P0 | Block screenshots and recents preview (`FLAG_SECURE`) | On |
| FR-ST4 | P0 | Show vaults in the system file picker | On |
| FR-ST5 | P1 | Remember the working PRF for each container | On |
| FR-ST6 | P1 | Theme: system, light or dark | System |
| FR-ST7 | P0 | About screen: version, GPL license text, third-party licenses | — |

## 6. VeraCrypt format specification (implementation notes)

> Implement from the official VeraCrypt documentation ("VeraCrypt Volume Format Specification",
> "Header Key Derivation", "Keyfiles", "Personal Iterations Multiplier"). Items marked **⚠ VERIFY**
> must be confirmed against the docs **and** against fixture containers before you rely on them.

### 6.1 Volume layout (file container, non-system)
| Offset | Size | Content |
|---|---|---|
| 0 | 512 | Standard volume header |
| 512 | 65 024 | Reserved / random |
| 65 536 | 512 | Hidden volume header (random data if there's no hidden volume) |
| 66 048 | 65 024 | Reserved |
| 131 072 | … | **Data area** (normal volume) |
| size − 131 072 | 512 | Backup header (standard) |
| size − 65 536 | 512 | Backup header (hidden) |

### 6.2 Header structure (512 bytes; all integers **big-endian**)
| Offset | Size | Encrypted | Field |
|---|---|---|---|
| 0 | 64 | no | Salt |
| 64 | 4 | yes | Magic ASCII `"VERA"` (TrueCrypt used `"TRUE"`, which is out of scope) |
| 68 | 2 | yes | Header format version (expect 5) |
| 70 | 2 | yes | Minimum program version needed |
| 72 | 4 | yes | CRC-32 of decrypted bytes **256–511** (master keys) |
| 76 | 16 | yes | Reserved |
| 92 | 8 | yes | Size of hidden volume (0 for a normal volume) |
| 100 | 8 | yes | Volume size (data area) |
| 108 | 8 | yes | Byte offset of the start of the master key scope (= data area start) |
| 116 | 8 | yes | Size of the encrypted area |
| 124 | 4 | yes | Flags |
| 128 | 4 | yes | Sector size (512 for file containers) |
| 132 | 120 | yes | Reserved |
| 252 | 4 | yes | CRC-32 of decrypted bytes **64–251** |
| 256 | 256 | yes | Master key material (primary keys then secondary keys; only the first 64 bytes are used for single AES) |

**Validation (all must pass):** magic == `VERA`; CRC at 252 matches; CRC at 72 matches; version ≥ 5
(accept 5 and newer while the layout stays compatible); sector size ∈ {512, 1024, 2048, 4096}; data offset
and size lie inside the storage. Compare CRCs in constant time. A header that passes the magic check but
fails a CRC means a wrong password: keep trying other combinations.

### 6.3 Header key derivation
- `headerKey = PBKDF2(PRF, passwordBytes ⊕keyfilePool, salt[0..63], iterations, dkLen = 64 × nCiphers)`. For AES only, dkLen = 64.
- PRFs to try in auto-detect, in this order: **SHA-512** (VeraCrypt default), SHA-256, BLAKE2s-256, Whirlpool, Streebog.
  SHA-512 and SHA-256 use `SecretKeyFactory("PBKDF2WithHmacSHA512/256")`. That is faster on Android, but it takes a `char[]`
  and **mishandles non-ASCII and binary input**, so use your own PBKDF2-HMAC over `Mac` with byte-array keys for every PRF
  (`Mac` is hardware-backed where available). Whirlpool, Streebog and BLAKE2s-HMAC come from BouncyCastle (`bcprov-jdk18on`).
- **Iterations (non-system volumes):** if PIM == 0 or blank, use **500 000** for SHA-512, SHA-256, Whirlpool, Streebog and BLAKE2s-256 (**⚠ VERIFY** the BLAKE2s value). If PIM > 0, use `15 000 + PIM × 1 000`.
- Optimisation: derive once per PRF (64 bytes for AES) and use the result to test **both** the normal and hidden header *of that same salt*. Note that the hidden header has its **own salt**, so it needs its own derivation. Run PRFs in parallel on `Dispatchers.Default` (up to the number of CPU cores) and cancel the rest on success.
- Argon2id volumes (newer VeraCrypt) are **out of MVP scope** (**⚠ VERIFY** how they are flagged, so we can report them precisely).

### 6.4 Header decryption and cipher detection
- The encrypted region is header bytes **64–511** (448 bytes = 28 AES blocks), decrypted with **XTS, data-unit number 0**, using `primary = headerKey[0..31]` and `secondary (tweak) key = headerKey[32..63]` for AES-256.
- MVP supports **AES-256 only**. For a better FR-U6 message, the decrypt step can optionally also try Serpent and Twofish (BouncyCastle) for single ciphers and stop at the magic check. If one of those passes, report "unsupported cipher" rather than "wrong password". Cascades: P2.
- Cascade key layout (**⚠ VERIFY**): primary keys of every cipher are concatenated first, then the secondary keys.

### 6.5 Data-area encryption (AES-256-XTS, IEEE 1619)
- Data unit = **512 bytes**, regardless of the header's sector size field.
- **Data unit number = (byte offset from the start of the container file) / 512**. So the first data-area unit of a normal volume is **256** (131 072 / 512). **⚠ VERIFY** with fixtures; this is the most likely place for an off-by-offset bug.
- Tweak: `T = AES_enc(K2, LE128(unitNumber))`. For each 16-byte block j: `C = AES_enc(K1, P ⊕ T) ⊕ T`, then `T = T ⊗ α` in GF(2¹²⁸) (shift left by 1 with conditional XOR 0x87, little-endian byte order).
- No ciphertext stealing is needed because 512 is a multiple of 16.
- Implement over `Cipher.getInstance("AES/ECB/NoPadding")` with **one long-lived instance per key per thread**. Process whole runs of sectors per call (batch ≥ 64 KiB) for throughput.
- `VeraCryptVolume.readSectors(n)` maps volume sector `n` to storage offset `dataOffset + n × 512` and to unit number `(dataOffset + n × 512) / 512`.
- The **hidden volume** data offset comes from its header (field 108). Do **not** hard-code it.

### 6.6 Keyfiles (**⚠ VERIFY** the pool size: 64 bytes in TrueCrypt-legacy, 128 in current VeraCrypt)
- Pool `P` of `poolSize` zero bytes. For each keyfile, in the order the user picked them: read up to the first **1 MiB**,
  keep a running CRC-32 over the bytes, and after **each byte** add the 4 bytes of the current CRC value (big-endian) to `P[i++ mod poolSize]`
  (mod 256). Then combine: `password' = (password padded with zeros to poolSize) +_byte P` (byte-wise mod 256).
- Keyfiles are read through SAF URIs. **Keyfile order matters**, so preserve it in the UI.
- A folder as a keyfile source (all files inside) is P2.

### 6.7 Write safety
- Never write header sectors in the MVP: header writes only happen for password change or volume creation (P2).
- Writes to the data area must be sector-aligned. The FAT driver writes through a **write-back sector cache** (§7.3) with `flush()` on sync or lock.
- Before the first write in a session, open the storage in `"rw"` mode. If the provider refuses, fall back to read-only and tell the user.

## 7. Filesystem drivers

### 7.1 FAT12/16/32 (`:core:fs-fat`), P0 read/write
> Build vs reuse: the libaums FAT32 spike (§15.3) decides whether FAT32 comes from vendored
> Apache-2.0 code. The requirements below apply either way.
- Parse the BPB and detect the FAT type from the cluster count (Microsoft FAT spec rules, not the label string).
- Directories: 8.3 entries, **VFAT long file names** (UTF-16, checksum validated), `.` and `..`, deleted-entry reuse.
- Allocation: cluster chains, a free-cluster search that starts at the FSInfo hint (FAT32), FSInfo updates on sync, and mirroring to all FAT copies.
- Timestamps: created, modified, accessed (date only) in **local time** as FAT expects. Convert with the device timezone.
- Name rules: reject invalid chars `" * / : < > ? \ |` and control characters. Case-insensitive uniqueness. Generate 8.3 short names with `~N` tails.
- Clear the volume dirty bit on clean unmount if it is supported. Set the FAT32 "clean shutdown" bit appropriately.
- `fsck`-lite checker for the CLI and tests: cross-linked clusters, lost chains, size vs chain length.

### 7.2 exFAT (`:core:fs-exfat`), P1 read-only
- Boot sector, allocation bitmap, up-case table, directory entry sets (File + Stream + FileName entries, set checksum), the `NoFatChain` flag.
- Write support is P2.

### 7.3 Sector cache (`:core:io`)
- LRU of 4 KiB blocks (8 sectors), default 4 MiB per session, with dirty tracking. Flush on `sync()`, on lock, and after each completed import file.
- Cache memory holds **plaintext**. Clear it (`fill(0)`) on lock.

## 8. Non-functional requirements

### 8.1 Security and privacy
| ID | Requirement |
|---|---|
| NFR-S1 | Manifest has **no `INTERNET` permission**. CI checks that the merged manifest contains no `INTERNET` or `ACCESS_NETWORK_STATE`. |
| NFR-S2 | `android:allowBackup="false"`, `dataExtractionRules` excludes everything, `usesCleartextTraffic="false"`. |
| NFR-S3 | Only these components are exported: the launcher activity and `VaultDocumentsProvider` (protected by `MANAGE_DOCUMENTS`). Every other activity, service and receiver has `exported=false`. |
| NFR-S4 | Key material (header key, master keys, password bytes, keyfile pool) lives in `ByteArray`s that are `fill(0)` on lock or failure. `SecretKeySpec` copies are avoided where possible, or reflectively cleared on a best-effort basis (document this JVM limitation). |
| NFR-S5 | No secrets, file names or paths in logs. Release builds strip `Log.d/v/i` with R8 rules, and an `if (BuildConfig.DEBUG)` guard covers path logging. |
| NFR-S6 | `FLAG_SECURE` on all windows by default. |
| NFR-S7 | No plaintext ever written to disk by the app: no temp files, thumbnail cache only in memory, viewer streams only. Exports are explicit user actions. |
| NFR-S8 | Crash reports: none (no network). Local crash log only on opt-in, with paths redacted. |
| NFR-S9 | Constant-time comparison for CRCs and magic. Identical error paths for "wrong password" and "unsupported" (FR-U5). |
| NFR-S10 | Dependencies are limited to AndroidX, Kotlin and Compose, BouncyCastle, and test libraries, plus vendored code approved in §15. Any new dependency needs a written justification (license per §15.1, size, network behaviour) and must pass the CI license check. |

### 8.2 Performance (reference device: mid-range ARMv8 with AES instructions, Android 12+)
| ID | Metric | Target |
|---|---|---|
| NFR-P1 | Unlock time with a known PRF (SHA-512, PIM default) | ≤ 3 s |
| NFR-P2 | Unlock time with auto-detect, all PRFs, normal + hidden | ≤ 12 s, with progress shown |
| NFR-P3 | Sequential read through `FsFile` (AES-XTS + FAT32), 100 MB file | ≥ 40 MB/s (stretch 80) |
| NFR-P4 | Sequential write (import) | ≥ 25 MB/s |
| NFR-P5 | List a directory with 5 000 entries | ≤ 1.5 s, UI stays responsive (paging or lazy list) |
| NFR-P6 | APK size (single universal APK, R8 on) | ≤ 8 MB |
| NFR-P7 | Memory (idle, one vault unlocked) | ≤ 120 MB PSS |

If NFR-P3 fails with pure Kotlin, the fallback (Phase 2) is a small JNI XTS routine using ARMv8 AES intrinsics, behind the same interface.

### 8.3 Reliability
- NFR-R1: A forced kill during a write must never corrupt **the header**, since the MVP never writes it. FAT corruption is limited to the in-flight file: write the data clusters first, then the FAT entries, then the directory entry, and sync at file end.
- NFR-R2: Unit, integration and fixture tests pass on CI for every PR (§10).
- NFR-R3: Containers modified by OpenVault open cleanly in desktop VeraCrypt, and `fsck.fat -n` or Windows `chkdsk` reports no errors (manual release gate).

### 8.4 Compatibility and accessibility
- Android 8.0–16, phones and tablets, portrait and landscape. Desktop VeraCrypt 1.24–1.26 containers.
- All controls have content descriptions. Supports font scaling to 200%. Touch targets ≥ 48 dp.
- Localisation-ready (all strings in `strings.xml`). English only for the MVP.

## 9. UI specification (Jetpack Compose, Material 3)

| Screen | Contents | Key actions |
|---|---|---|
| **Vaults** (start) | List of containers: name, size, lock icon. Empty state explains "Add an existing VeraCrypt container". | FAB **Add container**. Tap → Unlock or open browser. Long-press → Rename / Remove / Properties. Top bar: Lock all, Settings. |
| **Unlock** (bottom sheet) | Password, PIM (collapsed under "Advanced"), Keyfiles list (add, remove, reorder), Read-only switch, PRF dropdown. | Unlock (shows progress and Cancel). Errors per FR-U5. |
| **Browser** | Breadcrumbs, sortable list, multi-select toolbar, free-space chip. | Import (files or folder), New folder, Export, Rename, Delete, Open with…, Properties, Lock this vault. |
| **Image viewer** | Full-screen image, swipe between images, pinch zoom. | Share (through a provider URI), Delete, Export. |
| **Text viewer** | Monospace option, encoding picker. | — |
| **Transfers** | Notification is primary. An in-app sheet lists running and failed copies. | Cancel, Retry failed. |
| **Settings** | §5.6 | — |
| **About** | Version, licenses, link to source repo. | — |

Navigation: single-activity, Navigation-Compose. ViewModels expose `StateFlow<UiState>`.
**Lock events** (from timeout, screen off or the notification) navigate any browser or viewer screen back to **Vaults** and
clear in-memory state such as thumbnails and loaded bitmaps.

## 10. Testing and quality

### 10.1 Test fixtures (create on a desktop with VeraCrypt 1.26.x; commit to `:testing:fixtures`)
Keep each one small (**2–5 MB**, the minimum VeraCrypt allows for that filesystem) and record its settings in `fixtures.json`.

| Fixture | Settings | Expected |
|---|---|---|
| `aes_sha512_fat.hc` | AES, SHA-512, FAT, password `test` | opens, known tree |
| `aes_sha256_fat.hc` | AES, SHA-256 | opens via auto-detect |
| `aes_whirlpool_fat.hc` | AES, Whirlpool | opens |
| `aes_streebog_fat.hc`, `aes_blake2s_fat.hc` | — | opens |
| `aes_sha512_pim10.hc` | PIM 10 | opens only with PIM 10 |
| `aes_sha512_keyfile.hc` | password + 2 keyfiles (committed) | opens only with both keyfiles in the right order |
| `aes_keyfile_only.hc` | empty password, 1 keyfile | opens |
| `hidden.hc` | outer `outer`, hidden `inner`, both FAT | each password opens its own volume |
| `aes_exfat.hc` | exFAT | read-only browse |
| `serpent_sha512.hc`, `aes_twofish.hc` | unsupported ciphers | "unsupported" details (FR-U6) |
| `ntfs.hc` | NTFS | "unsupported filesystem" |
| `damaged_primary.hc` | primary header zeroed | opens via backup, with a warning |
| `unicode_pw.hc` | password `pässwörd✓` | opens (UTF-8 handling) |

Each fixture's expected file tree, with SHA-256 per file, goes in `fixtures.json`.

### 10.2 Test levels
- **Crypto unit tests:** IEEE 1619 XTS-AES-256 vectors, PBKDF2 vectors (RFC 6070 style for SHA-1/256/512 and published Whirlpool/Streebog vectors), CRC-32 vectors, keyfile pool against VeraCrypt-created fixtures.
- **Header tests:** parsing, validation, every rejection path, a fuzz test of 10 000 random headers (no crash, always rejected).
- **FAT tests:** create images with `mkfs.fat` (FAT12/16/32) in CI, plus property-based tests that apply random operation sequences against an in-memory model. Then run `fsck.fat -n` on the result in CI on Linux.
- **Integration (JVM):** fixture → `VaultOpener` → walk the tree → compare hashes. Write round-trip, then reopen and re-verify.
- **Android instrumented tests:** the provider contract (`DocumentsContract` calls through `ContentResolver`), proxy FD random reads, lock while an FD is open (FR-S6), auto-lock timer.
- **Manual release checklist:** NFR-R3, opening files through Google Files, Gallery and a PDF reader, rotation, process death, low storage.

### 10.3 CI
- GitHub Actions or GitLab CI: `./gradlew check` (ktlint/detekt, unit tests), `:app:assembleRelease`, instrumented tests on an emulator (API 26, 30, 35), a manifest check (NFR-S1/S3) and a dependency license report.

## 11. Milestones

| # | Milestone | Deliverables | Exit criteria |
|---|---|---|---|
| M0 | Project setup | Gradle multi-module skeleton, CI, lint, empty app that launches | CI green |
| M1 | Crypto core | XTS, PBKDF2 for all 5 PRFs, keyfiles, CRC | All vectors pass |
| M2 | VeraCrypt volume | Header open (normal, hidden, backup), `VeraCryptVolume` read/write, CLI `info` | All fixtures in §10.1 behave as expected at the header level |
| M3 | FAT read + CLI | libaums spike decision (§15.3), FAT driver read path, `VaultOpener`, CLI `ls/cat/get` | Spike decision recorded; fixture trees and hashes match |
| M4 | FAT write | create, write, delete, rename, move, sync, cache; CLI `put/fsck` | Property tests and `fsck.fat` clean; desktop VeraCrypt opens modified fixtures |
| M5 | Android shell | Vaults list, Unlock, Browser (read), session service, auto-lock | Manual: UC1, UC4 |
| M6 | SAF provider | `VaultDocumentsProvider` with proxy FDs | UC3 in Google Files and Photos; provider tests pass |
| M7 | Write UX | Import, export, transfers, viewers, settings | UC2; NFR-P targets measured |
| M8 | exFAT read + hardening | exFAT read-only, security review against §8.1, performance tuning | Release checklist complete → **v1.0** |

## 12. Roadmap after MVP
- **Phase 2:** create VeraCrypt containers (AES, FAT/exFAT format), change password, Serpent/Twofish/Camellia plus cascades, Argon2id, exFAT write, biometric unlock, grid/thumbnails, native XTS if needed.
- **Phase 3:** gocryptfs (Kotlin; the format is public and MIT-licensed upstream), LUKS (cryptsetup via NDK, GPL), NTFS (ntfs-3g, GPL) and ext4 via NDK, USB OTG raw access.
- **Phase 4:** network storage backends (SFTP, WebDAV, SMB) behind `RandomAccessStorage`, which adds an `INTERNET` permission behind a build flavour. Then calculator disguise, panic wipe, widgets.

## 13. Risks
| Risk | Impact | Mitigation |
|---|---|---|
| Format detail wrong (unit number, keyfile pool, PRF iterations) | Can't open real containers | ⚠ VERIFY items, fixtures from real VeraCrypt early (M2 before any UI) |
| Kotlin XTS too slow | Poor UX on large files | Batch processing, reuse `Cipher`, measure in M2; JNI fallback |
| FAT write bug corrupts user data | Severe | Read-only default for the first launches (P1 option), property tests, fsck in CI, documented beta warning |
| SAF provider with non-seekable sources (cloud providers) | Can't open the container | FR-C6 check with a clear message |
| `ProxyFileDescriptorCallback` quirks across OEMs | External-app opening fails | Instrumented tests on several API levels; fallback "Export to open" |
| Android 14+ foreground service type limits (`dataSync` time limits on 15+) | Service killed during long sessions | Use type `specialUse` for the session service with a documented justification; `dataSync` only for transfers |
| Vendored libaums FAT32 has latent bugs or goes unmaintained | Data corruption; we carry the maintenance | Spike acceptance criteria (§15.3), same property/fsck tests as our own code, isolation behind `FileSystem` so it can be replaced |
| A deferred component turns out GPL-2.0-only | Can't add LUKS/NTFS without relicensing | License gate (§15.1) before Phase 3 work starts |
| JVM cannot guarantee key wiping | Keys may linger in heap | Best effort; documented threat model; keep the key lifetime short |

## 14. Development environment (other machine)
- Android Studio (latest stable), JDK 17+ (bundled JBR is fine), Android SDK Platform for the targetSdk, Build-Tools, an emulator image (API 26 and latest).
- Desktop **VeraCrypt 1.26.x** to create fixtures. Linux or WSL with `dosfstools` (`mkfs.fat`, `fsck.fat`) and `exfatprogs` for filesystem tests.
- Suggested repo layout:
  ```
  openvault/
    settings.gradle.kts, build.gradle.kts, gradle/libs.versions.toml
    core/{io,crypto,veracrypt,fs-api,fs-fat,fs-exfat,vault}/
    tools/cli/
    testing/fixtures/
    app/
    docs/   ← copy 01-eds-ng-reference-analysis.md and this PRD here
  ```
- Dependencies (versions pinned in `libs.versions.toml`): Kotlin, kotlinx-coroutines, AndroidX Core/Activity/Lifecycle, Compose BOM + Material 3, Navigation-Compose, DataStore (or Room), `org.bouncycastle:bcprov-jdk18on`; tests: JUnit 5, kotest-property (or jqwik), Turbine, AndroidX Test.
- Start with **M1–M3 on the JVM via the CLI**. Only build Android UI once fixtures open and list correctly.

## 15. Reuse of upstream open-source components

### 15.1 Principles
1. **Reuse only when it cuts development effort *and* keeps licensing simple.** Each item below states both.
2. **Provenance:** take code only from the **upstream project** at a tagged release. Record the commit hash. **Never** take it from the EDS NG APK (binaries or DEX). EDS NG's own code (`com.sovworks.*`, its JNI wrappers) is proprietary and is excluded entirely.
3. **License gate:** the app is **GPL-3.0-or-later**. Any component must be compatible with that (MIT, BSD, Apache-2.0, LGPL, GPL-2.0-*or-later*, GPL-3.0). **GPL-2.0-only** and the **TrueCrypt License 3.0** are not compatible and are rejected. Before integrating, check the license headers of the exact files used, not just the repo's README.
4. **Two integration styles:**
   - *Dependency*: an unmodified published artifact, pinned in `libs.versions.toml`.
   - *Vendored*: copied into `third_party/<name>/` with its original `LICENSE`/`NOTICE` and file headers unchanged, plus a `README.md` (upstream URL, tag, commit, list of local changes). Vendored code is reached only through our own interfaces (`FileSystem`, `BlockDevice`), so it can be swapped out later.
5. **Compliance artifacts:** a generated third-party license list on the About screen (FR-ST7), a `NOTICE` file for Apache-2.0 components, an SBOM (CycloneDX) produced in CI, and a CI license check that fails on unknown or incompatible licenses.
6. **Tools are not code:** programs used only in CI or for testing (desktop VeraCrypt, `mkfs.fat`, `fsck.fat`, `exfatprogs`) are never linked into or shipped with the app, so their licenses do not affect it.

### 15.2 Decisions

| Component | Upstream / license | Used for | Style | Effort saved | Licensing risk | Decision |
|---|---|---|---|---|---|---|
| **BouncyCastle** (`bcprov-jdk18on`) | bcgit/bc-java, MIT | Whirlpool, Streebog, BLAKE2s PRFs; Serpent/Twofish detection; Argon2 (Phase 2) | Dependency | High: no hand-written hash or cipher code | None | **Adopt (MVP)** |
| **libaums FAT32 driver** | magnusja/libaums, Apache-2.0 | FAT32 read/write behind `:core:fs-fat` | Vendored (module `core/fs`, FAT32 package only) behind an adapter | **High: likely 2–4 weeks of M3/M4.** FAT32 directory, LFN and cluster-chain code already exists and has been used in production by Android apps | Low: Apache-2.0 is GPL-3.0-compatible. Keep the NOTICE | **Evaluate in a time-boxed spike (≤ 3 days, start of M3)**, see §15.3 |
| **Microsoft exFAT specification** | Public spec, open since 2019 | exFAT read driver | Implement from the spec | Medium: an authoritative spec, no guesswork | None | **Adopt as the source (M8)** |
| relan/exfat | GPL-2.0-or-later (**verify** the headers) | Reading reference only | Not linked | Low | Low if only read | **Reference only**; we write our own from the spec |
| **dosfstools** (`mkfs.fat`, `fsck.fat`), **exfatprogs** | GPL-3.0 / GPL-2.0 | Creating test images and checking our writes in CI | Tool | High: independent correctness checker | None (not shipped) | **Adopt (CI)** |
| **Desktop VeraCrypt 1.26.x** | Apache-2.0 + TrueCrypt 3.0 | Creating fixtures; checking that our modified volumes still open | Tool | High: real-world compatibility proof | None (not shipped, code not copied) | **Adopt (fixtures)** |
| **Published test vectors** | IEEE 1619 (XTS), RFC 6070-style PBKDF2, hash KATs | Crypto unit tests | Test data | Medium | None | **Adopt (M1)** |
| **AndroidX, Kotlin, Compose, coroutines** | Apache-2.0 | App framework | Dependency | — | None | **Adopt** |
| **gocryptfs** | rfjakob/gocryptfs, MIT | Phase 3: format reference (Kotlin port) or a gomobile build | Port / dependency | High for Phase 3 | None | **Planned (Phase 3)** |
| FatFs (ChaN) | 1-clause BSD-style | Native FAT if the Kotlin driver is too slow | Vendored (NDK) | Medium | None | **Fallback (Phase 2+)** |
| cryptsetup / libcryptsetup | GPL-2.0-or-later / LGPL-2.1-or-later (**verify** per file) | Phase 3 LUKS | NDK dependency | High for LUKS | Low **if** the "or later" clause is confirmed; otherwise rejected | **Deferred; license-gate first** |
| NTFS-3G | GPL-2.0-or-later (**verify**) | Phase 3 NTFS | NDK | High for NTFS | Same as above | **Deferred; license-gate first** |
| libsu | Apache-2.0 | Root mount | — | — | — | **Not needed** (no root, per scope) |

### 15.3 libaums FAT32 spike (start of M3, ≤ 3 days)
Goal: decide between *vendoring libaums' FAT32 code* and *writing our own driver*.

**Adapter plan:** implement libaums' block-device driver interface over our `BlockDevice` (`VeraCryptVolume`), and map its `UsbFile`/`FileSystem` API onto our `FileSystem`/`FsFile` interfaces. Strip everything USB-specific; only the FAT32 package and its minimal support classes are vendored.

**Accept libaums only if all of these pass:**
1. All FAT32 fixtures (§10.1) list and read with correct SHA-256 values.
2. The property-based random-operation test (create, write, truncate, rename, move, delete; 10 000 steps) leaves an image that `fsck.fat -n` reports clean, and that desktop VeraCrypt or Windows can open and read correctly.
3. Long-file-name, Unicode and case-insensitive name collisions behave per §7.1.
4. FSInfo free-count and next-free hints are kept consistent, or can be fixed with a small, isolated patch.
5. Throughput at least meets NFR-P3/P4 on the JVM benchmark.
6. The code needed is reasonably isolated: roughly 3 000 lines or fewer vendored, no Android dependency in the FAT package (or one that's trivial to remove).

**If accepted:** `:core:fs-fat` = adapter + `third_party/libaums-fat32`. We still write **FAT12/16** support ourselves; it's small, since the differences are mostly FAT entry width and a fixed root directory. Upstream fixes are tracked by commit.
**If rejected:** write our own driver per §7.1, using libaums only as a *reading reference* (Apache-2.0 allows this) and keeping its tests' scenarios.

### 15.4 Explicitly rejected reuse

| Source | Reason |
|---|---|
| Anything extracted from the EDS NG APK (`.so`, `.dex`, `main.jar`, resources, strings) | Proprietary. The binaries are bound to `com.sovworks.*` JNI names, unauditable, 32-bit ARM only, and may contain their changes |
| VeraCrypt source code (`Common/`, `Volume/`, crypto implementations) | Parts are under the TrueCrypt License 3.0, which is not GPL-compatible. Implement from the format docs (§6) instead |
| Any GPL-2.0-**only** file | Incompatible with GPL-3.0-or-later |
| Cloud SDKs (MSAL/Graph, Dropbox, Box, MEGA, pCloud, Yandex, AWS) | Out of scope; they caused the size bloat in EDS NG (§6 of the analysis) |

### 15.5 Effect on plan
- **M1:** BouncyCastle plus published vectors means no hand-written hash code.
- **M3:** starts with the libaums spike. If it's accepted, M3 and M4 together shrink by about 2–4 weeks; the FAT12/16 extension and the hardening tests stay.
- **M8:** exFAT is written from Microsoft's spec, not ported from relan/exfat.
- **CI (M0):** add the license report, the SBOM, the `third_party/` header check, and `dosfstools`/`exfatprogs` in the Linux CI image.

## 16. Open questions
1. App name and package ID (placeholder `org.openvault.app`).
2. Distribution: F-Droid (fits the GPL and no-network design), Play Store, or sideload only?
3. Should **read-only** be the default unlock mode until FAT write has matured (recommended for the first beta)?
4. Minimum supported VeraCrypt version for fixtures. Should we also support legacy TrueCrypt (`TRUE` magic, RIPEMD-160)? Proposed: no.
5. Translations for v1.0 (EDS NG ships about 40 locales; the proposal is English only).
