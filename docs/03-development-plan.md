# OpenVault: PRD Review and TDD Development Plan

| | |
|---|---|
| **Status** | Draft v1.0, 2026-11-18 |
| **Inputs** | `01-eds-ng-reference-analysis.md`, `02-PRD-vault-app.md` (Draft v1.0) |
| **Audience** | Developers, reviewers, and the PRD owner |
| **Method** | Test-driven development (TDD), with independent oracles at every layer |

---

## 0. Summary

The PRD is strong. It has a clean layered architecture, a tight MVP, a clear clean-room and licensing
policy, and requirements that can be tested. The core idea, pure-JVM `:core:*` modules that you can
test and debug through a CLI before any Android code exists, is the right foundation for TDD.

The review found **4 blocking issues** to fix in the PRD before M2 starts:

1. **Hidden-volume data loss (B1).** The MVP writes to FAT volumes. Opened with the decoy password, the
   outer volume can silently overwrite the hidden volume. The PRD has no *hidden volume protection*.
2. **Deniability leaks through SAF document IDs and the PRF hint (B2, B3).** Path-based document IDs end
   up in other apps' and the system DocumentsUI's databases, and survive after the vault locks. A
   "remembered PRF" that changes between sessions shows that two passwords exist.
3. **"Detect and report unsupported PRF/Argon2" cannot work (B4).** VeraCrypt does not store the PRF or
   cipher in the clear. An unsupported PRF looks exactly like a wrong password. Only ciphers whose
   header decryption we implement can be "detected".

The plan below fixes these issues, refines the architecture into testable seams, and sets out a
milestone-by-milestone TDD backlog. With **1 senior developer** it takes about **21 weeks** to v1.0.
With **2 developers** (core and Android streams running in parallel after M2) it takes about **14 weeks**.

---

## 1. PRD assessment

### 1.1 Strengths (keep these)
- **The layer split** (`RandomAccessStorage → BlockDevice → FileSystem → Session → UI/SAF`) follows the
  natural trust and test boundaries. Each layer can be tested in isolation with in-memory fakes.
- **Pure JVM core plus a CLI** (G6) makes the inner loop fast: no emulator for 80% of the code.
- **The scope discipline is good.** It is AES-only, opens existing containers only, and has no network.
  These choices remove the biggest risks.
- **The ⚠ VERIFY markers** and a fixture matrix built from real desktop VeraCrypt are exactly how to
  de-risk an implementation written from a format spec.
- **Same error for wrong password and unsupported settings** (FR-U5) is correct for deniability.
- **The proxy FD in the SAF provider** (FR-S4) means no plaintext temp files. This is the right call.
- **The licensing gate** (§15) is explicit and correct: no GPL-2.0-only code and no TrueCrypt License code.

### 1.2 Findings

Severity: **B** = blocking (fix the PRD before the affected milestone), **M** = major (fix during the
milestone), **m** = minor or clarification.

| ID | Sev | Area | Finding | Recommendation (PRD change) |
|---|---|---|---|---|
| B1 | B | Security / data | **No hidden volume protection.** Writing to an outer volume (FAT allocation, imports) can overwrite the hidden volume's data, because the hidden volume lives in the outer volume's "free" space. Desktop VeraCrypt prevents this with *"Protect hidden volume against damage"*, which takes the hidden password as well. | Add **FR-U11 (P0)**: an optional "Protect hidden volume" section in the Unlock sheet (hidden password, PIM and keyfiles). When it is set, a `ProtectedRangeBlockDevice` decorator rejects every write that overlaps the hidden range, and after the first such write the whole session becomes read-only (as VeraCrypt does) with a clear message. Also: **open read-only by default** in the beta (open question 3 = yes). The FAT allocator should prefer low clusters, starting from the next-free hint. |
| B2 | B | Deniability / SAF | **Document IDs `<containerId>:<absolute path>` leak plaintext paths.** DocumentsUI and client apps persist IDs (recents, last-visited, persisted grants). After lock, paths such as `/Secret/inner.pdf` stay on disk outside the vault, and they can show that a hidden volume exists. | Change **FR-S2**: document ID = `<sessionRootId>:<opaqueHandle>`. `sessionRootId` is random for each unlock session, and handles are mapped in memory per session. Persisted grants then go stale on lock by design. Document this trade-off ("URIs are not stable across unlocks"). |
| B3 | B | Deniability | **The PRF hint (FR-U9) is a side channel.** If the outer and hidden volumes use different PRFs, a hint that changes reveals two passwords. Any "last opened as hidden" state would be worse. | Change **FR-U9/FR-ST5**: default **off**. When on, store the hint only from the first successful unlock and never update it. Never persist which header (normal, hidden or backup) matched. Add a note on this to the threat model. |
| B4 | B | Requirements consistency | §2.2 says cascades and Argon2 are *"detected and reported as unsupported"*. The header has no plaintext field for PRF or cipher, so **an unsupported PRF or KDF is indistinguishable from a wrong password**. A cipher can only be "detected" if we implement its header decryption. | Rewrite §2.2: *unsupported PRFs/KDFs (Argon2) produce the generic FR-U5 error, and "Details" lists the PRFs tried.* For ciphers: implement **header-only trial decryption for every VeraCrypt cipher and cascade** with BouncyCastle (cheap, 448 bytes). Data-area support stays AES-only in the MVP. |
| M1 | M | Performance | **NFR-P2 (≤ 12 s, auto-detect) is probably unrealistic.** Each header has its **own salt**, so auto-detect costs 5 PRFs × 2 headers = **10 PBKDF2 runs of 500 000 iterations** (20 with backups). Pure-Java Whirlpool and Streebog on Android are slow. The §6.3 "derive once for both headers" optimisation does not exist; the PRD contradicts itself there. | Remove that optimisation from §6.3. Measure **in M1 on a real device** (spike). Use BouncyCastle's lightweight `HMac` (it caches ipad/opad state through `Memoable`, so each iteration costs about 2 compressions instead of 4) or Conscrypt `Mac`, whichever is faster for each PRF. Run PRFs in parallel. Order: SHA-512 → SHA-256 → BLAKE2s → Whirlpool → Streebog. Try backup headers **only after** the primary normal and hidden headers fail for all PRFs. Restate NFR-P2 after the spike. |
| M2 | M | Reliability | **NFR-R1's write ordering (data → FAT → directory entry) conflicts with an LRU write-back cache** (§7.3). An LRU cache evicts in any order. | The cache exposes `barrier()` (flush the dirty blocks and `force()` the storage). The FAT driver calls barriers at the defined points. Metadata blocks may also be written through. Test it with a crash-injection storage fake (§3.4). |
| M3 | M | Security | Password fields: the PRD does not mention the IME. Keyboards learn and sync typed text. | Add to FR-U1: `KeyboardType.Password`, `IME_FLAG_NO_PERSONALIZED_LEARNING`, autofill off, no clipboard copy. |
| M4 | M | SAF | `FLAG_SUPPORTS_IS_CHILD` enables `ACTION_OPEN_DOCUMENT_TREE`. Any app the user picks could then hold a **persistent tree grant** to the whole vault. | Make tree access a setting (default **off**: leave out `IS_CHILD`). With B2's per-session IDs, the grants are void after lock anyway. |
| M5 | M | Requirements consistency | FR-U3 says normal then hidden header, and FR-U7 then backups. The PRD does not say whether a hidden volume found through its **backup** header warns the user too, or how the order interacts with cancellation and progress. | Specify the full search order as a table (§2, ADR-05 below) and test it as a state machine. |
| M6 | M | Testability | The PRD has **no independent oracle** for header fields or master keys apart from "desktop VeraCrypt opens it". | Use **`cryptsetup tcryptDump --veracrypt [--dump-volume-key]`** (CI only, not shipped, works without root) as the oracle for header fields and master keys. Use **mtools** (`mdir`, `mcopy`, no root) and `fsck.fat -n` as FAT oracles. |
| M7 | M | Android | Screen-off locking (FR-L3) needs a **dynamically registered** receiver (`ACTION_SCREEN_OFF` cannot be declared in the manifest). The `specialUse` foreground service type needs `FOREGROUND_SERVICE_SPECIAL_USE` on API 34+ and a Play Console declaration. | Note both in FR-L1/L3, and register the receiver inside `VaultSessionService`. |
| M8 | M | Performance | A single-thread FS dispatcher also serialises **XTS crypto** onto one core. A proxy FD (appfuse) adds per-request overhead, so throughput through SAF will be well below NFR-P3. | Keep FS metadata single-threaded, but let `VeraCryptVolume` en/decrypt large batches in parallel chunks. Measure NFR-P3 at two points: `FsFile` (JVM) and proxy FD (device), with separate targets. |
| m1 | m | Build | "CI enforces no `android.*` in core" is enforced for free if the core modules are plain `kotlin("jvm")` modules: `android.*` won't compile. | Replace that check with module-type enforcement in convention plugins. |
| m2 | m | Format | Keyfile pool size (64 vs 128) depends on password length in current VeraCrypt (64-byte legacy and 128-byte max passwords). This is unconfirmed. | Add fixtures: a 65–128-byte password plus a keyfile. Keep ⚠ VERIFY. |
| m3 | m | Format | The non-ASCII password fixture: VeraCrypt converts passwords to UTF-8, but behaviour differs by platform and version. | Create `unicode_pw.hc` on **both** Windows and Linux VeraCrypt. Accept both or document the difference. |
| m4 | m | Format | The cascade XTS layout: each cipher in a cascade runs its own XTS pass with its own key pair (to be verified). | Keep ⚠ VERIFY. The tcryptDump oracle settles it. |
| m5 | m | Data | Room vs DataStore is undecided. The container list is small. | Use **DataStore (Preferences)** holding a versioned JSON blob, or Proto. Room is unnecessary weight. |
| m6 | m | Process | No threat model document. NFR-S4 admits the JVM can't wipe everything. | Add `docs/04-threat-model.md` in M0 (assets, adversaries: thief, coercer, malicious app, forensic examiner). |
| m7 | m | Tooling | JUnit 5 in Android unit tests needs a plugin. Instrumented tests use JUnit 4. | JUnit 5 for `:core:*` and `:tools:cli`. JUnit 4 + AndroidX Test in `:app`. |
| m8 | m | SAF | Proxy-FD behaviour differs between API 26–28 (older appfuse) and later versions. | Add API 28 to the instrumented test matrix (26, 28, 30, 35). |

---

## 2. Architecture refinements (lightweight ADRs)

Each ADR is a decision to adopt now. Record the full ADRs in `docs/adr/`.

**ADR-01: module graph and enforcement.** Keep the PRD modules and add two:
`:core:testkit` (in-memory fakes and **contract test suites** shared by every module) and `:build-logic`
(convention plugins: `openvault.jvm-library`, `openvault.android-app`, detekt, Kover, license checks).
Module dependencies are the architecture test: `:core:fs-fat` cannot see `:core:veracrypt`.

```
:core:io ◄── :core:crypto ◄── :core:veracrypt ◄─┐
   ▲                                             ├── :core:vault ◄── :tools:cli
   └── :core:fs-api ◄── :core:fs-fat ◄───────────┤                 ◄── :app
                     ◄── :core:fs-exfat ◄────────┘
:core:testkit (testFixtures for all of the above)
```

**ADR-02: secret handling.** Introduce `SecretBytes : Closeable` (it owns a `ByteArray`, `close()` =
`fill(0)`, and it is use-once with `use {}`). All key material flows as `SecretBytes`, never as a
`String`. Unit tests check that the backing array is zero after `close()` on success, failure **and**
cancellation paths. The JCA `SecretKeySpec` and the Cipher's key schedule can't be wiped. The threat
model documents this, and those objects are dropped on lock.

**ADR-03: crypto design.** `BlockCipher128` interface → `JcaAesEcb` (Conscrypt, hardware AES) and
`BcEngine` (Serpent, Twofish, Camellia, Kuznyechik for header trials). `Xts(cipher1, cipher2)` processes
**batches of sectors**: it computes all tweaks, XORs, makes **one ECB call for the whole batch**, then
XORs again. PBKDF2 is our own, over a `Prf` interface with byte-array keys (no `char[]` APIs). BC
`HMac` is benchmarked against Conscrypt `Mac` for each PRF.

**ADR-04: error model.** The core layers throw typed exceptions (`FsException` hierarchy,
`VolumeException`). `VaultOpener` returns a sealed `OpenResult` (`Opened`, `OpenedWithBackupHeader`,
`Failed(tried: List<Attempt>)`). `Failed` carries what was **tried**, never which step failed (FR-U5).

**ADR-05: header search as an explicit, testable plan.** `HeaderSearchPlan` is pure data: an ordered
list of `(location, prf)` attempts:

1. Primary normal × PRFs
2. Primary hidden × PRFs
3. Backup normal × PRFs
4. Backup hidden × PRFs

When the user picks a PRF, each step uses only that PRF. Execution is a separate `HeaderSearcher`. It
runs attempts in parallel, cancels the rest on success, and reports progress. The plan, and the
executor's cancellation and progress behaviour, are unit-tested with a fake KDF. No real PBKDF2 runs in
those tests.

**ADR-06: write safety.** The decorators stack on `BlockDevice`:
`VeraCryptVolume → ProtectedRangeBlockDevice (B1) → ReadOnlyGuard → CachedBlockDevice (barrier())`.
Header sectors can't be reached through the volume's API at all: sector 0 of the volume = the first data
unit.

**ADR-07: session concurrency.** `VaultSession` is a state machine
(`Unlocking → Open → Locking → Closed`) that owns a `limitedParallelism(1)` dispatcher for FS calls and a
gate that refuses new operations once `Locking` starts. The lock sequence follows FR-L4 exactly and is
tested with virtual time (`kotlinx-coroutines-test`).

**ADR-08: humble Android adapters.** Every Android component is a thin shell over a pure-Kotlin class
that is tested on the JVM:

| Android class | Pure core (JVM-tested) |
|---|---|
| `VaultDocumentsProvider` | `DocumentsCore` (ID mapping, flags, cursors as plain rows, MIME via an injected `MimeResolver`) |
| `ProxyFileDescriptorCallback` | `FdBridge` (read, write, size, release → session; EIO after lock) |
| `VaultSessionService` | `LockPolicy` (timeout, screen-off and task-removed events → lock decisions) |
| ViewModels | `UiState` reducers plus use cases that take `VaultManager` as an interface |

**ADR-09: dependency injection.** Use manual DI (`AppContainer`): no Hilt or Koin. This fits NFR-S10's
minimal dependencies and keeps test wiring explicit.

**ADR-10: persistence.** DataStore holds `ContainerRecord(id, uri, label, options)` only. The
`sessionRootId` is never persisted (B2).

---

## 3. TDD strategy

### 3.1 Principles
1. **Red → green → refactor** for all production code in `:core:*`, `:tools:cli`, and the pure cores of
   `:app`. You may write untested code only in spikes, which are thrown away.
2. **Inside-out for the core:** published vectors first, then units, then composition.
   **Outside-in for features:** each use case (UC1–UC5) starts as a failing **acceptance test**. At the
   core level that is a CLI golden test. At the app level it is an instrumented test. Units are then
   driven out underneath it.
3. **Every layer has an independent oracle.** Our own code is never the only judge of correctness
   (§3.3).
4. **Contract tests define the interfaces.** Every implementation of `RandomAccessStorage`, `BlockDevice`
   and `FileSystem` must pass the same abstract suite from `:core:testkit`. A new implementation starts
   as "inherit the contract suite, watch it fail".
5. **Security properties are tests,** not review notes: key wiping, identical error paths, no
   `INTERNET` in the merged manifest, no writes to header sectors, no plaintext files in app storage
   after a session.

### 3.2 Test pyramid per module

| Module | Unit | Contract | Property / fuzz | Golden / oracle | Benchmarks |
|---|---|---|---|---|---|
| `:core:io` | bounds, cache LRU, barrier | `RandomAccessStorageContract`, `BlockDeviceContract` | cache vs plain device equivalence (random ops) | — | cache hit path |
| `:core:crypto` | XTS tweak math, PBKDF2 loop, keyfile pool, `SecretBytes` | `PrfContract` (one HMAC KAT per PRF) | XTS: decrypt(encrypt(x)) = x; tweak/unit independence | **IEEE 1619 XTS-AES-256**, RFC 6070-style PBKDF2, BC/GOST KATs | PBKDF2 per PRF, XTS MB/s |
| `:core:veracrypt` | header parse and validate, every reject path, search plan | `BlockDeviceContract` (on a synthetic volume) | **Jazzer fuzz**: random headers are always rejected, never crash | **fixtures + `cryptsetup tcryptDump`** (fields, master key) | unlock time |
| `:core:fs-api` | `FsPath` normalisation, name validation | — | path round-trips | — | — |
| `:core:fs-fat` | BPB, FAT12/16/32 entry codecs, LFN checksum, 8.3 generation | `FileSystemContract` (full) | **model-based**: 10 000 random operations vs `InMemoryFileSystem`, then `fsck.fat -n` | `mkfs.fat` images, `mtools` read/write cross-checks | list 5 000 entries, sequential read/write |
| `:core:fs-exfat` | boot sector, bitmap, up-case, entry-set checksum | `FileSystemContract` (read subset) | fuzz the directory parser | `mkfs.exfat` + populated images | list, read |
| `:core:vault` | FS auto-detect | — | — | **every fixture: tree + SHA-256** | end-to-end read |
| `:tools:cli` | argument parsing | — | — | golden stdout for `info/ls/cat/fsck` | — |
| `:app` (JVM) | `DocumentsCore`, `FdBridge`, `LockPolicy`, reducers | `FileSystemContract`-backed fakes | lock/unlock state machine | — | — |
| `:app` (device) | — | **SAF provider contract via `ContentResolver`** | — | UC1–UC5 acceptance | androidx.benchmark: unlock, proxy FD read |

**Coverage gates (Kover):** ≥ 90% lines in `:core:crypto`, `:core:veracrypt`, `:core:fs-fat`. ≥ 80%
elsewhere in core. **Mutation testing (PIT)** runs nightly on crypto, veracrypt and fs-fat, with a
mutation score of ≥ 80% (≥ 90% for `:core:crypto`). For crypto code, mutation score matters more than
line coverage, because it catches tests that execute code but assert nothing.

### 3.3 Oracles (independent sources of truth)

| Layer | Oracle | Where it runs |
|---|---|---|
| AES-XTS | IEEE 1619-2007 vectors | unit tests |
| PBKDF2 / HMAC | RFC 6070-style vectors, BC KATs, Python `hashlib.pbkdf2_hmac` for the PRFs it supports (to generate extra vectors) | unit tests |
| VeraCrypt header | **`cryptsetup tcryptDump --veracrypt`** (+ `--veracrypt-pim`, `--tcrypt-hidden`, `--tcrypt-backup`, `--key-file`, `--dump-volume-key`) produces `expected-header.json` per fixture | fixture generation, plus a CI job that re-verifies |
| Data area | **The decrypted image** taken from a desktop VeraCrypt mount (raw `dd` of the mapped device) and stored as a SHA-256 per 64 KiB chunk | fixture generation |
| FAT | `mkfs.fat`, **`mtools`** (mdir, mcopy: no root), `fsck.fat -n` | CI (Linux) |
| exFAT | `mkfs.exfat`, `fsck.exfat`, loop mount (with sudo in CI) to populate | CI (Linux) |
| Whole system | Desktop VeraCrypt opens the modified containers (manual release gate, NFR-R3) | release checklist |

### 3.4 Test doubles (in `:core:testkit`)
- `MemoryStorage`, `MemoryBlockDevice`, `InMemoryFileSystem`, which is also the **reference model** for
  the property tests.
- `FaultyStorage`: injects `IOException` at the N-th call, short reads, refused writes, and a
  **crash point**, after which writes are silently dropped. It drives the NFR-R1 tests: after any crash
  point, `fsck` finds at most the in-flight file inconsistent.
- `CountingStorage` / `RecordingBlockDevice`: assert that header sectors are never written and that
  batching works (for example, at most N ECB calls for a 1 MiB read).
- `FakeKdf`: instant and deterministic. It lets search-plan and UI tests run without 500 000 iterations.
- `FakeClock` / `TestScope`: auto-lock timing.

### 3.5 Fixture pipeline (do this first: it is the critical risk)
- `testing/fixtures/make-fixtures.sh` (run on a desktop with VeraCrypt 1.26.x and cryptsetup) creates
  every container in PRD §10.1 plus **the new ones**: `hidden_protected_write.hc` (B1),
  `long_pw_keyfile.hc` (m2), `unicode_pw_windows.hc` / `unicode_pw_linux.hc` (m3), `cascade_*.hc` (B4),
  `fat12.hc` / `fat16.hc` / `fat32.hc`, a fragmented FAT32 image, and a directory with 5 000 entries.
- For each fixture it records `fixtures.json`: settings, password, PIM, keyfiles, the tcryptDump output,
  the expected tree with SHA-256 for each file, and the SHA-256 for each chunk of the decrypted image.
- Fixtures are committed (all 2–5 MB, about 60 MB in total; use Git LFS if that is a concern). The
  script is the specification. Regenerating fixtures never needs code changes.
- Sanity test in CI: `cryptsetup tcryptDump` re-verifies every fixture's `expected-header.json`. This
  catches fixture rot.

### 3.6 CI pipeline (GitHub Actions)

| Stage | Trigger | Jobs | Gate |
|---|---|---|---|
| **fast** | every push | `./gradlew :core:*:test :tools:cli:test detekt ktlintCheck` | < 5 min, required |
| **verify** | pull request | + Kover gates, `:app:testDebugUnitTest`, `assembleRelease`, **manifest check** (no INTERNET/ACCESS_NETWORK_STATE, exported set = launcher + provider), license report + CycloneDX SBOM, `third_party/` header check | required |
| **oracle** | pull request (Linux) | `fsck.fat`/mtools model-test runs, exFAT image tests, tcryptDump fixture re-verification | required |
| **device** | PR to main + nightly | instrumented tests on emulators API 26, 28, 30, 35 | required on main |
| **nightly** | cron | PIT mutation, Jazzer fuzz (30 min per target), long property runs (100 000 steps), benchmarks with trend tracking | alerts |

### 3.7 Definition of Done (per story)
A failing test came first (visible in the commit history or the PR description). All the contract
suites that apply pass. Coverage and mutation gates hold. No new dependency without an NFR-S10
justification. Logs contain no paths or secrets (a lint rule checks for `Log.*` with path arguments).
Docs or ADRs are updated if behaviour changed.

---

## 4. Delivery plan

### 4.1 Workstreams
- **CORE:** io, crypto, veracrypt, fs-fat, fs-exfat, vault, cli. JVM only.
- **APP:** Android shell, session, SAF, UI.
- **QA-INFRA:** fixtures, CI, oracles, benchmarks, device matrix.

With one developer these streams run one after another. With two, APP starts at M5 while CORE continues
with M4 and M8. This is possible because APP builds against `InMemoryFileSystem` and fake
`VaultManager`s from `:core:testkit`.

### 4.2 Milestones (estimates in developer-weeks)

| # | Milestone | Weeks (1 dev) | Exit criteria (all automated unless noted) |
|---|---|---|---|
| M0 | Skeleton, CI, fixtures, threat model | 1.5 | CI green on an empty app. **All fixtures generated** with `fixtures.json` and tcryptDump output. Threat model doc. PRD amended (B1–B4). |
| M1 | Crypto core + device KDF spike | 2 | IEEE 1619 and PBKDF2 vectors pass for 5 PRFs. Keyfile pool matches fixtures. **On-device PBKDF2 timings recorded**, NFR-P1/P2 restated. |
| M2 | VeraCrypt volume + CLI `info` | 2 | Every fixture behaves as expected at header level and matches tcryptDump. Decrypted-image chunk hashes match. Fuzzing never crashes. Hidden + backup paths work. |
| M3 | FAT read + `VaultOpener` + CLI `ls/cat/get` | 2.5 | libaums spike decision recorded (ADR). `FileSystemContract` read part passes for FAT12/16/32. **Every fixture tree + SHA-256 matches** (UC1 on the CLI). |
| M4 | FAT write + cache + hidden protection | 3.5 | Full `FileSystemContract`. 10 000-step model test + `fsck.fat -n` clean. Crash-injection tests pass. `ProtectedRangeBlockDevice` blocks writes into the hidden range (B1). CLI `put/fsck`. Desktop VeraCrypt opens modified fixtures (manual). |
| M5 | Android shell: vaults list, unlock, browse (read), session service, auto-lock | 3 | `LockPolicy` + session state machine tests. Instrumented: UC1 and UC4. FLAG_SECURE and IME flags checked. |
| M6 | SAF provider (opaque IDs, proxy FD) | 2 | `DocumentsCore` unit tests. Provider contract tests on API 26/28/30/35. UC3 in Google Files and Photos (manual). Lock while an FD is open → EIO (FR-S6). |
| M7 | Write UX: import, export, transfers, viewers, settings | 2.5 | UC2 instrumented. Cancelled copy leaves no partial file. NFR-P measured on the reference device. |
| M8 | exFAT read + hardening + release | 2.5 | exFAT read contract on fixtures. Security review against §8.1 + threat model. Release checklist (NFR-R3) → **v1.0**. |
| | **Total** | **≈ 21.5** | 2 developers: ≈ 14 weeks (critical path: M0 → M1 → M2 → M3 → M4 → M8; APP runs M5–M7 in parallel after M2) |

Contingency: add 15–20% for format surprises (⚠ VERIFY items) and OEM SAF quirks.

### 4.3 Milestone detail: the tests written first

**M0: Skeleton, CI, fixtures** (QA-INFRA)
1. `build-logic` convention plugins, version catalog, Kotlin JVM 17 toolchain, detekt + ktlint, Kover.
2. Empty `:app` with an instrumented smoke test (launches, FLAG_SECURE is set).
3. **First red test:** `ManifestPolicyTest` (merged manifest has no INTERNET, the exported set is
   exact). It turns green immediately and then guards every PR.
4. `make-fixtures.sh` + `fixtures.json` schema + `FixtureCatalogTest`, which loads the catalog and checks
   that every referenced file exists and matches its hash.
5. `docs/04-threat-model.md` and `docs/adr/0001…0010`.

**M1: crypto core** (CORE)
1. `SecretBytesTest`: zeroed after `close()`, and after an exception inside `use {}`.
2. `XtsAesTest`: IEEE 1619 vectors (including the 512-byte data-unit vectors). Then a tweak-per-unit
   property, and that batch == per-sector.
3. `Pbkdf2Test`: RFC 6070-style for SHA-256/512, then KATs per PRF through `PrfContract` (SHA-256,
   SHA-512, BLAKE2s-256, Whirlpool, Streebog-512).
4. `IterationPolicyTest`: PIM 0 → 500 000, PIM n → 15 000 + n × 1 000. Check BLAKE2s against the docs
   and fixtures (⚠ VERIFY).
5. `KeyfilePoolTest`: CRC-32 vectors, the pool algorithm on small synthetic inputs, the 1 MiB cap, order
   sensitivity, then **the fixture oracle** (the derived key must open `aes_sha512_keyfile.hc` in M2.
   Mark it as a pending integration test now).
6. **Spike (throwaway):** an instrumented benchmark of PBKDF2 for each PRF, BC `HMac` vs Conscrypt, on
   one or two real devices. The output is an ADR that updates NFR-P1/P2.

**M2: VeraCrypt volume** (CORE)
1. `HeaderLayoutTest`: field offsets and big-endian decoding against a hand-built header.
2. `HeaderValidatorTest`: one test **per rejection path** (magic, CRC at 252, CRC at 72, version,
   sector size, offsets outside storage), plus a constant-time comparison helper test.
3. `HeaderSearchPlanTest` (ADR-05): order, user-selected PRF, cancellation, progress, using `FakeKdf`.
4. `HeaderCipherTrialTest` (B4): Serpent, Twofish, Camellia, Kuznyechik and cascades decrypt the
   synthetic header magic. Report `UnsupportedCipher` only in the details.
5. `VeraCryptVolumeTest` runs `BlockDeviceContract` over a **synthetic** volume that our encryptor
   builds, then the **fixture oracle**: decrypted-image chunk hashes match the desktop mount, which
   proves the data-unit numbering (⚠ VERIFY item 6.5).
6. `FixtureHeaderTest` (parameterised over `fixtures.json`): every fixture → expected `OpenResult` +
   master key == tcryptDump.
7. `NoHeaderWriteTest`: `RecordingStorage` proves the volume can't write to offsets < data offset or to
   the backup areas.
8. Jazzer target `HeaderParserFuzz` and a 10 000-random-header test.
9. CLI `info`: golden output, which must not print secrets.

**M3: FAT read** (CORE)
1. **libaums spike** (≤ 3 days, timeboxed, PRD §15.3): run the `FileSystemContract` read part and the
   fixture tree test through an adapter. Accept or reject by the 6 criteria, and record an ADR. *Both
   branches start from the same contract suite. Only the implementation behind it changes.*
2. `BpbParserTest`, `FatTypeDetectionTest` (cluster count boundaries 4084/4085 and 65524/65525),
   `FatEntryCodecTest` (12-bit packing).
3. `LfnTest`: checksum, UTF-16, multi-entry names, orphaned LFN entries ignored.
4. `FileSystemContract` (read part): list, resolve (case-insensitive), read at offsets, read across
   cluster boundaries, read on a fragmented chain, EOF semantics.
5. `FsAutoDetectTest`: FAT, exFAT, NTFS and unformatted → typed result (FR-U8).
6. `FixtureTreeTest`: end to end, fixture → `VaultOpener` → walk → SHA-256 matches. **This is UC1's
   acceptance test at core level.**
7. CLI `ls/cat/get` golden tests.

**M4: FAT write** (CORE)
1. `FileSystemContract` (write part, written first, all red): create, write, extend, truncate, rename
   (including a case-only rename), move, delete, a non-empty directory delete is refused, name
   conflicts, invalid names, disk full → typed error and no leaked clusters.
2. `ShortNameGeneratorTest` (`~N` tails, collisions), `FsInfoTest` (free count / next-free kept
   consistent).
3. `CachedBlockDeviceTest`: equivalence to an uncached device under random operations, `barrier()`
   semantics, plaintext zeroed on close.
4. `CrashConsistencyTest` with `FaultyStorage`: for each crash point during an import, reopen → `fsck`
   finds only the in-flight file affected (NFR-R1, M2).
5. `FatModelTest`: 10 000 random operations vs `InMemoryFileSystem`, then export the image → `fsck.fat -n`
   and `mdir -/` must agree (CI oracle stage).
6. `ProtectedRangeTest` (B1): writes overlapping the hidden range are refused, the session becomes
   read-only, and with `hidden_protected_write.hc` the hidden volume still opens with intact hashes
   afterwards.
7. `ReadOnlySessionTest`: every mutating call throws `FsReadOnlyException`, and the storage sees no
   writes.
8. CLI `put`, `fsck`, plus a manual gate: desktop VeraCrypt opens the modified fixtures.

**M5: Android shell** (APP)
1. `LockPolicyTest` (virtual time): timeout values, activity resets the timer, screen-off, task removed,
   "never".
2. `VaultSessionStateMachineTest`: the lock sequence in FR-L4's exact order (verified with a recording
   fake), operations rejected during `Locking`, wipe called on every path.
3. `ContainerRepositoryTest`: DataStore round-trip, and no secret fields can be expressed
   (compile-time: `ContainerRecord` has no password field).
4. `UnlockViewModelTest` with a fake opener: progress, cancel, the generic error + details (FR-U5),
   backup warning (FR-U7), the password `CharArray` wiped after submit.
5. Compose UI tests: Vaults list states, Unlock sheet (PIM collapsed, keyfile reorder), Browser sort
   (natural order), breadcrumbs.
6. Instrumented acceptance: **UC1** (add the fixture through a test DocumentsProvider → unlock →
   browse → open a text file) and **UC4** (background + timeout → locked, back on the Vaults screen,
   keys wiped).
7. `FR-C6` test: a non-seekable provider (a pipe-backed test provider) is rejected with a clear error.

**M6: SAF provider** (APP)
1. `DocumentsCoreTest`: opaque per-session IDs (B2), unknown, stale or locked IDs →
   `FileNotFoundException`, flags for read-only sessions, no `IS_CHILD` unless the setting is on (M4),
   no roots when FR-S7 is off.
2. `FdBridgeTest`: random reads and writes map to `FsFile`, EIO after lock, release closes the file
   exactly once.
3. Instrumented `ProviderContractTest` via `ContentResolver` + `DocumentsContract`: query roots,
   children, open r/w/rw/wt, create, rename, delete, move, `notifyChange` on lock.
4. Instrumented `ProxyFdRandomAccessTest` (API matrix including 28) and `LockWhileOpenTest` (FR-S6).
5. Manual: UC3 in Google Files, Photos and a PDF reader. The document ID check: after lock + relaunch,
   DocumentsUI holds no plaintext paths.

**M7: write UX** (APP)
1. `TransferEngineTest` (JVM, fakes): conflict policies (skip, replace, keep both), cancel deletes the
   partial target, progress events, forced cancel on timeout or screen-off lock.
2. `ImportUseCaseTest` / `ExportUseCaseTest` with in-memory sources, including a tree import.
3. Viewer tests: the text viewer's encoding and 5 MB cap. The image viewer decodes from `FsFile` through
   a stream adapter, with no temp files (`NoPlaintextOnDiskTest` scans app storage after the test).
4. Properties: an SHA-256 check against the known fixture hash.
5. Instrumented **UC2**. Benchmarks on the reference device for NFR-P1…P5, at both measurement points
   (M8 finding).

**M8: exFAT + hardening** (CORE + APP)
1. `ExfatBootSectorTest`, `UpcaseTableTest`, `EntrySetChecksumTest`, `NoFatChainTest`.
2. `FileSystemContract` (read part) on generated exFAT images and on `aes_exfat.hc`.
3. Security sweep: a lint rule for logging paths, the R8 log-stripping check on the release APK, a
   review of `SecretBytes` usage, the threat model updated with test evidence.
4. Release checklist (PRD §10.2 manual items + NFR-R3) → tag v1.0, publish the SBOM and license report.

### 4.4 Critical path and parallelism

```
Week:   1    3    5    7    9   11   13   15   17   19   21
CORE  [M0][ M1 ][ M2 ][ M3  ][  M4   ]          [ M8  ]
APP (1 dev: after M4) ......................[ M5 ][M6][ M7 ]
APP (2nd dev)               [  M5   ][ M6 ][  M7  ]        ← against :core:testkit fakes,
                                                            switched to real VaultOpener after M3
```

The first real-container end-to-end result comes at **end of M3 (≈ week 8)**, through the CLI. That is
early enough to find format errors before any UI investment, as PRD §14 intends.

---

## 5. Risk register (additions and changes to PRD §13)

| Risk | Likelihood / impact | Mitigation in this plan |
|---|---|---|
| Hidden volume overwritten by writes to the outer volume | Medium / **severe** | B1: protection decorator, read-only default, allocator prefers low clusters, `ProtectedRangeTest` |
| Deniability leaks through SAF IDs, the PRF hint, or DocumentsUI history | High / severe (UC5) | B2, B3, M4; a manual forensic check in M6/M8 |
| Auto-detect unlock too slow on mid-range devices | High / medium | M1 device spike before committing to NFR-P2; parallel PRFs; HMAC state caching; backups tried last |
| Fixtures wrong or stale | Low / high | Generated by script, cross-checked by tcryptDump in CI |
| Model-based FAT test too weak (the model shares our bugs) | Medium / high | External oracles (fsck.fat, mtools) on every generated image, not just the model |
| Proxy FD throughput below expectations | High / medium | Separate SAF throughput target; document "Export to open" for large media |
| Scope creep from the B4 cipher trials | Low / low | Header trials only (448 bytes); data-area support stays Phase 2 |

---

## 6. Recommended answers to the PRD's open questions
1. **Name and package:** decide in M0. It blocks the store listing only, not code (use `org.openvault.app`
   until then).
2. **Distribution:** F-Droid first: it fits the GPL and no-network design, and avoids the Play
   `specialUse` foreground service review. Make builds reproducible from M0. Play Store later.
3. **Read-only default:** **yes** for every beta release. Change the default only after M4's oracle
   tests have run clean for at least 4 weeks of nightly runs.
4. **TrueCrypt (`TRUE`) and RIPEMD-160:** **no**. Upstream VeraCrypt 1.26 itself dropped TrueCrypt mode
   and RIPEMD-160.
5. **Translations:** English only. The strings are ready for localisation (already in the PRD).

---

## 7. First two weeks: ready-to-start backlog

| # | Ticket | Type | Done when |
|---|---|---|---|
| 1 | Amend PRD with B1–B4, M1–M8 (this doc §1.2) | Docs | PRD v1.1 merged |
| 2 | Gradle skeleton + `build-logic` + version catalog | Build | `./gradlew check` green |
| 3 | CI `fast` + `verify` workflows | CI | Required checks on main |
| 4 | `ManifestPolicyTest` | Test | Fails if INTERNET is added |
| 5 | `make-fixtures.sh` + generate all fixtures + `fixtures.json` | QA-INFRA | Catalog test green; tcryptDump outputs committed |
| 6 | `docs/04-threat-model.md` + ADR-01…10 | Docs | Reviewed |
| 7 | `:core:testkit`: `MemoryStorage`, `RandomAccessStorageContract`, `BlockDeviceContract` | Core | Contracts pass for the memory implementations |
| 8 | `SecretBytes` + tests | Core | Wipe tests green |
| 9 | XTS-AES with IEEE 1619 vectors | Core | Vectors green, batch == per-sector |
| 10 | PBKDF2 + `PrfContract` for 5 PRFs | Core | KATs green |
| 11 | Device KDF benchmark spike | Spike | ADR with timings; NFR-P1/P2 restated |
