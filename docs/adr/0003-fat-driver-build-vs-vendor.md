# ADR-0003: Write our own FAT driver (do not vendor libaums)

Status: accepted (2026-11-18), revisit if the write path (M4) proves too costly.

## Context
PRD §15.3 asks for a time-boxed spike deciding between vendoring libaums' FAT32 code and writing our own.

## Decision
Write our own FAT12/16/32 driver in `:core:fs-fat`; use libaums only as a reading reference if needed.

## Reasons
- The spike was **not executed**: this sandbox is scoped to this repository, so upstream code could not be
  fetched and measured against the six acceptance criteria. Deciding on a "pass" without running it would be guesswork.
- FAT12/16 must be written anyway (libaums is FAT32-only), so a vendored FAT32 core would give two drivers with two
  designs behind one interface.
- The read path (M3) turned out small (~250 lines) and is already verified against `mkfs.fat`/`fsck.fat`/mtools images
  (contract tests + byte-for-byte content from `mcopy`), so the saving from vendoring now applies mainly to the write path.
- Licensing stays trivial: no third-party source in the tree.

## Consequences
- M4 (write path) carries the full cost; mitigated by the contract suite, model-based tests and `fsck.fat -n` oracle.
- The decision is isolated behind `FileSystem`; a vendored implementation could replace ours and must pass the same contract suites.
