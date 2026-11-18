#!/usr/bin/env bash
# Generates fixtures if missing (needs python3 + cryptography, mkfs.fat, mtools, exfatprogs, ntfs-3g + attr + working FUSE), then runs all tests.
set -euo pipefail
cd "$(dirname "$0")/.."
[ -f testing/fixtures/fixtures.json ] || python3 tools/make_fixtures.py
[ -f testing/fixtures/exfat_fixtures.json ] || python3 tools/make_exfat.py
[ -f testing/fixtures/ntfs_fixtures.json ] || python3 tools/make_ntfs.py
[ -f testing/fixtures/fixtures.json ] && grep -q aes_ntfs testing/fixtures/fixtures.json || python3 tools/make_fixtures.py
mvn -B -q test "$@"
