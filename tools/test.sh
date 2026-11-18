#!/usr/bin/env bash
# Generates fixtures if missing (needs python3 + cryptography, mkfs.fat, mtools), then runs all tests.
set -euo pipefail
cd "$(dirname "$0")/.."
[ -f testing/fixtures/fixtures.json ] || python3 tools/make_fixtures.py
mvn -B -q test "$@"
