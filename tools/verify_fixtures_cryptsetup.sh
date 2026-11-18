#!/usr/bin/env bash
# Independent oracle: reads every fixture with cryptsetup (needs kernel AF_ALG, e.g. a normal Linux CI runner).
# Usage: tools/verify_fixtures_cryptsetup.sh   (run from repo root)
set -euo pipefail
python3 - <<'PY'
import json, subprocess, os, sys
d = "testing/fixtures"
cat = json.load(open(f"{d}/fixtures.json"))
bad = 0
for name, f in cat.items():
    for label, pw, extra in [("normal", f["password"], [])] + ([("hidden", f["hidden"]["password"], ["--tcrypt-hidden"])] if f["hidden"] else []):
        cmd = ["cryptsetup", "tcryptDump", "--veracrypt", *extra, f"{d}/{f['file']}", "--dump-volume-key"]
        if f["pim"]: cmd += ["--veracrypt-pim", str(f["pim"])]
        for k in f["keyfiles"]: cmd += ["--key-file", f"{d}/{k}"]
        r = subprocess.run(cmd, input=pw.encode(), capture_output=True)
        ok = r.returncode == 0
        print(("OK  " if ok else "FAIL"), name, label, "" if ok else r.stderr.decode().strip())
        bad += not ok
sys.exit(1 if bad else 0)
PY
