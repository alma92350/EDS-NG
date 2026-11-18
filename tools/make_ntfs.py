#!/usr/bin/env python3
"""Build NTFS test images with mkntfs + an ntfs-3g FUSE mount (needs ntfs-3g and /dev/fuse), record expected hashes.
Independent oracles for the Kotlin reader: ntfscat / ntfsls / ntfsinfo (separate implementation, tools only, never shipped).
Writes testing/fixtures/ntfs*.img and ntfs_fixtures.json."""
import hashlib, json, os, random, subprocess, sys, tempfile, time

OUT = os.path.join(os.path.dirname(__file__), "..", "testing", "fixtures")


def sh(*a, **k):
    return subprocess.run(a, check=True, capture_output=True, text=True, **k)


def build(img, size, cluster=4096, label="NTFSTEST", small=False):
    """Create+populate an NTFS image at `img` (size bytes). Returns {path: {sha256,size,kind}}."""
    with open(img, "wb") as f:
        f.truncate(size)
    sh("mkntfs", "-F", "-Q", "-L", label, "-c", str(cluster), img)
    mnt = tempfile.mkdtemp(prefix="ovntfs")
    env = dict(os.environ, LC_ALL="C.UTF-8")
    subprocess.run(["ntfs-3g", "-o", "rw,streams_interface=none,big_writes", img, mnt], check=True, env=env, capture_output=True)
    rnd = random.Random(1234)
    exp = {}

    def put(rel, data):
        p = os.path.join(mnt, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb") as f:
            f.write(data)
        exp[rel] = {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}

    try:
        put("hello.txt", b"hello ntfs\n")
        put("empty.txt", b"")
        put("Mixed Case Name.TXT", b"mixed\n")
        put("ünïcode-ß-日本.txt", "unicode name\n".encode())
        put("long-" + "n" * 200 + ".txt", b"long name\n")
        put("docs/readme.txt", b"nested file\n" * 50)
        put("a/b/c/deep.txt", b"deep\n")
        put("data.bin", bytes(rnd.getrandbits(8) for _ in range(300_000)))
        if not small:
            put("big.bin", bytes(rnd.getrandbits(8) for _ in range(3_000_000)))
            for i in range(400):  # forces a multi-block $INDEX_ALLOCATION B-tree
                put(f"many/file-{i:04d}-with-a-reasonably-long-name.txt", f"entry {i}\n".encode())
            # sparse file: 10 MiB logical size, only two small islands of data
            p = os.path.join(mnt, "sparse.bin")
            with open(p, "wb") as f:
                f.write(b"HEAD" * 10); f.seek(5 * 1024 * 1024); f.write(b"MIDDLE" * 100); f.truncate(10 * 1024 * 1024)
            data = open(p, "rb").read()
            exp["sparse.bin"] = {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}
            # fragmentation: two files grown alternately so each gets many small runs
            a = open(os.path.join(mnt, "frag-a.bin"), "wb"); b = open(os.path.join(mnt, "frag-b.bin"), "wb")
            da = bytearray(); db = bytearray()
            for i in range(700):
                ca = bytes([i % 251]) * 4096; cb = bytes([(i * 7) % 251]) * 4096
                a.write(ca); a.flush(); os.fsync(a.fileno()); b.write(cb); b.flush(); os.fsync(b.fileno()); da += ca; db += cb
            a.close(); b.close()
            exp["frag-a.bin"] = {"sha256": hashlib.sha256(bytes(da)).hexdigest(), "size": len(da)}
            exp["frag-b.bin"] = {"sha256": hashlib.sha256(bytes(db)).hexdigest(), "size": len(db)}
            # heavy fragmentation: fill with small files, delete every other one, then write a big file into the holes
            # (thousands of runs -> the data attribute no longer fits the MFT record -> $ATTRIBUTE_LIST + extension records)
            hd = os.path.join(mnt, "holes"); os.makedirs(hd)
            for i in range(1600):
                with open(os.path.join(hd, f"h{i:05d}.bin"), "wb") as f:
                    f.write(bytes([i % 256]) * 4096)
            filler = os.path.join(mnt, "filler.bin")
            with open(filler, "wb") as f:  # fill every free cluster so that only the holes below remain free
                try:
                    while True:
                        f.write(b"\0" * 65536); f.flush()
                except OSError:
                    pass
            for i in range(0, 1600, 2):
                os.remove(os.path.join(hd, f"h{i:05d}.bin"))
            for i in range(1, 1600, 2):
                exp[f"holes/h{i:05d}.bin"] = {"sha256": hashlib.sha256(bytes([i % 256]) * 4096).hexdigest(), "size": 4096}
            frag = bytes(rnd.getrandbits(8) for _ in range(3_000_000))
            put("fragmented-big.bin", frag)
            os.remove(filler)
    finally:
        subprocess.run(["sync"])
        for _ in range(10):
            r = subprocess.run(["fusermount", "-u", mnt], capture_output=True)
            if r.returncode == 0:
                break
            time.sleep(0.5)
        os.rmdir(mnt)
    return exp


def build_compressed(img, size=8 * 1024 * 1024):
    """Image with one NTFS-compressed file (ntfs-3g 'compression' option + compressed-directory attribute) and one normal file."""
    with open(img, "wb") as f:
        f.truncate(size)
    sh("mkntfs", "-F", "-Q", "-L", "COMP", img)
    mnt = tempfile.mkdtemp(prefix="ovntfsc")
    subprocess.run(["ntfs-3g", "-o", "rw,compression", img, mnt], check=True, capture_output=True, env=dict(os.environ, LC_ALL="C.UTF-8"))
    try:
        open(os.path.join(mnt, "plain.txt"), "wb").write(b"plain file\n")
        os.mkdir(os.path.join(mnt, "cdir"))
        sh("setfattr", "-n", "system.ntfs_attrib_be", "-v", "0x00000800", os.path.join(mnt, "cdir"))
        open(os.path.join(mnt, "cdir", "c.txt"), "wb").write(b"compress me please " * 5000)
    finally:
        subprocess.run(["sync"])
        for _ in range(10):
            if subprocess.run(["fusermount", "-u", mnt], capture_output=True).returncode == 0:
                break
            time.sleep(0.5)
        os.rmdir(mnt)
    return {"plain.txt": {"sha256": hashlib.sha256(b"plain file\n").hexdigest(), "size": 11}}


def main():
    cat = {}
    for name, size, cluster in (("ntfs", 32 * 1024 * 1024, 4096), ("ntfs512", 24 * 1024 * 1024, 512)):
        img = os.path.join(OUT, name + ".img")
        exp = build(img, size, cluster)
        cat[name] = {"file": name + ".img", "cluster": cluster, "label": "NTFSTEST", "files": exp}
        r = subprocess.run(["ntfsfix", "-n", img], capture_output=True, text=True)
        print(name, "ntfsfix -n:", r.returncode, r.stdout.strip().splitlines()[-1] if r.stdout.strip() else r.stderr.strip()[-80:])
    img = os.path.join(OUT, "ntfs-small.img")
    cat["ntfs-small"] = {"file": "ntfs-small.img", "cluster": 4096, "label": "SMALL", "files": build(img, 8 * 1024 * 1024, 4096, "SMALL", small=True)}
    cat["ntfs-comp"] = {"file": "ntfs-comp.img", "cluster": 4096, "label": "COMP", "files": build_compressed(os.path.join(OUT, "ntfs-comp.img"))}
    json.dump(cat, open(os.path.join(OUT, "ntfs_fixtures.json"), "w"), indent=1, ensure_ascii=False)
    print("ntfs ok", {k: len(v["files"]) for k, v in cat.items()})


if __name__ == "__main__":
    main()
