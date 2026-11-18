#!/usr/bin/env python3
"""Populate an exFAT image formatted by `mkfs.exfat` (no mount needed) and validate it with `fsck.exfat`.
Writes testing/fixtures/exfat.img + exfat_fixtures.json (path -> sha256). Independent oracle: fsck.exfat."""
import hashlib, json, os, struct, subprocess, sys

OUT = os.path.join(os.path.dirname(__file__), "..", "testing", "fixtures")


def cks16(data, skip=()):
    h = 0
    for i, b in enumerate(data):
        if i in skip:
            continue
        h = (((h & 1) << 15) | (h >> 1)) + b
        h &= 0xFFFF
    return h


class Exfat:
    def __init__(self, path):
        self.f = open(path, "r+b"); b = self.f.read(512)
        assert b[3:11] == b"EXFAT   "
        self.bps = 1 << b[108]; self.spc = 1 << b[109]; self.cb = self.bps * self.spc
        self.fat_off = struct.unpack_from("<I", b, 80)[0] * self.bps
        self.heap_off = struct.unpack_from("<I", b, 88)[0] * self.bps
        self.ccount = struct.unpack_from("<I", b, 92)[0]; self.root = struct.unpack_from("<I", b, 96)[0]
        self.bitmap = None
        # find bitmap in root
        raw = self.read_clusters([self.root])
        for i in range(0, len(raw), 32):
            if raw[i] == 0x81:
                self.bitmap = struct.unpack_from("<I", raw, i + 20)[0]; self.bitmap_len = struct.unpack_from("<Q", raw, i + 24)[0]
        self.bm = bytearray(self.read_at(self.coff(self.bitmap), self.bitmap_len))
        self.next_free = 2
        self.ts = 0x5C8E0000 | (6 << 21) | (15 << 16)  # fixed timestamp

    def coff(self, c): return self.heap_off + (c - 2) * self.cb
    def read_at(self, off, n): self.f.seek(off); return self.f.read(n)
    def write_at(self, off, d): self.f.seek(off); self.f.write(d)
    def read_clusters(self, cl): return b"".join(self.read_at(self.coff(c), self.cb) for c in cl)

    def used(self, c): return self.bm[(c - 2) // 8] >> ((c - 2) % 8) & 1
    def mark(self, c): self.bm[(c - 2) // 8] |= 1 << ((c - 2) % 8)

    def alloc(self, n, contiguous):
        got = []
        c = self.next_free
        if contiguous:
            while True:
                if c + n - 1 > self.ccount + 1: raise RuntimeError("full")
                if all(not self.used(c + i) for i in range(n)): got = list(range(c, c + n)); break
                c += 1
        else:  # deliberately fragmented: take every other free cluster
            while len(got) < n:
                if c > self.ccount + 1: raise RuntimeError("full")
                if not self.used(c): got.append(c); self.mark(c); c += 2; continue
                c += 1
            for g in got: self.bm[(g - 2) // 8] &= ~(1 << ((g - 2) % 8))
        for g in got: self.mark(g)
        self.next_free = max(self.next_free, (got[-1] + 1) if contiguous else self.next_free)
        return got

    def set_fat(self, c, v): self.write_at(self.fat_off + 4 * c, struct.pack("<I", v))

    def store(self, data, contiguous):
        n = max(1, -(-len(data) // self.cb)) if data else 0
        if n == 0: return 0, []
        cl = self.alloc(n, contiguous)
        for i, c in enumerate(cl):
            self.write_at(self.coff(c), data[i * self.cb:(i + 1) * self.cb].ljust(self.cb, b"\0"))
            if not contiguous: self.set_fat(c, cl[i + 1] if i + 1 < len(cl) else 0xFFFFFFFF)
        return cl[0], cl

    def entry_set(self, name, is_dir, first, size, contiguous):
        up = name.upper()
        nh = cks16(up.encode("utf-16-le"))
        chars = name.encode("utf-16-le"); nparts = -(-len(name) // 15)
        e = bytearray(32); e[0] = 0x85; e[1] = 1 + nparts; struct.pack_into("<H", e, 4, 0x10 if is_dir else 0x20)
        struct.pack_into("<III", e, 8, self.ts, self.ts, self.ts); e[22] = e[23] = 0x80
        s = bytearray(32); s[0] = 0xC0; s[1] = 0x01 | (0x02 if contiguous and first else 0); s[3] = len(name); struct.pack_into("<H", s, 4, nh)
        struct.pack_into("<Q", s, 8, size); struct.pack_into("<I", s, 20, first); struct.pack_into("<Q", s, 24, size)
        parts = []
        for i in range(nparts):
            p = bytearray(32); p[0] = 0xC1; p[2:2 + 30] = chars[i * 30:(i + 1) * 30].ljust(30, b"\0"); parts.append(p)
        blob = bytearray(e + s + b"".join(parts))
        struct.pack_into("<H", blob, 2, cks16(bytes(blob), skip=(2, 3)))
        return bytes(blob)

    def add_dir_entry(self, dir_clusters, dir_contig, blob):
        raw = bytearray(self.read_clusters(dir_clusters))
        i = 0
        while i < len(raw) and raw[i] != 0: i += 32
        if i + len(blob) > len(raw): raise RuntimeError("directory full (test generator)")
        raw[i:i + len(blob)] = blob
        for k, c in enumerate(dir_clusters): self.write_at(self.coff(c), bytes(raw[k * self.cb:(k + 1) * self.cb]))

    def finish(self):
        self.write_at(self.coff(self.bitmap), bytes(self.bm)); self.f.close()


def build(img, size):
    """Creates and populates an exFAT image of `size` bytes at `img`; returns {path: sha256}."""
    with open(img, "wb") as f: f.truncate(size)
    subprocess.run(["mkfs.exfat", "-L", "EXTEST", "-c", "4096", img], check=True, capture_output=True)
    fs = Exfat(img)
    root_cl = [fs.root]
    files = {"hello.txt": b"hello exfat\n", "Mixed Case Name.TXT": b"mixed\n", "empty.txt": b"",
             "data.bin": hashlib.sha512(b"x").digest() * 300, "frag.bin": os.urandom(30000), "héllo.txt": b"accent\n",
             "long-" + "n" * 100 + ".txt": b"long name\n"}
    dirs = {"docs": {"readme.txt": b"nested\n" * 100, "deep.bin": os.urandom(9000)}}
    expected = {}

    def put(parent_cl, parent_contig, name, data, contiguous, prefix):
        first, cl = fs.store(data, contiguous)
        fs.add_dir_entry(parent_cl, parent_contig, fs.entry_set(name, False, first, len(data), contiguous))
        expected[prefix + name] = hashlib.sha256(data).hexdigest()

    for n, d in files.items():
        put(root_cl, False, n, d, n != "frag.bin", "")
    for dn, content in dirs.items():
        first, cl = fs.store(b"\0" * 4096, True)  # one 4096-byte cluster directory
        fs.add_dir_entry(root_cl, False, fs.entry_set(dn, True, first, 4096, True))
        for n, d in content.items():
            put(cl, True, n, d, True, dn + "/")
    fs.finish()
    r = subprocess.run(["fsck.exfat", "-n", img], capture_output=True, text=True)
    if r.returncode != 0: sys.exit("fsck.exfat reported problems: " + r.stdout + r.stderr)
    return expected


def main():
    img = os.path.join(OUT, "exfat.img")
    expected = build(img, 8 * 1024 * 1024)
    json.dump({"file": "exfat.img", "files": expected}, open(os.path.join(OUT, "exfat_fixtures.json"), "w"), indent=1, ensure_ascii=False)
    print("exfat ok", len(expected))


if __name__ == "__main__":
    main()
