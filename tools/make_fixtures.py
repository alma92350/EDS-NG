#!/usr/bin/env python3
"""Generate VeraCrypt-format test containers (AES-XTS, FAT) from the public format description.

This is an INDEPENDENT implementation (Python `cryptography` + hashlib) used only to produce
fixtures. Every container is verified in the other direction with `cryptsetup tcryptDump`.
Real desktop-VeraCrypt fixtures should replace/augment these before release (PRD 10.1).
"""
import hashlib, json, os, struct, subprocess, sys, zlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

OUT = os.path.join(os.path.dirname(__file__), "..", "testing", "fixtures")
HDR = 131072
PRFS = {"sha512": "sha512", "sha256": "sha256", "blake2s": "blake2s", "ripemd160": "ripemd160"}
TC_ITER = {"ripemd160": 2000, "sha512": 1000}  # TrueCrypt: fixed iteration counts, no PIM


def pbkdf2(prf, pw, salt, iters, n=64):
    return hashlib.pbkdf2_hmac(PRFS[prf], pw, salt, iters, n)


def xts(key, unit, data, enc=True):
    c = Cipher(algorithms.AES(key), modes.XTS(unit.to_bytes(16, "little")))
    o = c.encryptor() if enc else c.decryptor()
    return o.update(data) + o.finalize()


def keyfile_pool(pw, files, pool=64):
    if not files:
        return pw
    p = bytearray(pool)
    for data in files:
        crc, pos = 0xFFFFFFFF, 0
        for b in data[:1048576]:
            crc = zlib_table[(crc ^ b) & 0xFF] ^ (crc >> 8)
            for sh in (24, 16, 8, 0):
                p[pos] = (p[pos] + ((crc >> sh) & 0xFF)) & 0xFF
                pos = (pos + 1) % pool
    out = bytearray(pool)
    for i, b in enumerate(pw):
        out[i] = b
    return bytes((out[i] + p[i]) & 0xFF for i in range(pool))


zlib_table = []
for n in range(256):
    c = n
    for _ in range(8):
        c = (c >> 1) ^ 0xEDB88320 if c & 1 else c >> 1
    zlib_table.append(c)


def header(master, vol_size, hidden_size, data_off, enc_size, flags=0, magic=b"VERA", version=5, sector=512):
    h = bytearray(448)
    h[0:4] = magic
    struct.pack_into(">H", h, 4, version)       # header version
    struct.pack_into(">H", h, 6, 0x010b)  # min program version 1.11
    struct.pack_into(">I", h, 8, zlib.crc32(master) & 0xFFFFFFFF)
    struct.pack_into(">Q", h, 28, hidden_size)
    struct.pack_into(">Q", h, 36, vol_size)
    struct.pack_into(">Q", h, 44, data_off)
    struct.pack_into(">Q", h, 52, enc_size)
    struct.pack_into(">I", h, 60, flags)
    struct.pack_into(">I", h, 64, sector)  # TrueCrypt v4 has no sector-size field: 0
    struct.pack_into(">I", h, 188, zlib.crc32(bytes(h[0:188])) & 0xFFFFFFFF)  # CRC of bytes 64..251
    h[192:448] = master.ljust(256, b"\0")
    return bytes(h)


def enc_header(salt, pw, prf, pim, plain, tc=False):
    if tc:
        assert pim == 0
        iters = TC_ITER[prf]
    else:
        iters = 500000 if pim == 0 else 15000 + pim * 1000
    key = pbkdf2(prf, pw, salt, iters)
    return salt + xts(key, 0, plain)


def make(name, size, pw, prf="sha512", pim=0, keyfiles=(), fat="16", files=None, hidden=None, exfat=False, truecrypt=False, tc_version=5):
    """hidden = (pw, size, files) creates a hidden volume at the end of the outer data area."""
    rnd = lambda n: os.urandom(n)
    tcargs = dict(magic=b"TRUE", version=tc_version, sector=(0 if tc_version < 5 else 512)) if truecrypt else {}
    img = bytearray(rnd(size))
    data_size = size - 2 * HDR
    master = rnd(64) + rnd(192)
    mkey = master[:64]
    # --- inner plain FAT image for the outer volume
    expected_files = None
    if exfat:
        sys.path.insert(0, os.path.dirname(__file__))
        import make_exfat, tempfile
        with tempfile.TemporaryDirectory() as td:
            p = os.path.join(td, "x.img"); expected_files = make_exfat.build(p, data_size); outer_fs = open(p, "rb").read()
    else:
        outer_fs = fat_image(name + "-outer", data_size, fat, files or {})
    for u in range(data_size // 512):
        img[HDR + u * 512:HDR + (u + 1) * 512] = xts(mkey, (HDR // 512) + u, outer_fs[u * 512:(u + 1) * 512])
    hid_info = None
    pw_b = keyfile_pool(pw.encode(), [open(k, "rb").read() for k in keyfiles])
    salt = rnd(64)
    hsize = 0
    if hidden:
        hpw, hsz, hfiles = hidden
        hsize = hsz
        hdata_off = size - HDR - hsz
        hmaster = rnd(64) + rnd(192)
        hfs = fat_image(name + "-hidden", hsz, fat, hfiles)
        for u in range(hsz // 512):
            img[hdata_off + u * 512:hdata_off + (u + 1) * 512] = xts(hmaster[:64], hdata_off // 512 + u, hfs[u * 512:(u + 1) * 512])
        hh = header(hmaster, hsz, hsz, hdata_off, hsz, **tcargs)
        hsalt = rnd(64)
        hblob = enc_header(hsalt, hpw.encode(), prf, 0, hh, truecrypt)
        img[65536:65536 + 512] = hblob
        img[size - 65536:size - 65536 + 512] = hblob
        hid_info = {"password": hpw, "size": hsz, "offset": hdata_off, "files": hashes(hfiles)}
    ohdr = header(master, data_size, 0, HDR, data_size, **tcargs)
    blob = enc_header(salt, pw_b, prf, pim, ohdr, truecrypt)
    img[0:512] = blob
    img[size - HDR:size - HDR + 512] = blob
    path = os.path.join(OUT, name + ".hc")
    open(path, "wb").write(img)
    return {"file": name + ".hc", "password": pw, "prf": prf, "pim": pim, "keyfiles": [os.path.basename(k) for k in keyfiles],
            "fat": ("exfat" if exfat else fat), "mode": ("truecrypt" if truecrypt else "veracrypt"), "tc_version": tc_version if truecrypt else None, "size": size, "files": expected_files if expected_files is not None else hashes(files or {}), "hidden": hid_info,
            "master_key_hex": master[:64].hex()}


def hashes(files):
    return {k: hashlib.sha256(v).hexdigest() for k, v in files.items()}


def fat_image(label, size, fat, files):
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "fs.img")
        with open(p, "wb") as f:
            f.truncate(size)
        subprocess.run(["mkfs.fat", "-F", fat, "-s", {"12": "2", "16": "1", "32": "1"}[fat], "-n", "OPENVAULT", "-i", "01020304", p], check=True, capture_output=True)
        for path, data in files.items():
            src = os.path.join(d, "src.bin")
            open(src, "wb").write(data)
            parts = path.strip("/").split("/")
            for i in range(1, len(parts)):
                subprocess.run(["mmd", "-D", "s", "-i", p, "::/" + "/".join(parts[:i])], capture_output=True)
            subprocess.run(["mcopy", "-i", p, src, "::/" + "/".join(parts)], check=True, capture_output=True)
        return open(p, "rb").read()


def sample_files(tag):
    return {"hello.txt": f"hello {tag}\n".encode(), "docs/readme.txt": b"nested file\n" * 50,
            "data.bin": hashlib.sha512(tag.encode()).digest() * 400}


def plain_images():
    """Unencrypted FAT images with a rich tree (LFN, unicode, big dir, fragmentation) for the FAT driver tests."""
    env = dict(os.environ, LC_ALL="C.UTF-8", MTOOLS_SKIP_CHECK="1")
    cat = {}
    for name, fat, size, spc in (("plain_fat12", "12", 3 * 512 * 1024, "1"), ("plain_fat16", "16", 16 * 1024 * 1024, "1"), ("plain_fat32", "32", 40 * 1024 * 1024, "1")):
        path = os.path.join(OUT, name + ".img")
        with open(path, "wb") as f:
            f.truncate(size)
        subprocess.run(["mkfs.fat", "-F", fat, "-s", spc, "-n", "PLAIN", "-i", "0A0B0C0D", path], check=True, capture_output=True)
        files = {"hello.txt": b"hello plain\n", "docs/readme.txt": b"nested file\n" * 50,
                 "data.bin": hashlib.sha512(name.encode()).digest() * 600,   # ~38 KB, many clusters
                 "Long File Name Here.txt": b"long name\n" * 10, "Mixed Case.Txt": b"mixed case\n",
                 "docs/deep/er/leaf.txt": b"leaf\n", "empty.txt": b""}
        for i in range(150):
            files[f"many/file{i:03d}.txt"] = f"entry {i}\n".encode()
        def put(rel, data):
            src = os.path.join(OUT, "_tmp.bin"); open(src, "wb").write(data)
            parts = rel.split("/")
            for i in range(1, len(parts)):
                subprocess.run(["mmd", "-D", "s", "-i", path, "::/" + "/".join(parts[:i])], capture_output=True, env=env)
            subprocess.run(["mcopy", "-i", path, src, "::/" + rel], check=True, capture_output=True, env=env)
        # fragmentation: interleave small files, delete every other one, then write a big file into the holes
        for i in range(12):
            put(f"frag/s{i}.bin", bytes([i]) * 2048)
        for i in range(0, 12, 2):
            subprocess.run(["mdel", "-i", path, f"::/frag/s{i}.bin"], check=True, capture_output=True, env=env)
        files.update({f"frag/s{i}.bin": bytes([i]) * 2048 for i in range(1, 12, 2)})
        files["frag/big.bin"] = os.urandom(20000)
        for rel, data in files.items():
            if not rel.startswith("frag/s"):
                put(rel, data)
        os.remove(os.path.join(OUT, "_tmp.bin"))
        cat[name] = {"file": name + ".img", "fat": fat, "files": hashes(files),
                     "sizes": {k: len(v) for k, v in files.items()}}
    json.dump(cat, open(os.path.join(OUT, "plain_fixtures.json"), "w"), indent=1, ensure_ascii=False)
    return cat


def main():
    os.makedirs(OUT, exist_ok=True)
    kf1, kf2 = os.path.join(OUT, "keyfile1.bin"), os.path.join(OUT, "keyfile2.bin")
    open(kf1, "wb").write(bytes(range(256)) * 4)
    open(kf2, "wb").write(b"second keyfile contents\n" * 20)
    M = 1024 * 1024
    cat = {}
    cat["aes_sha512_fat"] = make("aes_sha512_fat", 5 * M, "test", files=sample_files("a"))
    cat["aes_sha256_fat"] = make("aes_sha256_fat", 5 * M, "test", prf="sha256", files=sample_files("b"))
    cat["aes_blake2s_fat"] = make("aes_blake2s_fat", 5 * M, "test", prf="blake2s", files=sample_files("c"))
    cat["aes_sha512_pim10"] = make("aes_sha512_pim10", 5 * M, "test", pim=10, files=sample_files("d"))
    cat["aes_sha512_keyfile"] = make("aes_sha512_keyfile", 5 * M, "test", keyfiles=[kf1, kf2], files=sample_files("e"))
    cat["unicode_pw"] = make("unicode_pw", 5 * M, "pässwörd✓", files=sample_files("f"))
    cat["fat16"] = make("fat16", 8 * M, "test", fat="16", files=sample_files("g"))
    cat["tc_ripemd160"] = make("tc_ripemd160", 5 * M, "test", prf="ripemd160", files=sample_files("t1"), truecrypt=True, tc_version=5)
    cat["tc_sha512_v4"] = make("tc_sha512_v4", 5 * M, "test", prf="sha512", files=sample_files("t2"), truecrypt=True, tc_version=4)
    cat["tc_keyfile"] = make("tc_keyfile", 5 * M, "test", prf="ripemd160", keyfiles=[kf1], files=sample_files("t3"), truecrypt=True)
    cat["tc_hidden"] = make("tc_hidden", 8 * M, "outer", prf="sha512", files=sample_files("t4o"), hidden=("inner", 3 * M, sample_files("t4i")), truecrypt=True)
    cat["aes_exfat"] = make("aes_exfat", 9 * M, "test", exfat=True)
    cat["fat32"] = make("fat32", 41 * M, "test", fat="32", files=sample_files("j"))
    cat["fat12"] = make("fat12", 2 * M, "test", fat="12", files=sample_files("h"))
    cat["hidden"] = make("hidden", 8 * M, "outer", files=sample_files("o"), hidden=("inner", 3 * M, sample_files("i")))
    json.dump(cat, open(os.path.join(OUT, "fixtures.json"), "w"), indent=2, ensure_ascii=False)
    plain_images()
    print("generated", len(cat), "fixtures")


if __name__ == "__main__":
    main()
