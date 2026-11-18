package org.openvault.fs.ntfs

import org.openvault.fs.*
import org.openvault.io.BlockDevice
import java.time.Instant

/**
 * Read-only NTFS driver, written from the public NTFS format documentation (boot sector, MFT records with update-sequence
 * fixups, attributes, $ATTRIBUTE_LIST, data runs incl. sparse, $INDEX_ROOT/$INDEX_ALLOCATION B-trees, $UpCase).
 * Not supported (typed [FsException]): compressed and EFS-encrypted files. Resident/non-resident/sparse/fragmented files,
 * large directories, hard links and Unicode names are supported. Writing is intentionally not implemented (journal safety).
 */
class NtfsFileSystem(private val dev: BlockDevice) : FileSystem {
    private class Run(val vcn: Long, val lcn: Long /* -1 = sparse */, val length: Long)

    private class Attr(
        val type: Int, val name: String, val nonResident: Boolean, val flags: Int, val resident: ByteArray?,
        val startVcn: Long, val runs: List<Run>, val allocated: Long, val real: Long, val initialized: Long,
    )

    private class Rec(val number: Long, val flags: Int, val attrs: List<Attr>) {
        val inUse get() = flags and 1 != 0
        val isDir get() = flags and 2 != 0
    }

    private class Entry(val name: String, val mft: Long, val isDir: Boolean, val size: Long, val modified: Instant?, val created: Instant?)

    private val bps: Int; private val clusterSize: Int; private val recordSize: Int
    private val totalClusters: Long; private val mftLcn: Long
    private var closed = false
    private lateinit var mft: DataStream
    private val records = object : LinkedHashMap<Long, Rec>(256, 0.75f, true) { override fun removeEldestEntry(e: MutableMap.MutableEntry<Long, Rec>) = size > 1024 }
    private val dirCache = HashMap<FsPath, List<Entry>>()
    private val upcase: CharArray? by lazy { loadUpcase() }

    /** Number of times an $ATTRIBUTE_LIST had to be resolved (exposed for tests that must exercise that path). */
    var attributeListReads = 0
        private set

    companion object {
        fun matches(boot: ByteArray) = boot.size >= 512 && String(boot, 3, 8, Charsets.ISO_8859_1) == "NTFS    "
        private const val ROOT = 5L
        private fun u8(b: ByteArray, o: Int) = b[o].toInt() and 0xff
        private fun u16(b: ByteArray, o: Int) = u8(b, o) or (u8(b, o + 1) shl 8)
        private fun u32(b: ByteArray, o: Int) = u16(b, o).toLong() or (u16(b, o + 2).toLong() shl 16)
        private fun u64(b: ByteArray, o: Int) = u32(b, o) or (u32(b, o + 4) shl 32)
        private const val T_STDINFO = 0x10; private const val T_ATTRLIST = 0x20; private const val T_FILENAME = 0x30
        private const val T_VOLNAME = 0x60; private const val T_DATA = 0x80; private const val T_IROOT = 0x90
        private const val T_IALLOC = 0xA0; private const val T_END = -1
    }

    init {
        val boot = ByteArray(maxOf(512, dev.sectorSize)); dev.readSectors(0, boot, 0, 1)
        if (!matches(boot)) throw UnsupportedFilesystemException("not NTFS")
        if (u16(boot, 510) != 0xAA55) throw FsCorruptException("bad boot signature")
        bps = u16(boot, 0x0B)
        val spcRaw = u8(boot, 0x0D)
        val spc = if (spcRaw > 0x80) 1 shl (256 - spcRaw) else spcRaw
        if (bps !in intArrayOf(512, 1024, 2048, 4096) || spc < 1 || spc and (spc - 1) != 0) throw FsCorruptException("bad NTFS geometry")
        clusterSize = bps * spc
        if (clusterSize > 2 * 1024 * 1024) throw FsCorruptException("cluster size too large")
        val totalSectors = u64(boot, 0x28)
        if (totalSectors <= 0 || totalSectors * bps > dev.sectorCount * dev.sectorSize) throw FsCorruptException("filesystem larger than device")
        totalClusters = totalSectors / spc
        mftLcn = u64(boot, 0x30)
        val cpr = boot[0x40].toInt()
        recordSize = if (cpr > 0) cpr * clusterSize else 1 shl -cpr
        if (recordSize < 512 || recordSize > 65536 || recordSize and (recordSize - 1) != 0) throw FsCorruptException("bad MFT record size")
        if (mftLcn <= 0 || mftLcn >= totalClusters) throw FsCorruptException("bad MFT location")
        // bootstrap: record 0 describes the (possibly fragmented) $MFT itself
        val first = ByteArray(recordSize); readBytes(mftLcn * clusterSize, first, 0, recordSize)
        val rec0 = parseRecord(0, first)
        mft = DataStream(rec0.attrs.filter { it.type == T_DATA && it.name.isEmpty() }.let { assemble(it) ?: throw FsCorruptException("\$MFT has no data") })
        val extended = fullAttrs(rec0)
        mft = DataStream(assemble(extended.filter { it.type == T_DATA && it.name.isEmpty() }) ?: throw FsCorruptException("\$MFT has no data"))
        records[0] = Rec(0, rec0.flags, extended)
        if (!root().isDirectory) throw FsCorruptException("root directory missing")
    }

    // ------------------------------------------------------------------ raw access
    private fun readBytes(pos: Long, dst: ByteArray, off: Int, len: Int) {
        if (len == 0) return
        val s = dev.sectorSize
        require(pos >= 0 && pos + len <= dev.sectorCount * s) { "read outside device" }
        if (pos % s == 0L && len % s == 0) { dev.readSectors(pos / s, dst, off, len / s); return }
        val first = pos / s; val last = (pos + len - 1) / s
        val tmp = ByteArray(((last - first + 1) * s).toInt()); dev.readSectors(first, tmp, 0, (last - first + 1).toInt())
        System.arraycopy(tmp, (pos - first * s).toInt(), dst, off, len)
    }

    /** Update-sequence fixups (same scheme for FILE records and INDX blocks): every 512-byte stride ends with the USN. */
    private fun applyFixups(buf: ByteArray, usaOff: Int, usaCount: Int) {
        if (usaCount < 1 || usaOff < 8 || usaOff + usaCount * 2 > buf.size || (usaCount - 1) * 512 > buf.size) throw FsCorruptException("bad update sequence array")
        val usn = u16(buf, usaOff)
        for (i in 1 until usaCount) {
            val p = i * 512 - 2
            if (p + 2 > buf.size) break
            if (u16(buf, p) != usn) throw FsCorruptException("update sequence mismatch (torn or corrupt record)")
            buf[p] = buf[usaOff + 2 * i]; buf[p + 1] = buf[usaOff + 2 * i + 1]
        }
    }

    private fun parseRecord(number: Long, buf: ByteArray): Rec {
        val magic = String(buf, 0, 4, Charsets.ISO_8859_1)
        if (magic != "FILE") throw FsCorruptException("MFT record $number has bad magic '$magic'")
        applyFixups(buf, u16(buf, 4), u16(buf, 6))
        val flags = u16(buf, 0x16); val attrOff = u16(buf, 0x14); val used = u32(buf, 0x18).toInt().coerceAtMost(buf.size)
        val attrs = ArrayList<Attr>()
        var o = attrOff
        while (o + 8 <= used) {
            val type = u32(buf, o).toInt()
            if (type == T_END) break
            val len = u32(buf, o + 4).toInt()
            if (len < 16 || len % 8 != 0 || o + len > used) throw FsCorruptException("bad attribute length in record $number")
            val nonRes = buf[o + 8].toInt() != 0
            val nameLen = u8(buf, o + 9); val nameOff = u16(buf, o + 10); val aflags = u16(buf, o + 12)
            val name = if (nameLen == 0) "" else String(buf, o + nameOff, nameLen * 2, Charsets.UTF_16LE)
            if (!nonRes) {
                val vlen = u32(buf, o + 16).toInt(); val voff = u16(buf, o + 20)
                if (voff + vlen > len || vlen < 0) throw FsCorruptException("bad resident attribute in record $number")
                attrs += Attr(type, name, false, aflags, buf.copyOfRange(o + voff, o + voff + vlen), 0, emptyList(), vlen.toLong(), vlen.toLong(), vlen.toLong())
            } else {
                if (len < 0x40) throw FsCorruptException("short non-resident attribute")
                val startVcn = u64(buf, o + 16); val runOff = u16(buf, o + 32)
                attrs += Attr(type, name, true, aflags, null, startVcn, parseRuns(buf, o + runOff, o + len, startVcn), u64(buf, o + 40), u64(buf, o + 48), u64(buf, o + 56))
            }
            o += len
        }
        return Rec(number, flags, attrs)
    }

    private fun parseRuns(b: ByteArray, from: Int, to: Int, startVcn: Long): List<Run> {
        val out = ArrayList<Run>(); var o = from; var vcn = startVcn; var lcn = 0L
        while (o < to) {
            val h = u8(b, o); if (h == 0) break
            val ls = h and 0xf; val os = h shr 4
            if (ls == 0 || ls > 8 || os > 8 || o + 1 + ls + os > to) throw FsCorruptException("bad data run header")
            var len = 0L; for (i in 0 until ls) len = len or (u8(b, o + 1 + i).toLong() shl (8 * i))
            if (os == 0) out += Run(vcn, -1, len)
            else {
                var d = 0L; for (i in 0 until os) d = d or (u8(b, o + 1 + ls + i).toLong() shl (8 * i))
                if (b[o + ls + os].toInt() < 0) d = d or (-1L shl (8 * os)) // sign-extend
                lcn += d
                if (lcn < 0 || lcn + len > totalClusters) throw FsCorruptException("data run outside the volume")
                out += Run(vcn, lcn, len)
            }
            vcn += len; o += 1 + ls + os
        }
        return out
    }

    // ------------------------------------------------------------------ streams
    private class Assembled(val runs: List<Run>, val size: Long, val initialized: Long, val resident: ByteArray?, val flags: Int)

    private fun assemble(parts: List<Attr>): Assembled? {
        if (parts.isEmpty()) return null
        val sorted = parts.sortedBy { it.startVcn }; val first = sorted[0]
        if (!first.nonResident) return Assembled(emptyList(), first.real, first.real, first.resident, first.flags)
        return Assembled(sorted.flatMap { it.runs }, first.real, first.initialized, null, first.flags)
    }

    private inner class DataStream(a: Assembled) {
        val size = a.size; val flags = a.flags
        private val runs = a.runs; private val initialized = a.initialized; private val resident = a.resident
        fun read(pos: Long, dst: ByteArray, off: Int, len: Int): Int {
            if (pos >= size) return -1
            val n = minOf(len.toLong(), size - pos).toInt()
            if (resident != null) { System.arraycopy(resident, pos.toInt(), dst, off, n); return n }
            var done = 0
            while (done < n) {
                val p = pos + done; val vcn = p / clusterSize; val within = (p % clusterSize)
                val run = findRun(vcn) ?: throw FsCorruptException("no data run covers VCN $vcn")
                val inRun = (run.vcn + run.length - vcn) * clusterSize - within
                var take = minOf((n - done).toLong(), inRun)
                if (p >= initialized || run.lcn < 0) { java.util.Arrays.fill(dst, off + done, off + done + take.toInt(), 0) }
                else {
                    take = minOf(take, initialized - p)
                    readBytes((run.lcn + (vcn - run.vcn)) * clusterSize + within, dst, off + done, take.toInt())
                }
                done += take.toInt()
            }
            return n
        }
        private fun findRun(vcn: Long): Run? {
            var lo = 0; var hi = runs.size - 1
            while (lo <= hi) { val mid = (lo + hi) ushr 1; val r = runs[mid]
                if (vcn < r.vcn) hi = mid - 1 else if (vcn >= r.vcn + r.length) lo = mid + 1 else return r }
            return null
        }
        fun readAll(limit: Long = 64L shl 20): ByteArray {
            if (size > limit) throw FsCorruptException("attribute unreasonably large ($size bytes)")
            val b = ByteArray(size.toInt()); var q = 0
            while (q < b.size) { val r = read(q.toLong(), b, q, b.size - q); if (r < 0) break; q += r }
            return b
        }
    }

    // ------------------------------------------------------------------ MFT records
    private fun record(n: Long): Rec {
        records[n]?.let { return it }
        if (n < 0 || (n + 1) * recordSize > mft.size) throw FsNotFoundException("MFT record $n")
        val buf = ByteArray(recordSize)
        if (mft.read(n * recordSize, buf, 0, recordSize) < recordSize) throw FsCorruptException("short MFT record $n")
        val r = parseRecord(n, buf)
        return r.also { records[n] = it }
    }

    /** The record's attributes plus those living in extension records (via $ATTRIBUTE_LIST). */
    private fun fullAttrs(r: Rec): List<Attr> {
        val list = r.attrs.firstOrNull { it.type == T_ATTRLIST && it.name.isEmpty() } ?: return r.attrs
        attributeListReads++
        val bytes = if (!list.nonResident) list.resident!! else DataStream(assemble(listOf(list))!!).readAll(4L shl 20)
        val others = LinkedHashSet<Long>(); var o = 0
        while (o + 26 <= bytes.size) {
            val len = u16(bytes, o + 4); if (len < 26) throw FsCorruptException("bad attribute list entry")
            val ref = u64(bytes, o + 16) and 0xFFFFFFFFFFFFL
            if (ref != r.number) others += ref
            o += len
        }
        val all = ArrayList(r.attrs.filter { it !== list })
        for (n in others) {
            val buf = ByteArray(recordSize)
            if ((n + 1) * recordSize > mft.size || mft.read(n * recordSize, buf, 0, recordSize) < recordSize) throw FsCorruptException("extension record $n missing")
            all += parseRecord(n, buf).attrs.filter { it.type != T_ATTRLIST }
        }
        return all
    }

    private fun stream(attrs: List<Attr>, type: Int, name: String = ""): DataStream? = assemble(attrs.filter { it.type == type && it.name == name })?.let { DataStream(it) }

    private fun filetime(t: Long): Instant? = if (t <= 0) null else Instant.ofEpochSecond(t / 10_000_000L - 11_644_473_600L, (t % 10_000_000L) * 100)

    private fun entryOf(name: String, mftNo: Long): Entry? {
        val r = try { record(mftNo) } catch (e: FsNotFoundException) { return null }
        if (!r.inUse) return null
        val attrs = fullAttrs(r)
        val si = attrs.firstOrNull { it.type == T_STDINFO }?.resident
        val data = attrs.filter { it.type == T_DATA && it.name.isEmpty() }
        val size = if (r.isDir) 0L else assemble(data)?.size ?: 0L
        return Entry(name, mftNo, r.isDir, size, si?.takeIf { it.size >= 16 }?.let { filetime(u64(it, 8)) }, si?.takeIf { it.size >= 8 }?.let { filetime(u64(it, 0)) })
    }

    // ------------------------------------------------------------------ directories (B-tree indexes)
    private fun readDirectory(mftNo: Long): List<Entry> {
        val r = record(mftNo); val attrs = fullAttrs(r)
        val root = attrs.firstOrNull { it.type == T_IROOT && it.name == "\$I30" }?.resident ?: throw FsNotDirectoryException("MFT record $mftNo")
        if (root.size < 32) throw FsCorruptException("short \$INDEX_ROOT")
        val blockSize = u32(root, 8).toInt()
        val alloc = stream(attrs, T_IALLOC, "\$I30")
        val found = LinkedHashMap<String, Entry>()
        val seen = HashSet<Long>()

        fun walk(buf: ByteArray, nodeStart: Int, depth: Int) {
            if (depth > 48) throw FsCorruptException("directory index too deep")
            var o = nodeStart + u32(buf, nodeStart).toInt(); val end = minOf(nodeStart + u32(buf, nodeStart + 4).toInt(), buf.size)
            while (o + 16 <= end) {
                val len = u16(buf, o + 8); val keyLen = u16(buf, o + 10); val fl = u16(buf, o + 12)
                if (len < 16 || o + len > end) throw FsCorruptException("bad index entry")
                if (fl and 1 != 0) { // sub-node: entries there sort before this key
                    val vcn = u64(buf, o + len - 8)
                    if (alloc == null || blockSize <= 0) throw FsCorruptException("index sub-node without \$INDEX_ALLOCATION")
                    if (!seen.add(vcn)) throw FsCorruptException("directory index loop")
                    val blk = ByteArray(blockSize)
                    val unit = if (blockSize >= clusterSize) clusterSize else 512
                    if (alloc.read(vcn * unit, blk, 0, blockSize) < blockSize) throw FsCorruptException("index block beyond allocation")
                    if (String(blk, 0, 4, Charsets.ISO_8859_1) != "INDX") throw FsCorruptException("bad INDX magic")
                    applyFixups(blk, u16(blk, 4), u16(blk, 6))
                    walk(blk, 0x18, depth + 1)
                }
                if (fl and 2 == 0 && keyLen >= 0x42) {
                    val k = o + 16; val nameLen = u8(buf, k + 0x40); val ns = u8(buf, k + 0x41)
                    if (k + 0x42 + nameLen * 2 > o + len) throw FsCorruptException("bad file name key")
                    val name = String(buf, k + 0x42, nameLen * 2, Charsets.UTF_16LE)
                    val ref = u64(buf, o) and 0xFFFFFFFFFFFFL
                    val skip = ns == 2 /* DOS 8.3 duplicate of a Win32 name */ || name == "." || (mftNo == ROOT && ref < 24 && ref != ROOT)
                    if (!skip && !found.containsKey(name.lowercase() + "\u0000" + ref)) entryOf(name, ref)?.let { found[name.lowercase() + "\u0000" + ref] = it }
                }
                if (fl and 2 != 0) break
                o += len
            }
        }
        walk(root, 16, 0)
        return found.values.toList()
    }

    private fun loadUpcase(): CharArray? = try {
        val b = stream(fullAttrs(record(10)), T_DATA)?.readAll(256L * 1024) ?: null
        if (b == null || b.size < 256) null else CharArray(b.size / 2) { (u16(b, it * 2)).toChar() }
    } catch (e: Exception) { null }

    private fun fold(s: String): String {
        val t = upcase ?: return s.uppercase()
        return String(CharArray(s.length) { val c = s[it]; if (c.code < t.size) t[c.code] else c })
    }

    private class Loc(val path: FsPath, val mft: Long, val entry: Entry?)

    private fun readDir(path: FsPath, mftNo: Long): List<Entry> = dirCache.getOrPut(path) { readDirectory(mftNo) }

    private fun locate(p: FsPath): Loc {
        var cur = FsPath.ROOT; var no = ROOT; var e: Entry? = null
        for ((i, seg) in p.segments.withIndex()) {
            if (e != null && !e.isDir) throw FsNotDirectoryException(cur)
            val want = fold(seg)
            val hit = readDir(cur, no).firstOrNull { fold(it.name) == want } ?: throw FsNotFoundException(p)
            cur = cur.child(hit.name); no = hit.mft; e = hit
            if (!hit.isDir && i < p.segments.size - 1) throw FsNotDirectoryException(cur)
        }
        return Loc(cur, no, e)
    }

    // ------------------------------------------------------------------ FileSystem
    override val label: String? by lazy { try { stream(fullAttrs(record(3)), T_VOLNAME)?.readAll(1024)?.let { String(it, Charsets.UTF_16LE) }?.ifEmpty { null } } catch (e: Exception) { null } }
    override val isReadOnly get() = true
    private fun node(path: FsPath, e: Entry) = FsNode(path, e.name, e.isDir, e.size, e.modified, e.created)
    override fun root(): FsNode { val e = entryOf("", ROOT); return FsNode(FsPath.ROOT, "", true, 0, e?.modified, e?.created) }

    override fun resolve(path: FsPath): FsNode { check(!closed); val l = locate(path); return l.entry?.let { node(l.path, it) } ?: root() }

    override fun list(dir: FsNode): List<FsNode> {
        check(!closed); val l = locate(dir.path)
        if (l.entry != null && !l.entry.isDir) throw FsNotDirectoryException(dir.path)
        return readDir(l.path, l.mft).map { node(l.path.child(it.name), it) }
    }

    override fun open(node: FsNode, mode: OpenMode): FsFile {
        check(!closed); if (mode != OpenMode.READ) throw FsReadOnlyException()
        val l = locate(node.path); val e = l.entry ?: throw FsIsDirectoryException(node.path)
        if (e.isDir) throw FsIsDirectoryException(node.path)
        val attrs = fullAttrs(record(e.mft))
        val parts = attrs.filter { it.type == T_DATA && it.name.isEmpty() }
        val first = parts.minByOrNull { it.startVcn }
        if (first != null && first.flags and 0x0001 != 0) throw FsException("Compressed NTFS files are not supported: ${node.path}")
        if (first != null && first.flags and 0x4000 != 0) throw FsException("Encrypted (EFS) NTFS files cannot be read: ${node.path}")
        if (record(e.mft).attrs.any { it.type == 0x100 } ) { /* $LOGGED_UTILITY_STREAM present = EFS metadata; flags above decide */ }
        val ds = stream(attrs, T_DATA) ?: DataStream(Assembled(emptyList(), 0, 0, ByteArray(0), 0))
        return object : FsFile {
            override val size = ds.size
            override fun read(position: Long, dst: ByteArray, off: Int, len: Int): Int { require(off >= 0 && len >= 0 && off + len <= dst.size); return ds.read(position, dst, off, len) }
            override fun write(position: Long, src: ByteArray, off: Int, len: Int) = throw FsReadOnlyException()
            override fun truncate(newSize: Long) = throw FsReadOnlyException()
            override fun flush() {}
            override fun close() {}
        }
    }

    override fun spaceInfo(): SpaceInfo {
        val bm = stream(fullAttrs(record(6)), T_DATA) ?: return SpaceInfo(totalClusters * clusterSize, 0)
        var used = 0L; val buf = ByteArray(65536); var pos = 0L; val bytesNeeded = (totalClusters + 7) / 8
        while (pos < bytesNeeded) {
            val n = bm.read(pos, buf, 0, minOf(buf.size.toLong(), bytesNeeded - pos).toInt()); if (n <= 0) break
            for (i in 0 until n) {
                var v = buf[i].toInt() and 0xff
                if (pos + i == bytesNeeded - 1 && totalClusters % 8 != 0L) v = v and ((1 shl (totalClusters % 8).toInt()) - 1)
                used += Integer.bitCount(v)
            }
            pos += n
        }
        return SpaceInfo(totalClusters * clusterSize, (totalClusters - used) * clusterSize)
    }

    override fun createFile(dir: FsNode, name: String) = throw FsReadOnlyException()
    override fun createDirectory(dir: FsNode, name: String) = throw FsReadOnlyException()
    override fun rename(node: FsNode, newName: String) = throw FsReadOnlyException()
    override fun move(node: FsNode, newParent: FsNode) = throw FsReadOnlyException()
    override fun delete(node: FsNode) = throw FsReadOnlyException()
    override fun sync() {}
    override fun close() { if (closed) return; closed = true; records.clear(); dirCache.clear(); dev.close() }
}
