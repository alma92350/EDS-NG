package org.openvault.fs.fat

import org.openvault.fs.*
import org.openvault.io.BlockDevice
import java.time.Instant
import java.time.LocalDateTime
import java.time.ZoneId

/**
 * FAT12/16/32 driver with read/write. Not thread-safe (serialised by the vault session).
 * I/O is write-through, in crash-safe order: file data, then FAT entries, then the directory entry.
 */
class FatFileSystem(
    private val dev: BlockDevice,
    private val zone: ZoneId = ZoneId.systemDefault(),
    readOnly: Boolean = dev.isReadOnly,
    private val clock: () -> Instant = { Instant.now() },
) : FileSystem {
    val bpb: Bpb
    private val sectorCache = object : LinkedHashMap<Long, ByteArray>(64, 0.75f, true) {
        override fun removeEldestEntry(e: MutableMap.MutableEntry<Long, ByteArray>) = size > 256
    }
    private val dirCache = HashMap<FsPath, List<DirEntry>>()
    private var closed = false
    private val readOnlyMode = readOnly || dev.isReadOnly
    private var freeCount = -1L
    private var nextFree = 2L

    init {
        require(dev.sectorSize >= 512)
        val boot = ByteArray(dev.sectorSize); dev.readSectors(0, boot, 0, 1)
        bpb = Bpb.parse(boot)
        if (bpb.bytesPerSector != dev.sectorSize) throw FsCorruptException("BPB sector size ${bpb.bytesPerSector} != device ${dev.sectorSize}")
        if (bpb.totalSectors > dev.sectorCount) throw FsCorruptException("filesystem larger than device")
    }

    val type get() = bpb.type
    override val label: String? get() = bpb.label
    override val isReadOnly get() = readOnlyMode
    private fun requireWritable() { if (readOnlyMode) throw FsReadOnlyException() }

    // ---------------------------------------------------------------- sectors / FAT
    private fun sector(n: Long): ByteArray = sectorCache.getOrPut(n) { ByteArray(bpb.bytesPerSector).also { dev.readSectors(n, it, 0, 1) } }
    private fun putSector(n: Long, data: ByteArray) { dev.writeSectors(n, data, 0, 1) }

    private fun fatByteAt(copy: Int, o: Long): Long = bpb.fatStartSector + copy * bpb.fatSectors + o / bpb.bytesPerSector
    private fun fatGet(o: Long): Int = sector(fatByteAt(0, o))[(o % bpb.bytesPerSector).toInt()].toInt() and 0xff
    /** Applies byte updates to every FAT copy, writing each affected sector ONCE per copy (no torn multi-byte entries within a sector). */
    private fun fatPutMany(updates: List<Pair<Long, Int>>) {
        val bps = bpb.bytesPerSector
        val bySector = updates.groupBy { it.first / bps }
        for (copy in 0 until bpb.numFats) for ((secIdx, ups) in bySector.entries.sortedBy { it.key }) {
            val sn = bpb.fatStartSector + copy * bpb.fatSectors + secIdx
            val s = sector(sn)
            for ((o, v) in ups) s[(o % bps).toInt()] = v.toByte()
            putSector(sn, s)
        }
    }

    private fun fatEntry(c: Long): Long {
        val off = when (bpb.type) { FatType.FAT12 -> c + c / 2; FatType.FAT16 -> c * 2; FatType.FAT32 -> c * 4 }
        return when (bpb.type) {
            FatType.FAT12 -> { val v = fatGet(off) or (fatGet(off + 1) shl 8); (if (c and 1L == 0L) v and 0xfff else v shr 4).toLong() }
            FatType.FAT16 -> (fatGet(off) or (fatGet(off + 1) shl 8)).toLong()
            FatType.FAT32 -> (fatGet(off).toLong() or (fatGet(off + 1).toLong() shl 8) or (fatGet(off + 2).toLong() shl 16) or (fatGet(off + 3).toLong() shl 24)) and 0x0FFFFFFFL
        }
    }

    private fun setFatEntry(c: Long, value: Long) {
        val off = when (bpb.type) { FatType.FAT12 -> c + c / 2; FatType.FAT16 -> c * 2; FatType.FAT32 -> c * 4 }
        val ups = ArrayList<Pair<Long, Int>>(4)
        when (bpb.type) {
            FatType.FAT12 -> {
                val v = value.toInt() and 0xfff
                if (c and 1L == 0L) { ups += off to (v and 0xff); ups += (off + 1) to ((fatGet(off + 1) and 0xf0) or (v shr 8)) }
                else { ups += off to ((fatGet(off) and 0x0f) or ((v and 0xf) shl 4)); ups += (off + 1) to (v shr 4) }
            }
            FatType.FAT16 -> { ups += off to (value.toInt() and 0xff); ups += (off + 1) to ((value shr 8).toInt() and 0xff) }
            FatType.FAT32 -> {
                ups += off to (value.toInt() and 0xff); ups += (off + 1) to ((value shr 8).toInt() and 0xff); ups += (off + 2) to ((value shr 16).toInt() and 0xff)
                ups += (off + 3) to ((fatGet(off + 3) and 0xf0) or ((value shr 24).toInt() and 0x0f))
            }
        }
        fatPutMany(ups)
    }

    private val eoc get() = when (bpb.type) { FatType.FAT12 -> 0xFFFL; FatType.FAT16 -> 0xFFFFL; FatType.FAT32 -> 0x0FFFFFFFL }
    private fun isEnd(v: Long) = when (bpb.type) { FatType.FAT12 -> v >= 0xFF8; FatType.FAT16 -> v >= 0xFFF8; FatType.FAT32 -> v >= 0x0FFFFFF8 }
    private fun isBad(v: Long) = when (bpb.type) { FatType.FAT12 -> v == 0xFF7L; FatType.FAT16 -> v == 0xFFF7L; FatType.FAT32 -> v == 0x0FFFFFF7L }

    private fun chain(first: Long, limit: Long = bpb.clusterCount): MutableList<Long> {
        val out = ArrayList<Long>()
        if (first < 2) return out
        var c = first
        while (true) {
            if (c < 2 || c >= bpb.clusterCount + 2) throw FsCorruptException("cluster $c out of range")
            out += c
            if (out.size > limit) throw FsCorruptException("cluster chain loop")
            val n = fatEntry(c)
            if (isEnd(n)) break
            if (isBad(n) || n < 2) throw FsCorruptException("bad cluster in chain at $c")
            c = n
        }
        return out
    }

    private fun ensureFreeCount() {
        if (freeCount >= 0) return
        var f = 0L; for (c in 2L until bpb.clusterCount + 2) if (fatEntry(c) == 0L) f++
        freeCount = f
    }

    /** Allocates one cluster and marks it end-of-chain. Does not touch data. */
    private fun allocCluster(): Long {
        ensureFreeCount()
        if (freeCount == 0L) throw FsNoSpaceException()
        val total = bpb.clusterCount
        var c = if (nextFree in 2 until total + 2) nextFree else 2L
        for (i in 0 until total) {
            if (fatEntry(c) == 0L) { setFatEntry(c, eoc); freeCount--; nextFree = if (c + 1 < total + 2) c + 1 else 2; return c }
            c = if (c + 1 < total + 2) c + 1 else 2
        }
        throw FsNoSpaceException()
    }

    /** Allocates [n] clusters in one pass and links them (and [prev] -> first) with batched FAT writes (FAT16/32); returns them in order. */
    private fun allocClusters(n: Int, prev: Long): List<Long> {
        if (n == 1 || bpb.type == FatType.FAT12) {
            val out = ArrayList<Long>()
            for (i in 0 until n) { val c = allocCluster(); if (i == 0 && prev != 0L) setFatEntry(prev, c) else if (i > 0) setFatEntry(out.last(), c); out += c }
            return out
        }
        ensureFreeCount()
        if (freeCount < n) throw FsNoSpaceException()
        val total = bpb.clusterCount; val got = ArrayList<Long>(n)
        var c = if (nextFree in 2 until total + 2) nextFree else 2L
        var scanned = 0L
        while (got.size < n && scanned < total) { if (fatEntry(c) == 0L) got += c; c = if (c + 1 < total + 2) c + 1 else 2; scanned++ }
        if (got.size < n) throw FsNoSpaceException()
        val ups = ArrayList<Pair<Long, Int>>()
        fun put(cl: Long, v: Long) {
            val off = if (bpb.type == FatType.FAT16) cl * 2 else cl * 4
            if (bpb.type == FatType.FAT16) { ups += off to (v.toInt() and 0xff); ups += (off + 1) to ((v shr 8).toInt() and 0xff) }
            else { ups += off to (v.toInt() and 0xff); ups += (off + 1) to ((v shr 8).toInt() and 0xff); ups += (off + 2) to ((v shr 16).toInt() and 0xff); ups += (off + 3) to ((fatGet(off + 3) and 0xf0) or ((v shr 24).toInt() and 0x0f)) }
        }
        for (i in got.indices) put(got[i], if (i + 1 < got.size) got[i + 1] else eoc)
        if (prev != 0L) put(prev, got[0])
        fatPutMany(ups)
        freeCount -= n; nextFree = if (got.last() + 1 < total + 2) got.last() + 1 else 2
        return got
    }

    private fun freeChain(first: Long) {
        ensureFreeCount()
        for (c in chain(first)) { setFatEntry(c, 0); freeCount++; if (c < nextFree) nextFree = c }
    }

    private fun zeroCluster(c: Long) {
        val z = ByteArray(bpb.clusterBytes)
        dev.writeSectors(bpb.clusterFirstSector(c), z, 0, bpb.sectorsPerCluster)
    }

    // ---------------------------------------------------------------- directory streams
    /** Reference to a directory's byte stream: 0 = fixed root (FAT12/16), else first cluster. */
    private fun dirRef(e: DirEntry?): Long = if (e == null) (if (bpb.type == FatType.FAT32) bpb.rootCluster else 0L) else e.firstCluster

    private fun readStream(ref: Long): ByteArray =
        if (ref == 0L) ByteArray(bpb.rootDirSectors * bpb.bytesPerSector).also { dev.readSectors(bpb.rootDirStartSector, it, 0, bpb.rootDirSectors) }
        else readClusters(chain(ref))

    private fun readClusters(cl: List<Long>): ByteArray {
        val out = ByteArray(cl.size * bpb.clusterBytes)
        for ((i, c) in cl.withIndex()) dev.readSectors(bpb.clusterFirstSector(c), out, i * bpb.clusterBytes, bpb.sectorsPerCluster)
        return out
    }

    /** Writes [data] at byte [offset] of the directory stream (read-modify-write at sector granularity). */
    private fun writeStream(ref: Long, offset: Int, data: ByteArray) {
        var done = 0
        val bps = bpb.bytesPerSector
        val cl = if (ref == 0L) null else chain(ref)
        while (done < data.size) {
            val pos = offset + done
            val secIdx = pos / bps
            val diskSector = if (cl == null) bpb.rootDirStartSector + secIdx else bpb.clusterFirstSector(cl[pos / bpb.clusterBytes]) + (pos % bpb.clusterBytes) / bps
            val buf = ByteArray(bps); dev.readSectors(diskSector, buf, 0, 1)
            val inSec = pos % bps; val n = minOf(bps - inSec, data.size - done)
            System.arraycopy(data, done, buf, inSec, n); dev.writeSectors(diskSector, buf, 0, 1)
            done += n
        }
    }

    private fun invalidate() { dirCache.clear() }

    private fun readDir(path: FsPath, e: DirEntry?): List<DirEntry> = dirCache.getOrPut(path) {
        val ref = dirRef(e)
        DirParser.parse(readStream(ref), zone).onEach { it.parentFirst = ref }
    }

    private fun node(path: FsPath, e: DirEntry) = FsNode(path, e.name, e.isDirectory, e.size, e.modified, e.created)
    override fun root() = FsNode(FsPath.ROOT, "", true, 0, null, null)

    private class Located(val path: FsPath, val entry: DirEntry?)

    private fun locate(p: FsPath): Located {
        var cur = FsPath.ROOT; var ce: DirEntry? = null
        for ((i, seg) in p.segments.withIndex()) {
            if (ce != null && !ce.isDirectory) throw FsNotDirectoryException(cur)
            val hit = readDir(cur, ce).firstOrNull { it.name.equals(seg, true) || it.shortName.equals(seg, true) } ?: throw FsNotFoundException(p)
            cur = cur.child(hit.name); ce = hit
            if (!hit.isDirectory && i < p.segments.size - 1) throw FsNotDirectoryException(cur)
        }
        return Located(cur, ce)
    }

    override fun resolve(path: FsPath): FsNode { check(!closed); val l = locate(path); return l.entry?.let { node(l.path, it) } ?: root() }

    override fun list(dir: FsNode): List<FsNode> {
        check(!closed)
        val l = locate(dir.path)
        if (l.entry != null && !l.entry.isDirectory) throw FsNotDirectoryException(dir.path)
        return readDir(l.path, l.entry).map { node(l.path.child(it.name), it) }
    }

    // ---------------------------------------------------------------- directory entry creation
    private fun fatDateTime(t: Instant): Pair<Int, Int> {
        val l = LocalDateTime.ofInstant(t, zone)
        val y = (l.year - 1980).coerceIn(0, 127)
        return ((y shl 9) or (l.monthValue shl 5) or l.dayOfMonth) to ((l.hour shl 11) or (l.minute shl 5) or (l.second / 2))
    }

    private fun shortEntry(name11: ByteArray, nt: Int, attr: Int, cluster: Long, size: Long, now: Instant): ByteArray {
        val e = ByteArray(32); name11.copyInto(e); e[11] = attr.toByte(); e[12] = nt.toByte()
        val (d, t) = fatDateTime(now)
        fun p16(o: Int, v: Int) { e[o] = v.toByte(); e[o + 1] = (v shr 8).toByte() }
        p16(14, t); p16(16, d); p16(18, d); p16(20, (cluster shr 16).toInt()); p16(22, t); p16(24, d); p16(26, cluster.toInt() and 0xffff)
        e[28] = size.toByte(); e[29] = (size shr 8).toByte(); e[30] = (size shr 16).toByte(); e[31] = (size shr 24).toByte()
        return e
    }

    /** Adds a new entry for [name] into the directory [parent] (null = root). Returns the entry. */
    private fun addEntry(parentPath: FsPath, parent: DirEntry?, name: String, attr: Int, cluster: Long, size: Long): DirEntry {
        ShortName.validate(name)
        val siblings = readDir(parentPath, parent)
        if (siblings.any { it.name.equals(name, true) || it.shortName.equals(name, true) }) throw FsExistsException(parentPath.child(name))
        val taken = siblings.map { it.shortName.let { s -> val d = s.lastIndexOf('.'); if (d < 0) s.uppercase().padEnd(8) + "   " else s.substring(0, d).uppercase().padEnd(8) + s.substring(d + 1).uppercase().padEnd(3) } }.toSet()
        val packed = ShortName.pack(name, taken)
        val lfn = if (packed.needsLfn) ShortName.lfnEntries(name, packed.name11) else emptyList()
        val now = clock()
        val sh = shortEntry(packed.name11, packed.ntFlags, attr, cluster, size, now)
        val need = lfn.size + 1
        val ref = dirRef(parent)
        var raw = readStream(ref)
        var start = findRun(raw, need)
        if (start < 0) {
            if (ref == 0L) throw FsNoSpaceException()
            val c = allocCluster(); zeroCluster(c)
            val last = chain(ref).last(); setFatEntry(last, c.toLong()); setFatEntry(c, eoc)
            raw = readStream(ref); start = findRun(raw, need)
            check(start >= 0)
        }
        val blob = ByteArray(need * 32)
        lfn.forEachIndexed { i, e -> e.copyInto(blob, i * 32) }; sh.copyInto(blob, lfn.size * 32)
        writeStream(ref, start, blob)
        invalidate()
        return DirParser.parse(readStream(ref), zone).first { it.shortOffset == start + lfn.size * 32 }.also { it.parentFirst = ref }
    }

    private fun findRun(raw: ByteArray, need: Int): Int {
        var runStart = -1; var run = 0; var o = 0
        var endSeen = false
        while (o + 32 <= raw.size) {
            val f = raw[o].toInt() and 0xff
            val free = f == 0x00 || f == 0xE5 || endSeen
            if (f == 0x00) endSeen = true
            if (free) { if (run == 0) runStart = o; run++; if (run == need) return runStart } else run = 0
            o += 32
        }
        return -1
    }

    /** Marks all entries of [e] deleted; returns their original first bytes (for rollback). */
    private fun markDeleted(e: DirEntry): ByteArray {
        val raw = readStream(e.parentFirst)
        val saved = ByteArray((e.shortOffset - e.startOffset) / 32 + 1) { raw[e.startOffset + it * 32] }
        for (i in saved.indices) writeStream(e.parentFirst, e.startOffset + i * 32, byteArrayOf(0xE5.toByte()))
        invalidate()
        return saved
    }

    private fun parentOf(path: FsPath): Located = locate(path.parent)

    override fun createFile(dir: FsNode, name: String): FsNode {
        check(!closed); requireWritable()
        val l = locate(dir.path); if (l.entry != null && !l.entry.isDirectory) throw FsNotDirectoryException(dir.path)
        val e = addEntry(l.path, l.entry, name, 0x20, 0, 0)
        return node(l.path.child(e.name), e)
    }

    override fun createDirectory(dir: FsNode, name: String): FsNode {
        check(!closed); requireWritable()
        val l = locate(dir.path); if (l.entry != null && !l.entry.isDirectory) throw FsNotDirectoryException(dir.path)
        ShortName.validate(name)
        if (readDir(l.path, l.entry).any { it.name.equals(name, true) || it.shortName.equals(name, true) }) throw FsExistsException(l.path.child(name))
        val c = allocCluster()
        try {
            zeroCluster(c)
            val now = clock()
            val dot = shortEntry(".".padEnd(11).toByteArray(), 0, 0x10, c, 0, now)
            val dotdot = shortEntry("..".padEnd(11).toByteArray(), 0, 0x10, if (l.entry == null) 0 else l.entry.firstCluster, 0, now)
            val blob = ByteArray(64); dot.copyInto(blob, 0); dotdot.copyInto(blob, 32)
            dev.writeSectors(bpb.clusterFirstSector(c), ByteArray(bpb.clusterBytes).also { blob.copyInto(it) }, 0, bpb.sectorsPerCluster)
            val e = addEntry(l.path, l.entry, name, 0x10, c, 0)
            return node(l.path.child(e.name), e)
        } catch (t: Throwable) { freeChain(c); throw t }
    }

    override fun delete(node: FsNode) {
        check(!closed); requireWritable()
        val l = locate(node.path); val e = l.entry ?: throw FsException("cannot delete root")
        if (e.isDirectory && readDir(l.path, e).isNotEmpty()) throw FsException("directory not empty: ${node.path}")
        markDeleted(e)               // entry first: a crash leaves lost clusters (fsck-fixable), never a dangling entry
        if (e.firstCluster >= 2) freeChain(e.firstCluster)
        invalidate()
    }

    override fun rename(node: FsNode, newName: String): FsNode {
        check(!closed); requireWritable()
        val l = locate(node.path); val e = l.entry ?: throw FsException("cannot rename root")
        return relocate(l, e, parentOf(node.path), newName)
    }

    override fun move(node: FsNode, newParent: FsNode): FsNode {
        check(!closed); requireWritable()
        val l = locate(node.path); val e = l.entry ?: throw FsException("cannot move root")
        val np = locate(newParent.path); if (np.entry != null && !np.entry.isDirectory) throw FsNotDirectoryException(newParent.path)
        if (e.isDirectory && (np.path == l.path || np.path.segments.take(l.path.segments.size) == l.path.segments)) throw FsException("cannot move a directory into itself")
        return relocate(l, e, np, e.name)
    }

    private fun relocate(l: Located, e: DirEntry, target: Located, name: String): FsNode {
        ShortName.validate(name)
        val sameDir = target.path == l.path.parent
        val clash = readDir(target.path, target.entry).firstOrNull { (it.name.equals(name, true) || it.shortName.equals(name, true)) && !(sameDir && it.shortOffset == e.shortOffset) }
        if (clash != null) throw FsExistsException(target.path.child(name))
        // Same directory & only case/LFN differs: delete first so the short name can be reused, then add (crash window noted in ADR).
        val saved = if (sameDir) markDeleted(e) else null
        val created = try { addEntryClone(target, name, e) } catch (t: Throwable) { if (saved != null) restore(e, saved); throw t }
        if (!sameDir) markDeleted(e)
        if (e.isDirectory && !sameDir && e.firstCluster >= 2) {
            val dd = readStream(e.firstCluster).copyOfRange(32, 64)
            val p = if (target.entry == null) 0L else target.entry.firstCluster
            dd[20] = (p shr 16).toByte(); dd[21] = (p shr 24).toByte(); dd[26] = p.toByte(); dd[27] = (p shr 8).toByte()
            writeStream(e.firstCluster, 32, dd)
        }
        invalidate()
        return node(target.path.child(created.name), created)
    }

    private fun restore(e: DirEntry, saved: ByteArray) {
        for (i in saved.indices) writeStream(e.parentFirst, e.startOffset + i * 32, byteArrayOf(saved[i]))
        invalidate()
    }

    private fun addEntryClone(target: Located, name: String, e: DirEntry): DirEntry {
        val created = addEntry(target.path, target.entry, name, e.attr, e.firstCluster, if (e.isDirectory) 0 else e.size)
        // preserve original timestamps/size by rewriting the fixed fields
        val raw = readStream(created.parentFirst).copyOfRange(created.shortOffset, created.shortOffset + 32)
        val old = readStream(e.parentFirst).copyOfRange(e.shortOffset, e.shortOffset + 32)
        for (i in 13..19) raw[i] = old[i]; for (i in 22..25) raw[i] = old[i]
        writeStream(created.parentFirst, created.shortOffset, raw)
        invalidate()
        return DirParser.parse(readStream(created.parentFirst), zone).first { it.shortOffset == created.shortOffset }.also { it.parentFirst = created.parentFirst }
    }

    // ---------------------------------------------------------------- files
    override fun open(node: FsNode, mode: OpenMode): FsFile {
        check(!closed)
        if (mode != OpenMode.READ) requireWritable()
        val l = locate(node.path); val e = l.entry ?: throw FsIsDirectoryException(node.path)
        if (e.isDirectory) throw FsIsDirectoryException(node.path)
        val clusters = if (e.size == 0L) ArrayList<Long>() else chain(e.firstCluster, (e.size + bpb.clusterBytes - 1) / bpb.clusterBytes)
        if (clusters.size.toLong() * bpb.clusterBytes < e.size) throw FsCorruptException("chain shorter than size for ${node.path}")
        return FatFile(e, clusters, mode == OpenMode.READ_WRITE)
    }

    private inner class FatFile(private val entry: DirEntry, private val clusters: MutableList<Long>, private val writable: Boolean) : FsFile {
        private val cb = bpb.clusterBytes
        private val buf = ByteArray(cb)
        override var size: Long = entry.size
            private set
        private var dirty = false
        private var closed = false

        override fun read(position: Long, dst: ByteArray, off: Int, len: Int): Int {
            check(!closed)
            require(off >= 0 && len >= 0 && off + len <= dst.size)
            if (position >= size) return -1
            val n = minOf(len.toLong(), size - position).toInt(); var done = 0
            while (done < n) {
                val pos = position + done; val ci = (pos / cb).toInt(); val co = (pos % cb).toInt()
                if (co == 0 && n - done >= cb) {
                    var run = 1; while (ci + run < clusters.size && (n - done) >= (run + 1) * cb && clusters[ci + run] == clusters[ci + run - 1] + 1) run++
                    dev.readSectors(bpb.clusterFirstSector(clusters[ci]), dst, off + done, run * bpb.sectorsPerCluster); done += run * cb; continue
                }
                val take = minOf(n - done, cb - co)
                dev.readSectors(bpb.clusterFirstSector(clusters[ci]), buf, 0, bpb.sectorsPerCluster)
                System.arraycopy(buf, co, dst, off + done, take); done += take
            }
            return n
        }

        /** Grows the chain to cover [bytes]; new clusters are zeroed except those [skipZeroFrom, skipZeroTo) fully overwritten by the caller. */
        private fun grow(bytes: Long, fullWriteFrom: Long = Long.MAX_VALUE, fullWriteTo: Long = Long.MIN_VALUE) {
            val need = ((bytes + cb - 1) / cb).toInt()
            val add = need - clusters.size
            if (add <= 0) return
            val firstIdx = clusters.size
            val fresh = allocClusters(add, clusters.lastOrNull() ?: 0L)
            if (clusters.isEmpty()) entryFirst = fresh[0]
            for ((i, c) in fresh.withIndex()) {
                val lo = (firstIdx + i).toLong() * cb
                if (!(fullWriteFrom <= lo && lo + cb <= fullWriteTo)) zeroCluster(c)
            }
            clusters += fresh
        }
        private var entryFirst: Long = entry.firstCluster

        private fun zeroRange(from: Long, to: Long) { // bytes inside already-allocated clusters
            var p = from
            while (p < to) {
                val ci = (p / cb).toInt(); val co = (p % cb).toInt(); val n = minOf(to - p, (cb - co).toLong()).toInt()
                dev.readSectors(bpb.clusterFirstSector(clusters[ci]), buf, 0, bpb.sectorsPerCluster)
                java.util.Arrays.fill(buf, co, co + n, 0); dev.writeSectors(bpb.clusterFirstSector(clusters[ci]), buf, 0, bpb.sectorsPerCluster)
                p += n
            }
        }

        override fun write(position: Long, src: ByteArray, off: Int, len: Int) {
            check(!closed); if (!writable) throw FsReadOnlyException()
            require(off >= 0 && len >= 0 && off + len <= src.size && position >= 0)
            if (len == 0) return
            val end = position + len
            if (end > 0xFFFFFFFFL) throw FsNoSpaceException()
            if (position > size) { // gap: expose zeros, never stale bytes
                val clustersBefore = clusters.size
                if (size % cb != 0L && clustersBefore > 0) zeroRange(size, minOf((size / cb + 1) * cb, position))
                grow(position)
            } else if (size % cb != 0L) { /* tail of last cluster beyond size is only exposed when growing; handled below */ }
            val before = clusters.size
            // bytes between old size and write start within an existing cluster must be zero if position > size (handled), else contiguous.
            grow(end, (position + cb - 1) / cb * cb, end / cb * cb)
            var done = 0
            while (done < len) {
                val pos = position + done; val ci = (pos / cb).toInt(); val co = (pos % cb).toInt()
                if (co == 0 && len - done >= cb) { // whole clusters: coalesce a contiguous run into one device call
                    var run = 1; while (ci + run < clusters.size && (len - done) >= (run + 1) * cb && clusters[ci + run] == clusters[ci + run - 1] + 1) run++
                    dev.writeSectors(bpb.clusterFirstSector(clusters[ci]), src, off + done, run * bpb.sectorsPerCluster); done += run * cb; continue
                }
                val take = minOf(len - done, cb - co); val sec = bpb.clusterFirstSector(clusters[ci])
                dev.readSectors(sec, buf, 0, bpb.sectorsPerCluster); System.arraycopy(src, off + done, buf, co, take)
                dev.writeSectors(sec, buf, 0, bpb.sectorsPerCluster); done += take
            }
            if (end > size) size = end
            dirty = true
            if (before < 0) throw IllegalStateException()
        }

        override fun truncate(newSize: Long) {
            check(!closed); if (!writable) throw FsReadOnlyException()
            require(newSize >= 0)
            if (newSize == size) return
            if (newSize > size) { if (size % cb != 0L) zeroRange(size, minOf((size / cb + 1) * cb, newSize)); grow(newSize) }
            else {
                val keep = ((newSize + cb - 1) / cb).toInt()
                if (keep < clusters.size) {
                    val drop = clusters.subList(keep, clusters.size).toList()
                    if (keep == 0) { entryFirst = 0 } else setFatEntry(clusters[keep - 1], eoc)
                    ensureFreeCount(); for (c in drop) { setFatEntry(c, 0); freeCount++; if (c < nextFree) nextFree = c }
                    while (clusters.size > keep) clusters.removeAt(clusters.size - 1)
                }
            }
            size = newSize; dirty = true
        }

        override fun flush() {
            if (!writable || !dirty) return
            val raw = readStream(entry.parentFirst).copyOfRange(entry.shortOffset, entry.shortOffset + 32)
            val first = if (clusters.isEmpty()) 0L else entryFirst
            raw[20] = (first shr 16).toByte(); raw[21] = (first shr 24).toByte(); raw[26] = first.toByte(); raw[27] = (first shr 8).toByte()
            for (i in 0..3) raw[28 + i] = (size shr (8 * i)).toByte()
            val (d, t) = fatDateTime(clock())
            raw[22] = t.toByte(); raw[23] = (t shr 8).toByte(); raw[24] = d.toByte(); raw[25] = (d shr 8).toByte(); raw[18] = d.toByte(); raw[19] = (d shr 8).toByte()
            writeStream(entry.parentFirst, entry.shortOffset, raw)
            invalidate(); dirty = false
        }

        override fun close() { if (closed) return; flush(); closed = true; buf.fill(0) }
    }

    override fun spaceInfo(): SpaceInfo { ensureFreeCount(); return SpaceInfo(bpb.clusterCount * bpb.clusterBytes, freeCount * bpb.clusterBytes) }

    override fun sync() {
        if (!readOnlyMode && bpb.type == FatType.FAT32 && bpb.fsInfoSector > 0) {
            val s = ByteArray(bpb.bytesPerSector); dev.readSectors(bpb.fsInfoSector.toLong(), s, 0, 1)
            fun u32(o: Int) = (s[o].toLong() and 0xff) or ((s[o + 1].toLong() and 0xff) shl 8) or ((s[o + 2].toLong() and 0xff) shl 16) or ((s[o + 3].toLong() and 0xff) shl 24)
            if (u32(0) == 0x41615252L && u32(484) == 0x61417272L) {
                ensureFreeCount()
                fun p32(o: Int, v: Long) { for (i in 0..3) s[o + i] = (v shr (8 * i)).toByte() }
                p32(488, freeCount); p32(492, nextFree); dev.writeSectors(bpb.fsInfoSector.toLong(), s, 0, 1)
            }
        }
        dev.flush()
    }

    override fun close() {
        if (closed) return
        try { sync() } finally {
            closed = true
            sectorCache.values.forEach { it.fill(0) }; sectorCache.clear(); dirCache.clear()
            dev.close()
        }
    }
}
