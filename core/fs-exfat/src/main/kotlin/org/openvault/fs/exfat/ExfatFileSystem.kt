package org.openvault.fs.exfat

import org.openvault.fs.*
import org.openvault.io.BlockDevice
import java.time.Instant
import java.time.LocalDateTime
import java.time.ZoneId
import java.time.ZoneOffset

/**
 * Read-only exFAT driver, written from Microsoft's public exFAT specification (PRD §7.2).
 * Supports boot sector, FAT chains and the NoFatChain flag, directory entry sets with checksum validation,
 * long names. Case-insensitive lookup uses Java case folding (not the on-disk up-case table: documented limitation).
 */
class ExfatFileSystem(private val dev: BlockDevice, private val zone: ZoneId = ZoneId.systemDefault()) : FileSystem {
    private val bps: Int; private val spc: Int; private val cb: Int
    private val fatOffsetSectors: Long; private val heapOffsetSectors: Long; private val clusterCount: Long; private val rootCluster: Long
    private var closed = false
    private val dirCache = HashMap<FsPath, List<Entry>>()
    private val fatCache = HashMap<Long, ByteArray>()

    private class Entry(val name: String, val isDir: Boolean, val size: Long, val valid: Long, val first: Long, val contiguous: Boolean, val mod: Instant?, val created: Instant?)

    companion object {
        fun matches(boot: ByteArray) = boot.size >= 512 && String(boot, 3, 8, Charsets.ISO_8859_1) == "EXFAT   "
        private fun u16(b: ByteArray, o: Int) = (b[o].toInt() and 0xff) or ((b[o + 1].toInt() and 0xff) shl 8)
        private fun u32(b: ByteArray, o: Int) = u16(b, o).toLong() or (u16(b, o + 2).toLong() shl 16)
        private fun u64(b: ByteArray, o: Int) = u32(b, o) or (u32(b, o + 4) shl 32)
    }

    init {
        val b = ByteArray(dev.sectorSize); dev.readSectors(0, b, 0, 1)
        if (!matches(b)) throw UnsupportedFilesystemException("not exFAT")
        if (b[510].toInt() and 0xff != 0x55 || b[511].toInt() and 0xff != 0xAA) throw FsCorruptException("bad boot signature")
        val bShift = b[108].toInt() and 0xff; val sShift = b[109].toInt() and 0xff
        if (bShift < 9 || bShift > 12 || sShift > 25 - bShift) throw FsCorruptException("bad sector/cluster size")
        bps = 1 shl bShift; spc = 1 shl sShift; cb = bps * spc
        if (bps != dev.sectorSize) throw FsCorruptException("exFAT sector size $bps != device ${dev.sectorSize}")
        fatOffsetSectors = u32(b, 80); heapOffsetSectors = u32(b, 88); clusterCount = u32(b, 92); rootCluster = u32(b, 96)
        if (u64(b, 72) > dev.sectorCount) throw FsCorruptException("filesystem larger than device")
        if (rootCluster < 2 || rootCluster >= clusterCount + 2) throw FsCorruptException("bad root cluster")
        if (b[104].toInt() and 0xff != 0 || b[105].toInt() and 0xff != 1) { /* revision 1.0 expected; newer minor tolerated */ }
    }

    override val label: String? by lazy { try { rootLabel() } catch (e: Exception) { null } }
    override val isReadOnly get() = true

    private fun rootLabel(): String? {
        val raw = readStream(rootCluster, 0, false, true)
        var i = 0
        while (i + 32 <= raw.size && raw[i].toInt() != 0) {
            if ((raw[i].toInt() and 0xff) == 0x83) { val n = raw[i + 1].toInt() and 0xff; return String(raw, i + 2, n * 2, Charsets.UTF_16LE) }
            i += 32
        }
        return null
    }

    private fun fatNext(c: Long): Long {
        val sec = fatOffsetSectors + (c * 4) / bps
        val s = fatCache.getOrPut(sec) { ByteArray(bps).also { dev.readSectors(sec, it, 0, 1) } }
        return u32(s, ((c * 4) % bps).toInt())
    }

    private fun clusters(first: Long, size: Long, contiguous: Boolean): LongArray {
        if (first < 2) return LongArray(0)
        val need = if (size > 0) (size + cb - 1) / cb else Long.MAX_VALUE
        val out = ArrayList<Long>()
        if (contiguous) { for (i in 0 until need) { if (first + i >= clusterCount + 2) throw FsCorruptException("contiguous run beyond volume"); out += first + i } }
        else {
            var c = first
            while (true) {
                if (c < 2 || c >= clusterCount + 2) throw FsCorruptException("cluster $c out of range")
                out += c
                if (out.size > clusterCount) throw FsCorruptException("cluster chain loop")
                if (size > 0 && out.size >= need) break
                val n = fatNext(c)
                if (n == 0xFFFFFFFFL) break
                if (n == 0xFFFFFFF7L || n < 2) throw FsCorruptException("bad cluster in chain")
                c = n
            }
        }
        return out.toLongArray()
    }

    private fun clusterSector(c: Long) = heapOffsetSectors + (c - 2) * spc

    /** Reads a whole directory/file stream; [size]==0 with !contiguous means "follow FAT to end" (used for directories). */
    private fun readStream(first: Long, size: Long, contiguous: Boolean, untilEnd: Boolean = false): ByteArray {
        val cl = clusters(first, if (untilEnd) 0 else size, contiguous)
        val out = ByteArray(cl.size * cb)
        for ((i, c) in cl.withIndex()) dev.readSectors(clusterSector(c), out, i * cb, spc)
        return out
    }

    private fun checksum(raw: ByteArray, start: Int, count: Int): Int {
        var h = 0
        for (i in 0 until count * 32) { if (i == 2 || i == 3) continue; h = (((h and 1) shl 15) or (h ushr 1)) + (raw[start + i].toInt() and 0xff); h = h and 0xffff }
        return h
    }

    private fun ts(t: Long, tenMs: Int, tz: Int): Instant? {
        if (t == 0L) return null
        return try {
            val ldt = LocalDateTime.of(1980 + ((t shr 25).toInt() and 0x7f), ((t shr 21).toInt() and 0xf), ((t shr 16).toInt() and 0x1f), ((t shr 11).toInt() and 0x1f), ((t shr 5).toInt() and 0x3f), ((t and 0x1f).toInt()) * 2)
            val inst = if (tz and 0x80 != 0) { val off = (tz and 0x7f).let { if (it >= 64) it - 128 else it } * 15 * 60; ldt.toInstant(ZoneOffset.ofTotalSeconds(off)) } else ldt.atZone(zone).toInstant()
            inst.plusMillis((tenMs.coerceIn(0, 199)) * 10L)
        } catch (e: java.time.DateTimeException) { null }
    }

    private fun parseDir(raw: ByteArray): List<Entry> {
        val out = ArrayList<Entry>()
        var i = 0
        while (i + 32 <= raw.size) {
            val type = raw[i].toInt() and 0xff
            if (type == 0x00) break
            if (type == 0x85) {
                val sec = raw[i + 1].toInt() and 0xff
                if (sec < 2 || i + (sec + 1) * 32 > raw.size) throw FsCorruptException("truncated entry set")
                val stored = u16(raw, i + 2)
                if (stored != checksum(raw, i, sec + 1)) throw FsCorruptException("entry set checksum mismatch")
                if ((raw[i + 32].toInt() and 0xff) != 0xC0) throw FsCorruptException("missing stream extension")
                val flags = raw[i + 33].toInt() and 0xff; val nameLen = raw[i + 35].toInt() and 0xff
                val valid = u64(raw, i + 40); val first = u32(raw, i + 52); val size = u64(raw, i + 56)
                val sb = StringBuilder()
                for (k in 2..sec) { if ((raw[i + k * 32].toInt() and 0xff) != 0xC1) throw FsCorruptException("missing name entry"); sb.append(String(raw, i + k * 32 + 2, 30, Charsets.UTF_16LE)) }
                if (sb.length < nameLen) throw FsCorruptException("name shorter than declared")
                val attr = u16(raw, i + 4)
                val mod = ts(u32(raw, i + 12), raw[i + 21].toInt() and 0xff, raw[i + 23].toInt() and 0xff)
                val cr = ts(u32(raw, i + 8), raw[i + 20].toInt() and 0xff, raw[i + 22].toInt() and 0xff)
                out += Entry(sb.substring(0, nameLen), attr and 0x10 != 0, size, valid, first, flags and 0x02 != 0, mod, cr)
                i += (sec + 1) * 32
            } else i += 32
        }
        return out
    }

    private fun readDir(path: FsPath, e: Entry?): List<Entry> = dirCache.getOrPut(path) {
        if (e == null) parseDir(readStream(rootCluster, 0, false, true)) else parseDir(readStream(e.first, e.size, e.contiguous, !e.contiguous && e.size == 0L))
    }

    private class Loc(val path: FsPath, val entry: Entry?)
    private fun locate(p: FsPath): Loc {
        var cur = FsPath.ROOT; var ce: Entry? = null
        for ((i, seg) in p.segments.withIndex()) {
            if (ce != null && !ce.isDir) throw FsNotDirectoryException(cur)
            val hit = readDir(cur, ce).firstOrNull { it.name.equals(seg, ignoreCase = true) } ?: throw FsNotFoundException(p)
            cur = cur.child(hit.name); ce = hit
            if (!hit.isDir && i < p.segments.size - 1) throw FsNotDirectoryException(cur)
        }
        return Loc(cur, ce)
    }

    private fun node(path: FsPath, e: Entry) = FsNode(path, e.name, e.isDir, if (e.isDir) 0 else e.size, e.mod, e.created)
    override fun root() = FsNode(FsPath.ROOT, "", true, 0, null, null)
    override fun resolve(path: FsPath): FsNode { check(!closed); val l = locate(path); return l.entry?.let { node(l.path, it) } ?: root() }
    override fun list(dir: FsNode): List<FsNode> {
        check(!closed); val l = locate(dir.path)
        if (l.entry != null && !l.entry.isDir) throw FsNotDirectoryException(dir.path)
        return readDir(l.path, l.entry).map { node(l.path.child(it.name), it) }
    }

    override fun open(node: FsNode, mode: OpenMode): FsFile {
        check(!closed); if (mode != OpenMode.READ) throw FsReadOnlyException()
        val l = locate(node.path); val e = l.entry ?: throw FsIsDirectoryException(node.path)
        if (e.isDir) throw FsIsDirectoryException(node.path)
        val cl = if (e.size == 0L) LongArray(0) else clusters(e.first, e.size, e.contiguous)
        if (cl.size.toLong() * cb < e.size) throw FsCorruptException("chain shorter than size for ${node.path}")
        return object : FsFile {
            private val buf = ByteArray(cb)
            override val size = e.size
            override fun read(position: Long, dst: ByteArray, off: Int, len: Int): Int {
                require(off >= 0 && len >= 0 && off + len <= dst.size)
                if (position >= size) return -1
                val n = minOf(len.toLong(), size - position).toInt(); var done = 0
                while (done < n) {
                    val pos = position + done; val ci = (pos / cb).toInt(); val co = (pos % cb).toInt(); val take = minOf(n - done, cb - co)
                    if (pos >= e.valid) java.util.Arrays.fill(dst, off + done, off + done + take, 0) // beyond ValidDataLength reads as zero
                    else { dev.readSectors(clusterSector(cl[ci]), buf, 0, spc); System.arraycopy(buf, co, dst, off + done, take) }
                    done += take
                }
                return n
            }
            override fun write(position: Long, src: ByteArray, off: Int, len: Int) = throw FsReadOnlyException()
            override fun truncate(newSize: Long) = throw FsReadOnlyException()
            override fun flush() {}
            override fun close() { buf.fill(0) }
        }
    }

    override fun spaceInfo(): SpaceInfo {
        // allocation bitmap entry (0x81) in the root directory
        val raw = readStream(rootCluster, 0, false, true); var i = 0
        while (i + 32 <= raw.size && raw[i].toInt() != 0) {
            if ((raw[i].toInt() and 0xff) == 0x81) {
                val first = u32(raw, i + 20); val len = u64(raw, i + 24)
                val bm = readStream(first, len, false).let { if (it.size < len) it else it.copyOf(len.toInt()) }
                var used = 0L; for (c in 0 until clusterCount) if (bm[(c / 8).toInt()].toInt() shr (c % 8).toInt() and 1 != 0) used++
                return SpaceInfo(clusterCount * cb, (clusterCount - used) * cb)
            }
            i += 32
        }
        return SpaceInfo(clusterCount * cb, 0)
    }

    override fun createFile(dir: FsNode, name: String) = throw FsReadOnlyException()
    override fun createDirectory(dir: FsNode, name: String) = throw FsReadOnlyException()
    override fun rename(node: FsNode, newName: String) = throw FsReadOnlyException()
    override fun move(node: FsNode, newParent: FsNode) = throw FsReadOnlyException()
    override fun delete(node: FsNode) = throw FsReadOnlyException()
    override fun sync() {}
    override fun close() { if (closed) return; closed = true; dirCache.clear(); fatCache.clear(); dev.close() }
}
