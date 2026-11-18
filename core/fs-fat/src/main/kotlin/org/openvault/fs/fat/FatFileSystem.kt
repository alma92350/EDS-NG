package org.openvault.fs.fat

import org.openvault.fs.*
import org.openvault.io.BlockDevice
import java.time.ZoneId

/** FAT12/16/32 driver. M3: read-only; all mutating calls throw [FsReadOnlyException]. Not thread-safe. */
class FatFileSystem(private val dev: BlockDevice, private val zone: ZoneId = ZoneId.systemDefault()) : FileSystem {
    val bpb: Bpb
    private val sectorCache = object : LinkedHashMap<Long, ByteArray>(64, 0.75f, true) {
        override fun removeEldestEntry(e: MutableMap.MutableEntry<Long, ByteArray>) = size > 128
    }
    private val dirCache = HashMap<FsPath, List<DirEntry>>()
    private val entries = HashMap<FsPath, DirEntry>()
    private var closed = false

    init {
        require(dev.sectorSize >= 512)
        val boot = ByteArray(dev.sectorSize); dev.readSectors(0, boot, 0, 1)
        bpb = Bpb.parse(boot)
        if (bpb.bytesPerSector != dev.sectorSize) throw FsCorruptException("BPB sector size ${bpb.bytesPerSector} != device ${dev.sectorSize}")
        if (bpb.totalSectors > dev.sectorCount) throw FsCorruptException("filesystem larger than device")
    }

    val type get() = bpb.type
    override val label: String? get() = bpb.label
    override val isReadOnly get() = true

    private fun sector(n: Long): ByteArray = sectorCache.getOrPut(n) { ByteArray(bpb.bytesPerSector).also { dev.readSectors(n, it, 0, 1) } }

    private fun fatEntry(cluster: Long): Long {
        val off = when (bpb.type) { FatType.FAT12 -> cluster + cluster / 2; FatType.FAT16 -> cluster * 2; FatType.FAT32 -> cluster * 4 }
        fun byteAt(o: Long): Int = sector(bpb.fatStartSector + o / bpb.bytesPerSector)[(o % bpb.bytesPerSector).toInt()].toInt() and 0xff
        return when (bpb.type) {
            FatType.FAT12 -> { val v = byteAt(off) or (byteAt(off + 1) shl 8); (if (cluster and 1L == 0L) v and 0xfff else v shr 4).toLong() }
            FatType.FAT16 -> (byteAt(off) or (byteAt(off + 1) shl 8)).toLong()
            FatType.FAT32 -> (byteAt(off).toLong() or (byteAt(off + 1).toLong() shl 8) or (byteAt(off + 2).toLong() shl 16) or (byteAt(off + 3).toLong() shl 24)) and 0x0FFFFFFFL
        }
    }

    private fun isEnd(v: Long) = when (bpb.type) { FatType.FAT12 -> v >= 0xFF8; FatType.FAT16 -> v >= 0xFFF8; FatType.FAT32 -> v >= 0x0FFFFFF8 }
    private fun isBad(v: Long) = when (bpb.type) { FatType.FAT12 -> v == 0xFF7L; FatType.FAT16 -> v == 0xFFF7L; FatType.FAT32 -> v == 0x0FFFFFF7L }

    /** Cluster chain from [first]; [limit] caps the number of clusters (loop guard / size bound). */
    private fun chain(first: Long, limit: Long = bpb.clusterCount): LongArray {
        if (first < 2) return LongArray(0)
        val out = ArrayList<Long>(); var c = first
        while (true) {
            if (c < 2 || c >= bpb.clusterCount + 2) throw FsCorruptException("cluster $c out of range")
            out += c
            if (out.size > limit) throw FsCorruptException("cluster chain loop")
            val n = fatEntry(c)
            if (isEnd(n)) break
            if (isBad(n) || n < 2) throw FsCorruptException("bad cluster in chain at $c")
            c = n
        }
        return out.toLongArray()
    }

    private fun readClusters(clusters: LongArray): ByteArray {
        val out = ByteArray(clusters.size * bpb.clusterBytes)
        for ((i, c) in clusters.withIndex()) dev.readSectors(bpb.clusterFirstSector(c), out, i * bpb.clusterBytes, bpb.sectorsPerCluster)
        return out
    }

    private fun readDir(path: FsPath, e: DirEntry?): List<DirEntry> = dirCache.getOrPut(path) {
        val raw = if (e == null && bpb.type != FatType.FAT32) {
            ByteArray(bpb.rootDirSectors * bpb.bytesPerSector).also { dev.readSectors(bpb.rootDirStartSector, it, 0, bpb.rootDirSectors) }
        } else readClusters(chain(e?.firstCluster ?: bpb.rootCluster))
        DirParser.parse(raw, zone).also { list -> list.forEach { entries[path.child(it.name)] = it } }
    }

    private fun node(path: FsPath, e: DirEntry) = FsNode(path, e.name, e.isDirectory, e.size, e.modified, e.created)
    override fun root() = FsNode(FsPath.ROOT, "", true, 0, null, null)

    private fun dirEntryOf(p: FsPath): DirEntry? { // null = root
        if (p.isRoot) return null
        var cur = FsPath.ROOT; var curEntry: DirEntry? = null
        for (seg in p.segments) {
            val list = readDir(cur, curEntry)
            val hit = list.firstOrNull { it.name.equals(seg, ignoreCase = true) || it.shortName.equals(seg, ignoreCase = true) } ?: throw FsNotFoundException(p)
            val next = cur.child(hit.name)
            cur = next; curEntry = hit
            if (!hit.isDirectory && next.segments.size < p.segments.size) throw FsNotDirectoryException(next)
        }
        return curEntry
    }

    override fun resolve(path: FsPath): FsNode {
        check(!closed)
        val e = dirEntryOf(path) ?: return root()
        return node(canonical(path), e)
    }

    private fun canonical(p: FsPath): FsPath {
        var cur = FsPath.ROOT; var ce: DirEntry? = null
        for (seg in p.segments) { val hit = readDir(cur, ce).first { it.name.equals(seg, true) || it.shortName.equals(seg, true) }; cur = cur.child(hit.name); ce = hit }
        return cur
    }

    override fun list(dir: FsNode): List<FsNode> {
        check(!closed)
        val e = dirEntryOf(dir.path)
        if (e != null && !e.isDirectory) throw FsNotDirectoryException(dir.path)
        val cp = canonical(dir.path)
        return readDir(cp, e).map { node(cp.child(it.name), it) }
    }

    override fun open(node: FsNode, mode: OpenMode): FsFile {
        check(!closed)
        if (mode != OpenMode.READ) throw FsReadOnlyException()
        val e = dirEntryOf(node.path) ?: throw FsIsDirectoryException(node.path)
        if (e.isDirectory) throw FsIsDirectoryException(node.path)
        val clusters = if (e.size == 0L) LongArray(0) else chain(e.firstCluster, (e.size + bpb.clusterBytes - 1) / bpb.clusterBytes)
        if (clusters.size.toLong() * bpb.clusterBytes < e.size) throw FsCorruptException("chain shorter than size for ${node.path}")
        return ReadFile(e.size, clusters)
    }

    private inner class ReadFile(override val size: Long, private val clusters: LongArray) : FsFile {
        private val cb = bpb.clusterBytes
        private val buf = ByteArray(cb)
        override fun read(position: Long, dst: ByteArray, off: Int, len: Int): Int {
            require(off >= 0 && len >= 0 && off + len <= dst.size)
            if (position >= size) return -1
            val n = minOf(len.toLong(), size - position).toInt()
            var done = 0
            while (done < n) {
                val pos = position + done
                val ci = (pos / cb).toInt(); val co = (pos % cb).toInt()
                val take = minOf(n - done, cb - co)
                dev.readSectors(bpb.clusterFirstSector(clusters[ci]), buf, 0, bpb.sectorsPerCluster)
                System.arraycopy(buf, co, dst, off + done, take)
                done += take
            }
            return n
        }
        override fun write(position: Long, src: ByteArray, off: Int, len: Int) = throw FsReadOnlyException()
        override fun truncate(newSize: Long) = throw FsReadOnlyException()
        override fun flush() {}
        override fun close() { buf.fill(0) }
    }

    override fun spaceInfo(): SpaceInfo {
        var free = 0L
        for (c in 2L until bpb.clusterCount + 2) if (fatEntry(c) == 0L) free++
        return SpaceInfo(bpb.clusterCount * bpb.clusterBytes, free * bpb.clusterBytes)
    }

    override fun createFile(dir: FsNode, name: String) = throw FsReadOnlyException()
    override fun createDirectory(dir: FsNode, name: String) = throw FsReadOnlyException()
    override fun rename(node: FsNode, newName: String) = throw FsReadOnlyException()
    override fun move(node: FsNode, newParent: FsNode) = throw FsReadOnlyException()
    override fun delete(node: FsNode) = throw FsReadOnlyException()
    override fun sync() {}

    override fun close() {
        if (closed) return
        closed = true
        sectorCache.values.forEach { it.fill(0) }; sectorCache.clear(); dirCache.clear(); entries.clear()
        dev.close()
    }
}
