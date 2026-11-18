package org.openvault.cli

import org.openvault.crypto.Prf
import org.openvault.fs.*
import org.openvault.fs.fat.FatFileSystem
import org.openvault.io.RandomAccessStorage
import org.openvault.io.checkRange
import org.openvault.vault.VaultOpener
import org.openvault.vault.VaultResult
import java.io.File
import java.io.InputStream
import java.io.OutputStream
import java.io.PrintStream
import java.io.RandomAccessFile

/** Desktop debugging CLI (PRD §4.2). Read-only. Never prints secrets. */
class FileRandomAccessStorage(file: File) : RandomAccessStorage {
    private val raf = RandomAccessFile(file, "r")
    override val size get() = raf.length()
    override val isReadOnly = true
    override fun read(position: Long, dst: ByteArray, off: Int, len: Int) { checkRange(position, off, len, dst.size, size); raf.seek(position); raf.readFully(dst, off, len) }
    override fun write(position: Long, src: ByteArray, off: Int, len: Int) = throw java.io.IOException("read-only")
    override fun flush() {}
    override fun close() = raf.close()
}

private const val USAGE = """usage: openvault <command> <container> [path] [options]
commands:
  info  <container>              show volume and filesystem details
  ls    <container> [path]       list a directory
  cat   <container> <path>       write a file to stdout
  get   <container> <path> <dst> copy a file out (UNENCRYPTED copy!)
options:
  --password-stdin   read the password from the first line of stdin (preferred)
  -p <password>      password on the command line (visible in process list!)
  -k <keyfile>       keyfile (repeatable)
  --pim <n>          personal iterations multiplier
  --prf <name>       sha512|sha256|blake2s|whirlpool|streebog (default: auto-detect)
"""

fun run(args: List<String>, stdin: InputStream, out: OutputStream, err: PrintStream): Int {
    val o = PrintStream(out, false, "UTF-8")
    try {
        if (args.size < 2 || args[0] in setOf("-h", "--help")) { err.print(USAGE); return 2 }
        val cmd = args[0]; val container = File(args[1])
        val pos = ArrayList<String>(); var pw: String? = null; var pwStdin = false; var pim = 0
        val kfs = ArrayList<File>(); var prfs: List<Prf> = Prf.entries
        var i = 2
        while (i < args.size) {
            when (val a = args[i]) {
                "--password-stdin" -> pwStdin = true
                "-p" -> pw = args.getOrNull(++i) ?: return fail(err, "missing value for -p")
                "-k" -> kfs += File(args.getOrNull(++i) ?: return fail(err, "missing value for -k"))
                "--pim" -> pim = args.getOrNull(++i)?.toIntOrNull() ?: return fail(err, "invalid --pim")
                "--prf" -> { val n = args.getOrNull(++i)?.lowercase(); prfs = listOf(Prf.entries.firstOrNull { it.name.lowercase() == n } ?: return fail(err, "unknown prf: $n")) }
                else -> if (a.startsWith("-")) return fail(err, "unknown option: $a") else pos += a
            }
            i++
        }
        if (cmd !in setOf("info", "ls", "cat", "get")) return fail(err, "unknown command: $cmd")
        if (!container.isFile) return fail(err, "no such file: $container")
        if (pwStdin) pw = generateSequence { stdin.read().takeIf { it >= 0 && it != '\n'.code } }.toList().let { String(ByteArray(it.size) { k -> it[k].toByte() }, Charsets.UTF_8) }.trimEnd('\r')
        if (pw == null) return fail(err, "no password: use --password-stdin or -p")
        val password = pw.toByteArray(Charsets.UTF_8)
        val result = try {
            VaultOpener.open(FileRandomAccessStorage(container), password, pim, kfs.map { it.inputStream().buffered() }, prfs)
        } finally { password.fill(0) }
        when (result) {
            is VaultResult.Failed -> return fail(err, "Incorrect password, PIM, keyfiles or unsupported settings")
            is VaultResult.Cancelled -> return fail(err, "cancelled")
            is VaultResult.UnsupportedFilesystem -> return fail(err, "Unsupported filesystem (${result.kind})")
            is VaultResult.Opened -> result.fileSystem.use { fs -> return execute(cmd, pos, result, fs, o, out, err) }
        }
    } catch (e: FsException) { return fail(err, e.message ?: "filesystem error") }
    finally { o.flush() }
}

private fun execute(cmd: String, pos: List<String>, r: VaultResult.Opened, fs: FileSystem, o: PrintStream, raw: OutputStream, err: PrintStream): Int {
    when (cmd) {
        "info" -> {
            val v = r.volume; val sp = fs.spaceInfo()
            o.println("volume:     ${if (r.isHidden) "hidden" else "normal"}${if (r.usedBackupHeader) " (opened with BACKUP header)" else ""}")
            o.println("cipher:     AES-256-XTS")
            o.println("prf:        ${r.prf.displayName}")
            o.println("size:       ${v.sectorCount * v.sectorSize} bytes")
            o.println("filesystem: ${(fs as? FatFileSystem)?.type ?: "unknown"}")
            o.println("label:      ${fs.label ?: "-"}")
            o.println("space:      ${sp.freeBytes} free of ${sp.totalBytes} bytes")
            o.println("mode:       ${if (fs.isReadOnly) "read-only" else "read-write"}")
        }
        "ls" -> {
            val dir = fs.resolve(FsPath.parse(pos.getOrElse(0) { "/" }))
            for (n in fs.list(dir).sortedWith(compareBy({ !it.isDirectory }, { it.name.lowercase() })))
                o.println("${if (n.isDirectory) "d" else "-"} ${n.size.toString().padStart(10)} ${n.modified?.toString()?.take(19)?.replace('T', ' ') ?: "-".padEnd(19)} ${n.name}${if (n.isDirectory) "/" else ""}")
        }
        "cat", "get" -> {
            if (pos.isEmpty() || (cmd == "get" && pos.size < 2)) return fail(err, "missing path argument")
            val node = fs.resolve(FsPath.parse(pos[0]))
            val sink = if (cmd == "cat") raw else File(pos[1]).outputStream()
            try { fs.open(node, OpenMode.READ).use { f -> val buf = ByteArray(64 * 1024); var p = 0L
                while (true) { val n = f.read(p, buf, 0, buf.size); if (n < 0) break; sink.write(buf, 0, n); p += n } } }
            finally { if (cmd == "get") sink.close() else sink.flush() }
        }
    }
    return 0
}

private fun fail(err: PrintStream, m: String): Int { err.println("error: $m"); return 1 }

fun main(args: Array<String>) { System.exit(run(args.toList(), System.`in`, System.out, System.err)) }
