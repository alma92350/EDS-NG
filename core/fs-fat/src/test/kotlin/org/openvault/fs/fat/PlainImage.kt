package org.openvault.fs.fat

import com.google.gson.JsonParser
import org.openvault.io.BlockDevice
import java.io.File

/** Treats a plain (unencrypted) FAT image file as a block device. */
class ImageDevice(val data: ByteArray, override val sectorSize: Int = 512) : BlockDevice {
    override val sectorCount get() = data.size.toLong() / sectorSize
    override val isReadOnly = false
    override fun readSectors(firstSector: Long, dst: ByteArray, off: Int, count: Int) = System.arraycopy(data, (firstSector * sectorSize).toInt(), dst, off, count * sectorSize)
    override fun writeSectors(firstSector: Long, src: ByteArray, off: Int, count: Int) = System.arraycopy(src, off, data, (firstSector * sectorSize).toInt(), count * sectorSize)
    override fun flush() {}
    override fun close() {}
}

object Fixtures {
    val dir = File("../../testing/fixtures")
    val catalog = JsonParser.parseString(File(dir, "plain_fixtures.json").readText()).asJsonObject
    fun image(name: String) = File(dir, catalog[name].asJsonObject["file"].asString).readBytes()
    fun hashes(name: String): Map<String, String> = catalog[name].asJsonObject["files"].asJsonObject.entrySet().associate { it.key to it.value.asString }
    fun sizes(name: String): Map<String, Int> = catalog[name].asJsonObject["sizes"].asJsonObject.entrySet().associate { it.key to it.value.asInt }
}
