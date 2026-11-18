package org.openvault.veracrypt

import com.google.gson.JsonObject
import com.google.gson.JsonParser
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource
import org.openvault.crypto.Prf
import org.openvault.crypto.VolumeMode
import org.openvault.testkit.MemoryStorage
import org.openvault.testkit.toHex
import java.io.ByteArrayInputStream
import java.io.File

/** TrueCrypt-mode containers (magic TRUE, header v4/v5, fixed 1000/2000 iterations, no PIM). */
class TrueCryptTest {
    private val dir = File("../../testing/fixtures")
    private val catalog: JsonObject = JsonParser.parseString(File(dir, "fixtures.json").readText()).asJsonObject
    private fun fx(n: String) = catalog[n].asJsonObject
    private fun bytes(n: String) = File(dir, fx(n)["file"].asString).readBytes()
    private fun prf(n: String) = Prf.entries.first { it.name.lowercase() == fx(n)["prf"].asString }

    private fun open(n: String, pw: String = fx(n)["password"].asString, mode: VolumeMode = VolumeMode.TRUECRYPT, prfs: List<Prf>? = null,
                     keyfiles: List<String> = fx(n)["keyfiles"].asJsonArray.map { it.asString }, storage: MemoryStorage = MemoryStorage(bytes(n))): OpenResult =
        VolumeOpener.open(storage, pw.toByteArray(), 0, keyfiles.map { ByteArrayInputStream(File(dir, it).readBytes()) }, prfs, mode = mode)

    @ParameterizedTest @ValueSource(strings = ["tc_ripemd160", "tc_sha512_v4", "tc_keyfile"])
    fun `truecrypt container opens with auto-detect and master key matches`(n: String) {
        val r = open(n) as OpenResult.Opened
        r.volume.use { v ->
            assertEquals(prf(n), r.prf); assertEquals(HeaderLocation.NORMAL, v.location)
            assertEquals(fx(n)["master_key_hex"].asString, v.header.keyMaterial.copyOf(64).toHex())
            assertEquals(if (n == "tc_sha512_v4") 4 else 5, v.header.version); assertEquals(512, v.sectorSize)
            val s = ByteArray(512); v.readSectors(0, s, 0, 1)
            assertEquals(0x55, s[510].toInt() and 0xff); assertEquals(0xAA, s[511].toInt() and 0xff)
        }
    }

    @ParameterizedTest @ValueSource(strings = ["tc_ripemd160", "tc_sha512_v4"])
    fun `truecrypt containers are not opened in veracrypt mode and veracrypt ones not in truecrypt mode`(n: String) {
        assertTrue(open(n, mode = VolumeMode.VERACRYPT, prfs = listOf(prf(n))) is OpenResult.Failed)
        assertTrue(open("aes_sha512_fat", mode = VolumeMode.TRUECRYPT, prfs = listOf(Prf.SHA512)) is OpenResult.Failed)
    }

    @Test fun `wrong password and missing keyfile fail`() {
        assertTrue(open("tc_ripemd160", pw = "nope") is OpenResult.Failed)
        assertTrue(open("tc_keyfile", keyfiles = emptyList()) is OpenResult.Failed)
    }

    @Test fun `truecrypt hash list is tried in order and is fast`() {
        val t0 = System.nanoTime()
        val r = open("tc_sha512_v4") as OpenResult.Opened; r.volume.close()
        assertTrue((System.nanoTime() - t0) < 3_000_000_000L, "TrueCrypt KDF has only 1000-2000 iterations")
        val failed = open("tc_ripemd160", pw = "wrong") as OpenResult.Failed
        assertEquals(HeaderSearchPlan.build(listOf(Prf.RIPEMD160, Prf.SHA512, Prf.WHIRLPOOL)), failed.tried)
    }

    @Test fun `hidden truecrypt volume and backup header`() {
        val h = fx("tc_hidden")["hidden"].asJsonObject
        (open("tc_hidden") as OpenResult.Opened).volume.use { assertEquals(HeaderLocation.NORMAL, it.location) }
        (open("tc_hidden", pw = h["password"].asString) as OpenResult.Opened).volume.use {
            assertEquals(HeaderLocation.HIDDEN, it.location); assertEquals(h["offset"].asLong, it.header.dataOffset)
        }
        val data = bytes("tc_ripemd160"); data.fill(0, 0, 512)
        (open("tc_ripemd160", storage = MemoryStorage(data)) as OpenResult.Opened).volume.use { assertEquals(HeaderLocation.BACKUP_NORMAL, it.location) }
    }
}
