package org.openvault.testkit

fun String.hex(): ByteArray {
    val s = filter { !it.isWhitespace() }
    require(s.length % 2 == 0)
    return ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
}

fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }
