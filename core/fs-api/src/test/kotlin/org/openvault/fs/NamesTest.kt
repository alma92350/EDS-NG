package org.openvault.fs

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class NamesTest {
    @Test fun `free name is unchanged`() = assertEquals("a.txt", Names.keepBoth("a.txt", listOf("b.txt")))
    @Test fun `conflict gets a counter before the extension`() = assertEquals("a (1).txt", Names.keepBoth("a.txt", listOf("A.TXT")))
    @Test fun `counter skips taken names`() = assertEquals("a (3).txt", Names.keepBoth("a.txt", listOf("a.txt", "a (1).txt", "A (2).TXT")))
    @Test fun `no extension and dotfiles`() { assertEquals("README (1)", Names.keepBoth("README", listOf("readme"))); assertEquals(".bashrc (1)", Names.keepBoth(".bashrc", listOf(".bashrc"))) }
    @Test fun `sizes`() { assertEquals("0 B", Names.size(0)); assertEquals("1023 B", Names.size(1023)); assertEquals("1.0 KB", Names.size(1024)); assertEquals("1.5 MB", Names.size(1572864)) }
}
