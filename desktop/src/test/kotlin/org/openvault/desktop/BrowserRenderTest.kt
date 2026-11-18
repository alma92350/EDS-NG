package org.openvault.desktop

import com.google.gson.JsonParser
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.awt.image.BufferedImage
import java.io.File
import java.nio.file.Path
import javax.imageio.ImageIO
import javax.swing.SwingUtilities

/** Headless smoke test: the browser panel builds against a real vault, lists it, and paints non-blank output (PNG saved in target/). */
class BrowserRenderTest {
    @Test fun `browser panel lists a real vault and renders`(@TempDir t: Path) {
        System.setProperty("java.awt.headless", "true")
        val dir = File("../testing/fixtures"); val cat = JsonParser.parseString(File(dir, "fixtures.json").readText()).asJsonObject
        val f = File(t.toFile(), "c.hc"); File(dir, cat["aes_sha512_fat"].asJsonObject["file"].asString).copyTo(f)
        val s = (Unlocker.open(UnlockRequest(f, "test".toCharArray(), readOnly = false)) as UnlockOutcome.Opened).session
        var panel: BrowserPanel? = null
        SwingUtilities.invokeAndWait { panel = BrowserPanel(s) }
        s.sync { 0 } // vault thread idle => the initial listing has been computed
        SwingUtilities.invokeAndWait { } // flush the event queue: listing delivered
        val p = panel!!
        val img = BufferedImage(900, 520, BufferedImage.TYPE_INT_RGB)
        SwingUtilities.invokeAndWait { p.addNotify(); p.setSize(900, 520); p.validate(); p.doLayout(); p.validate()
            val g = img.createGraphics(); g.color = java.awt.Color.WHITE; g.fillRect(0, 0, 900, 520); p.paintAll(g); g.dispose() }
        val out = File("target/browser-render.png"); out.parentFile.mkdirs(); ImageIO.write(img, "png", out)
        val distinct = (0 until 900 step 7).flatMap { x -> (0 until 520 step 7).map { y -> img.getRGB(x, y) } }.toSet().size
        assertTrue(distinct > 5, "rendered image looks blank ($distinct colours)")
        s.lock()
    }
}
