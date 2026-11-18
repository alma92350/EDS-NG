package org.openvault.app

import android.app.Activity
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.Typeface
import android.os.Bundle
import android.widget.ImageView
import android.widget.ScrollView
import android.widget.TextView
import org.openvault.fs.FsPath
import org.openvault.fs.OpenMode

/** Built-in viewer: images (decoded from memory) and text. No temp files are written. */
class ViewerActivity : Activity() {
    private val onLock: () -> Unit = { runOnUiThread { finish() } }
    private val imageExt = setOf("png", "jpg", "jpeg", "gif", "webp", "bmp")

    override fun onCreate(b: Bundle?) {
        super.onCreate(b); secure()
        val p = FsPath.parse(intent.getStringExtra("path") ?: "/")
        title = p.name
        if (Vault.session == null) { finish(); return }
        Vault.lockListeners.add(onLock)
        val isImage = p.name.substringAfterLast('.', "").lowercase() in imageExt
        val limit = if (isImage) 40L * 1024 * 1024 else 5L * 1024 * 1024
        Vault.io({
            val fs = Vault.session!!.fs
            fs.open(fs.resolve(p), OpenMode.READ).use { f ->
                if (f.size > limit) throw java.io.IOException("File too large for the built-in viewer (${f.size / 1048576} MB). Use Export instead.")
                ByteArray(f.size.toInt()).also { buf -> var q = 0; while (q < buf.size) { val n = f.read(q.toLong(), buf, q, buf.size - q); if (n < 0) break; q += n } }
            }
        }) { r ->
            r.onFailure { reportError(it); finish() }.onSuccess { bytes ->
                if (isImage) showImage(bytes) else if (bytes.take(4096).any { it.toInt() == 0 }) { toast("No built-in viewer for this file type. Use Export."); finish() } else showText(bytes)
            }
        }
    }

    private fun showImage(bytes: ByteArray) {
        val o = BitmapFactory.Options().apply { inJustDecodeBounds = true }; BitmapFactory.decodeByteArray(bytes, 0, bytes.size, o)
        var s = 1; while (o.outWidth / (s * 2) >= 2048 || o.outHeight / (s * 2) >= 2048) s *= 2
        val bmp: Bitmap? = BitmapFactory.decodeByteArray(bytes, 0, bytes.size, BitmapFactory.Options().apply { inSampleSize = s })
        if (bmp == null) { toast("Cannot decode this image"); finish(); return }
        setContentView(ImageView(this).apply { setImageBitmap(bmp); scaleType = ImageView.ScaleType.FIT_CENTER; setBackgroundColor(0xFF000000.toInt()) })
    }

    private fun showText(bytes: ByteArray) {
        val tv = TextView(this).apply { text = String(bytes, Charsets.UTF_8); typeface = Typeface.MONOSPACE; textSize = 13f; setTextIsSelectable(true); setPadding(dp(12), dp(12), dp(12), dp(12)) }
        setContentView(ScrollView(this).apply { addView(tv) })
    }

    override fun onDestroy() { Vault.lockListeners.remove(onLock); super.onDestroy() }
    override fun onUserInteraction() { Vault.activity() }
}
