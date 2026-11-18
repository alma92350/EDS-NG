package org.openvault.app

import android.app.Activity
import android.app.AlertDialog
import android.content.Context
import android.view.View
import android.view.WindowManager
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import org.openvault.veracrypt.HiddenVolumeProtectionException

fun Activity.secure() { window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE) }
fun Context.dp(v: Int) = (v * resources.displayMetrics.density).toInt()
fun Context.toast(m: String) = Toast.makeText(this, m, Toast.LENGTH_LONG).show()

fun Activity.pad(v: View, dp: Int = 16): View { v.setPadding(dp(dp), dp(dp), dp(dp), dp(dp)); return v }

fun Activity.reportError(t: Throwable) {
    var c: Throwable? = t
    while (c != null) {
        if (c is HiddenVolumeProtectionException) {
            AlertDialog.Builder(this).setTitle("Write refused").setMessage("This write would have overwritten the hidden volume. The vault is now read-only; nothing was damaged. Lock and unlock again to continue reading.").setPositiveButton("OK", null).show()
            return
        }
        c = c.cause
    }
    toast(t.message ?: t.javaClass.simpleName)
}

fun Activity.prompt(title: String, initial: String = "", ok: String = "OK", onOk: (String) -> Unit) {
    val e = EditText(this).apply { setText(initial); setSingleLine(); selectAll() }
    val box = LinearLayout(this).apply { setPadding(dp(20), dp(8), dp(20), 0); addView(e, LinearLayout.LayoutParams(-1, -2)) }
    AlertDialog.Builder(this).setTitle(title).setView(box).setNegativeButton("Cancel", null).setPositiveButton(ok) { _, _ -> onOk(e.text.toString()) }.show()
}

fun label(ctx: Context, text: String, sizeSp: Float = 14f) = TextView(ctx).apply { this.text = text; textSize = sizeSp }

/** API 26 constants/methods missing from the API 23 compile stubs (they exist on every supported device, minSdk 26). */
const val IME_NO_PERSONALIZED_LEARNING = 0x1000000
fun View.noAutofill() { runCatching { View::class.java.getMethod("setImportantForAutofill", Int::class.javaPrimitiveType).invoke(this, 2) } }
