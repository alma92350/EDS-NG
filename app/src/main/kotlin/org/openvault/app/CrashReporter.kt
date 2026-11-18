package org.openvault.app

import android.app.Activity
import android.app.Application
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.graphics.Typeface
import android.os.Build
import android.os.Bundle
import android.os.Process
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import java.io.PrintWriter
import java.io.StringWriter

/**
 * Test-build diagnostics: on an uncaught exception, show the stack trace in [CrashActivity] (separate process)
 * so it can be screenshotted/copied. The trace contains class/method names and device model only, no vault data.
 */
object CrashReporter {
    fun install(app: Application) {
        val previous = Thread.getDefaultUncaughtExceptionHandler()
        Thread.setDefaultUncaughtExceptionHandler { t, e ->
            try {
                val sw = StringWriter(); e.printStackTrace(PrintWriter(sw))
                val report = "OpenVault 0.1.0-test\nAndroid ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT}), ${Build.MANUFACTURER} ${Build.MODEL}\nthread: ${t.name}\n\n$sw"
                app.startActivity(Intent(app, CrashActivity::class.java).putExtra("report", report.take(12000)).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK))
            } catch (x: Throwable) { /* nothing more we can do */ }
            Process.killProcess(Process.myPid())
            previous?.uncaughtException(t, e)
        }
    }
}

class CrashActivity : Activity() {
    override fun onCreate(b: Bundle?) {
        super.onCreate(b)
        title = "OpenVault crashed"
        val report = intent.getStringExtra("report") ?: "(no report)"
        val tv = TextView(this).apply { text = report; typeface = Typeface.MONOSPACE; textSize = 11f; setTextIsSelectable(true); setPadding(24, 24, 24, 24) }
        val copy = Button(this).apply { text = "Copy report"; setOnClickListener { (getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager).setPrimaryClip(ClipData.newPlainText("crash", report)) } }
        val close = Button(this).apply { text = "Close"; setOnClickListener { finish() } }
        setContentView(LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            addView(copy); addView(close); addView(ScrollView(this@CrashActivity).apply { addView(tv) }, LinearLayout.LayoutParams(-1, 0, 1f))
        })
    }
}
