package org.openvault.app

import android.app.Activity
import android.app.AlertDialog
import android.app.ProgressDialog
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.text.InputType
import android.view.Menu
import android.view.MenuItem
import android.view.View
import android.view.inputmethod.EditorInfo
import android.widget.*
import org.json.JSONArray
import org.json.JSONObject
import org.openvault.crypto.Prf
import org.openvault.crypto.SecretBytes
import org.openvault.vault.HiddenProtection
import org.openvault.vault.VaultOpener
import org.openvault.vault.VaultResult
import java.io.ByteArrayInputStream
import java.util.concurrent.atomic.AtomicBoolean

class MainActivity : Activity() {
    private class Rec(val uri: String, val name: String)
    private val recs = ArrayList<Rec>()
    private lateinit var list: ListView
    private lateinit var status: TextView
    private val keyfiles = ArrayList<Uri>()
    private var keyfileLabel: TextView? = null

    override fun onCreate(b: Bundle?) {
        super.onCreate(b); secure()
        Vault.policy.timeoutMs = prefs().getLong("timeout_ms", 5 * 60_000L)
        title = "OpenVault"
        status = label(this, "", 13f)
        list = ListView(this)
        val add = Button(this).apply { text = "Add VeraCrypt container…"; setOnClickListener { pickContainer() } }
        setContentView(LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            addView(pad(status, 12)); addView(add, LinearLayout.LayoutParams(-1, -2)); addView(list, LinearLayout.LayoutParams(-1, 0, 1f))
        })
        list.setOnItemClickListener { _, _, i, _ -> unlockDialog(recs[i]) }
        list.setOnItemLongClickListener { _, _, i, _ -> AlertDialog.Builder(this).setTitle(recs[i].name).setItems(arrayOf("Remove from list")) { _, _ -> remove(i) }.show(); true }
        Vault.lockListeners.add(refreshOnLock)
        load()
    }

    private val refreshOnLock: () -> Unit = { runOnUiThread { refresh() } }
    override fun onDestroy() { Vault.lockListeners.remove(refreshOnLock); super.onDestroy() }
    override fun onResume() { super.onResume(); refresh() }
    override fun onUserInteraction() { Vault.activity() }

    private fun refresh() {
        val s = Vault.session
        status.text = if (s != null) "Unlocked: ${s.containerName}${if (s.readOnly) " (read-only)" else ""} - tap to open, menu > Lock all" else "No vault unlocked. Container files are never copied; only their location is remembered."
        status.setOnClickListener { if (Vault.session != null) startActivity(Intent(this, BrowserActivity::class.java)) }
        list.adapter = ArrayAdapter(this, android.R.layout.simple_list_item_1, recs.map { it.name })
    }

    private fun load() {
        recs.clear()
        runCatching { JSONArray(prefs().getString("containers", "[]")).let { a -> for (i in 0 until a.length()) a.getJSONObject(i).let { recs += Rec(it.getString("uri"), it.getString("name")) } } }
        refresh()
    }

    private fun save() { prefs().edit().putString("containers", JSONArray().also { a -> recs.forEach { a.put(JSONObject().put("uri", it.uri).put("name", it.name)) } }.toString()).apply() }

    private fun remove(i: Int) {
        runCatching { contentResolver.releasePersistableUriPermission(Uri.parse(recs[i].uri), Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION) }
        recs.removeAt(i); save(); refresh()
    }

    private fun pickContainer() = startActivityForResult(Intent(Intent.ACTION_OPEN_DOCUMENT).addCategory(Intent.CATEGORY_OPENABLE).setType("*/*")
        .addFlags(Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION or Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION), 1)

    override fun onActivityResult(req: Int, res: Int, data: Intent?) {
        if (res != RESULT_OK || data?.data == null) return
        val uri = data.data!!
        when (req) {
            1 -> {
                runCatching { contentResolver.takePersistableUriPermission(uri, Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION) }
                    .recoverCatching { contentResolver.takePersistableUriPermission(uri, Intent.FLAG_GRANT_READ_URI_PERMISSION) }
                if (recs.none { it.uri == uri.toString() }) { recs += Rec(uri.toString(), uri.displayName(this)); save() }
                refresh()
            }
            2 -> { keyfiles += uri; keyfileLabel?.text = "Keyfiles: ${keyfiles.size}" }
        }
    }

    // ------------------------------------------------------------------ unlock
    private fun unlockDialog(rec: Rec) {
        keyfiles.clear()
        val pw = EditText(this).apply { hint = "Password"; inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD; imeOptions = IME_NO_PERSONALIZED_LEARNING or EditorInfo.IME_FLAG_NO_EXTRACT_UI; noAutofill() }
        val pim = EditText(this).apply { hint = "PIM (optional)"; inputType = InputType.TYPE_CLASS_NUMBER; imeOptions = IME_NO_PERSONALIZED_LEARNING; noAutofill() }
        val ro = CheckBox(this).apply { text = "Open read-only (recommended)"; isChecked = true }
        val all = CheckBox(this).apply { text = "Try all hash algorithms (slow: adds Whirlpool, Streebog)" }
        val prot = CheckBox(this).apply { text = "Protect hidden volume while writing" }
        val hpw = EditText(this).apply { hint = "Hidden volume password"; inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD; visibility(false); imeOptions = IME_NO_PERSONALIZED_LEARNING; noAutofill() }
        prot.setOnCheckedChangeListener { _, on -> hpw.visibility(on) }
        ro.setOnCheckedChangeListener { _, on -> if (on) { prot.isChecked = false }; prot.isEnabled = !on }
        prot.isEnabled = false
        val kf = label(this, "Keyfiles: 0"); keyfileLabel = kf
        val addKf = Button(this).apply { text = "Add keyfile…"; setOnClickListener { startActivityForResult(Intent(Intent.ACTION_OPEN_DOCUMENT).addCategory(Intent.CATEGORY_OPENABLE).setType("*/*"), 2) } }
        val box = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL; setPadding(dp(20), dp(8), dp(20), 0)
            listOf<View>(pw, pim, kf, addKf, ro, all, prot, hpw).forEach { addView(it, LinearLayout.LayoutParams(-1, -2)) }
        }
        AlertDialog.Builder(this).setTitle("Unlock ${rec.name}").setView(ScrollView(this).apply { addView(box) })
            .setNegativeButton("Cancel", null)
            .setPositiveButton("Unlock") { _, _ -> unlock(rec, pw, pim, ro.isChecked, all.isChecked, if (prot.isChecked) hpw else null) }.show()
    }

    private fun View.visibility(on: Boolean) { visibility = if (on) View.VISIBLE else View.GONE }

    private fun secret(e: EditText): SecretBytes {
        val n = e.text.length; val chars = CharArray(n); e.text.getChars(0, n, chars, 0)
        try { return SecretBytes.ofUtf8(chars) } finally { chars.fill('\u0000') }
    }

    private fun unlock(rec: Rec, pwField: EditText, pimField: EditText, readOnly: Boolean, all: Boolean, hiddenField: EditText?) {
        val pw = secret(pwField); val hp = hiddenField?.let { secret(it) }
        pwField.setText(""); hiddenField?.setText("")
        if (pw.size > 128 || (hp?.size ?: 0) > 128) { pw.close(); hp?.close(); toast("Passwords longer than 128 bytes are not supported"); return }
        val pimV = pimField.text.toString().toIntOrNull() ?: 0
        val kfBytes = keyfiles.map { u -> contentResolver.openInputStream(u)!!.use { it.readBytes().let { b -> if (b.size > 1048576) b.copyOf(1048576) else b } } }
        val cancelled = AtomicBoolean(false)
        val dlg = ProgressDialog(this).apply { setMessage("Deriving keys…"); setCancelable(false); setButton(ProgressDialog.BUTTON_NEGATIVE, "Cancel") { _, _ -> cancelled.set(true) }; show() }
        Thread {
            var storage: SafStorage? = null; var result: VaultResult? = null; var error: String? = null; var wroteRo = readOnly
            try {
                val uri = Uri.parse(rec.uri)
                storage = try { if (readOnly) SafStorage(contentResolver.openFileDescriptor(uri, "r")!!, false) else SafStorage(contentResolver.openFileDescriptor(uri, "rw")!!, true) }
                catch (e: SecurityException) { wroteRo = true; SafStorage(contentResolver.openFileDescriptor(uri, "r")!!, false) }
                result = VaultOpener.open(storage, pw.bytes, pimV, kfBytes.map { ByteArrayInputStream(it) }, if (all) Prf.entries else Prf.COMMON, wroteRo,
                    hp?.let { HiddenProtection(it.bytes) }, { cancelled.get() }, { d, t -> runOnUiThread { dlg.setMessage("Header attempt $d of $t…") } })
            } catch (e: Exception) { error = e.message ?: e.javaClass.simpleName }
            finally { pw.close(); hp?.close(); kfBytes.forEach { it.fill(0) } }
            runOnUiThread {
                dlg.dismiss()
                if (result !is VaultResult.Opened) storage?.close()
                when (val r = result) {
                    is VaultResult.Opened -> {
                        if (r.usedBackupHeader) toast("Primary header damaged, opened with backup header")
                        if (wroteRo && !readOnly) toast("Write access was refused by the provider: opened read-only")
                        Vault.start(rec.name, r.fileSystem, wroteRo, r.protection)
                        startActivity(Intent(this, BrowserActivity::class.java))
                    }
                    is VaultResult.Failed -> fail("Incorrect password, PIM, keyfiles or unsupported settings." + if (!all) "\n\nOnly SHA-512, SHA-256 and BLAKE2s were tried. Tick \"Try all hash algorithms\" if the container uses Whirlpool or Streebog." else "")
                    is VaultResult.HiddenProtectionFailed -> fail("The hidden volume password did not match, so protection could not be enabled.")
                    is VaultResult.UnsupportedFilesystem -> fail("Unsupported filesystem (${r.kind}). This version reads FAT12/16/32 and exFAT.")
                    is VaultResult.Cancelled -> toast("Cancelled")
                    null -> fail(error ?: "Could not open the container")
                }
            }
        }.start()
    }

    private fun fail(m: String) { AlertDialog.Builder(this).setTitle("Cannot unlock").setMessage(m).setPositiveButton("OK", null).show() }

    // ------------------------------------------------------------------ menu
    override fun onCreateOptionsMenu(m: Menu): Boolean { m.add(0, 1, 0, "Lock all"); m.add(0, 2, 1, "Auto-lock timeout"); m.add(0, 3, 2, "About"); return true }
    override fun onOptionsItemSelected(i: MenuItem): Boolean {
        when (i.itemId) {
            1 -> { Vault.lock(); refresh() }
            2 -> { val opts = longArrayOf(60_000, 5 * 60_000, 15 * 60_000, 60 * 60_000, 0); val names = arrayOf("1 minute", "5 minutes", "15 minutes", "1 hour", "Never")
                AlertDialog.Builder(this).setTitle("Lock after inactivity").setItems(names) { _, k -> Vault.policy.timeoutMs = opts[k]; prefs().edit().putLong("timeout_ms", opts[k]).apply(); Vault.activity() }.show() }
            3 -> AlertDialog.Builder(this).setTitle("OpenVault 0.1.0 (test build)").setMessage("GPL-3.0-or-later. Clean-room VeraCrypt container reader/writer.\n\nNo network permission. Vault locks on screen-off and after inactivity.\n\nThis is an early test build: keep backups of your containers and prefer read-only mode.").setPositiveButton("OK", null).show()
        }
        return true
    }
}
